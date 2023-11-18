require "ddtrace"
require "datadog_thread_tracer"
require "sinatra"
require "mysql2"

# FIXME: ruby 3.2.0-devでインストールできないのでコメントアウト
# require "datadog/statsd"

if defined?(::SQLite3)
  require_relative "./ddtrace_sqlite3"
end

ENV["DD_TRACE_SAMPLE_RATE"] = "1.0"

Datadog.configure do |c|
  app_name = "isucon"

  # Global settings
  c.version = current_revision
  c.runtime_metrics.enabled = true
  c.service = app_name
  c.env = ENV["RACK_ENV"]
  c.tags = { app: app_name }
  c.profiling.enabled = true

  # Tracing settings
  c.tracing.analytics.enabled = true
  c.tracing.partial_flush.enabled = true

  # FIXME: samplerがnilなのでDD_TRACE_SAMPLE_RATEで渡す
  # c.tracing.sampler.default_rate = 1.0

  # Instrumentation
  c.tracing.instrument :sinatra, service_name: app_name + "-sinatra", analytics_enabled: true
  c.tracing.instrument :mysql2,  service_name: app_name + "-mysql2",  analytics_enabled: true
  c.tracing.instrument :http,    service_name: app_name + "-http",    analytics_enabled: true, split_by_domain: true

  if defined?(::Redis)
    c.tracing.instrument :redis, service_name: app_name + "-redis", analytics_enabled: true
  end

  if defined?(::Sidekiq)
    c.tracing.instrument :sidekiq, service_name: app_name + '-sidekiq', analytics_enabled: true, client_service_name: app_name + '-sidekiq-client'
  end
end

# NOTE: 設定有効後じゃないとpreloadが効かない
require "datadog/profiling/preload"

# NOTE: 書くのをよく忘れるのでファイルをrequireした時点で自動で適用されるようにする
class Sinatra::Base
  register Datadog::Tracing::Contrib::Sinatra::Tracer
end

# Datadog上だと生クエリが見れないため別tagとして送信するためのパッチ
module DatadogMysql2RawQuerySenderPatch
  def _query(sql, options = {})
    span = ::Datadog::Tracing.active_span
    span.set_tag("sql.raw_query", sql) if span

    super(sql, options)
  end
end

::Mysql2::Client.prepend(DatadogMysql2RawQuerySenderPatch)

# Datadogに `POST /api/condition/:jia_isu_uuid` のようなsinatraで定義してるrouting名で送信するためのパッチ
module DatadogSinatraRouteingPathNamePatch
  def route_eval
    # NOTE: sinatraのrouting内で @datadog_route を設定することでDatadog上で表示する時のresource名を上書きすることができる
    # c.f. https://github.com/DataDog/dd-trace-rb/blob/v0.54.2/lib/ddtrace/contrib/sinatra/tracer.rb#L112
    @datadog_route = request.env["sinatra.route"].split(" ").last

    super
  end
end

::Sinatra::Base.prepend(DatadogSinatraRouteingPathNamePatch)

# DatadogにWorkerのクラス名を送信するためのモンキーパッチをSidekiq::Worker#performに仕込む
module DatadogSidekiqWorkerPatch
  def perform(*)
    trace = ::Datadog::Tracing.active_trace
    trace.resource = self.class.to_s if trace

    super
  end
end

# Sidekiq::Workerをincludeした全workerクラスにモンキーパッチをあてる
# NOTE: Sidekiq::Workerがincludeされているかどうかを厳密に調べようとするとインスタンスを生成する必要があって遅くなるため、
#       Sidekiq::Workerをincludeした時に生成されるクラスメソッド(sidekiq_options)の存在をチェックしている
sidekiq_worker_classes = ObjectSpace.each_object(Class).select do |klass|
  klass.name&.end_with?("Worker") && klass.respond_to?(:sidekiq_options)
end

sidekiq_worker_classes.each do |worker_class|
  worker_class.prepend(DatadogSidekiqWorkerPatch)
end
