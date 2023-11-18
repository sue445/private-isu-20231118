# ddtrace, Sentryの一括有効＆一括無効を1ファイルのみで行うためのファイル
require "sentry-ruby"
require "sinatra"
require "mysql2"

def current_revision
  @current_revision ||= `git rev-parse --short HEAD`.strip # rubocop:disable Isucon/Shell/Backtick 最終的にはファイル自体requireしないので無視する
end

# for Datadog
# require_relative "./ddtrace_init"

# for NewRelic
require_relative "./newrelic_init"

Sentry.init do |config|
  config.enabled_environments = %w[production development]
  config.release = current_revision
end

# NOTE: 書くのをよく忘れるのでファイルをrequireした時点で自動でSentry::Rack::CaptureExceptionsが適用されるようにする
class Sinatra::Base
  use Sentry::Rack::CaptureExceptions
end


# {Mysql2::Client#query} や {Mysql2::Client#xquery} のエラー時にSentryにSQLを送信するためのパッチ
module SentryMysql2Patch
  def _query(sql, options = {})
    super(sql, options)

  rescue Mysql2::Error => error
    Sentry.configure_scope do |scope|
      scope.set_context(
        "mysql2",
        {
          sql: sql,
        }
      )
      raise error
    end
  end
end

::Mysql2::Client.prepend(SentryMysql2Patch)
