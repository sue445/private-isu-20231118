# ddtraceをrequireしてない場合にもDatadogThreadHelper.traceと同じインターフェースを提供するためのヘルパー

if defined?(Datadog) && defined?(DatadogThreadTracer)
  # ddtraceをrequireしてる場合にはdatadog_thread_tracerをそのまま使う
  ThreadHelper = DatadogThreadTracer
  return
end

# ddtraceをrequireしていない場合にはdatadog_thread_tracerと同じインターフェースを提供したヘルパーを定義する
class ThreadHelper
  def initialize
    @threads = []
  end

  def trace(trace_name: nil, thread_args: [])
    thread_args = Array(thread_args)
    @threads << Thread.new(thread_args) do |args|
      yield(*args)
    end
  end

  def join_threads
    @threads.each(&:join)
  end

  def self.trace
    helper = ThreadHelper.new

    yield helper

    helper.join_threads
  end
end
