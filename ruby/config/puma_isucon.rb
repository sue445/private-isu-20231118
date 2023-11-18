# pumaのいい感じの初期設定
#
# ref. https://github.com/puma/puma/blob/master/lib/puma/dsl.rb

# environments
# * RACK_ENV
# * PUMA_PORT
# * PUMA_WORKERS
# * PUMA_THREADS_MIN
# * PUMA_THREADS_MAX
# * PUMA_LOGGING
# * PUMA_WORKER_KILLER

require "etc"

environment(ENV.fetch("RACK_ENV", "production"))

port(ENV.fetch("PUMA_PORT", 8000).to_i, "0.0.0.0")

# c.f.https://zenn.dev/rosylilly/articles/202201-config-turn
puma_workers = ENV.fetch("PUMA_WORKERS", (Etc.nprocessors * 1.5).floor)
workers(puma_workers)

threads_min = ENV.fetch("PUMA_THREADS_MIN", 1).to_i
threads_max = ENV.fetch("PUMA_THREADS_MAX", threads_min).to_i
threads(threads_min, threads_max)

preload_app!

puma_logging = ENV.fetch("PUMA_LOGGING", "true") == "true"
log_requests(puma_logging)

# for puma 5+
# Recommended 0.001~0.010(default 0.005)
wait_for_less_busy_worker 0.005

if ENV.fetch("PUMA_WORKER_KILLER", "false") == "true"
  before_fork do
    require "puma_worker_killer"

    PumaWorkerKiller.config do |config|
      config.ram           = 2048 # mb
      config.frequency     = 5    # seconds
      config.percent_usage = 0.80
      config.rolling_restart_frequency = 12 * 3600 # 12 hours in seconds, or 12.hours if using Rails
      config.reaper_status_logs = false # setting this to false will not log lines like:
      # PumaWorkerKiller: Consuming 54.34765625 mb with master and 2 workers.

      # config.pre_term = -> (worker) { puts "Worker #{worker.inspect} being killed" }
      # config.rolling_pre_term = -> (worker) { puts "Worker #{worker.inspect} being killed by rolling restart" }
    end
    PumaWorkerKiller.start
  end
end

activate_control_app "tcp://127.0.0.1:9293", { auth_token: "datadog" }
