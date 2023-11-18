require "sidekiq"

require_relative "../config/sentry_methods"

class SidekiqStatsWorker
  include Sidekiq::Worker
  include SentryMethods

  sidekiq_options queue: "default", retry: false

  def perform(*args)
    with_sentry do
      # ref. https://github.com/feedforce/datadog-sidekiq
      command = "datadog-sidekiq -redis-host #{ENV.fetch("REDIS_HOST")}:#{ENV.fetch("REDIS_PORT", "6379")} -tags service:isucon"

      system_with_sentry(command)
    end
  end
end
