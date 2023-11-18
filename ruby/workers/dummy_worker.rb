require "sidekiq"
require "mysql2-cs-bind"

require_relative "../config/sentry_methods"
# require_relative "../isucon_helper"

class DummyWorker
  include Sidekiq::Worker
  include SentryMethods
  # include IsuconHelper

  sidekiq_options queue: "default"

  def perform(*args)
    with_sentry do
      # do something
    end
  end
end
