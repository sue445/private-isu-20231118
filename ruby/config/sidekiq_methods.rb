# sidekiqの便利メソッド
require "sidekiq/api"

module SidekiqMethods
  # c.f.
  # * https://gist.github.com/wbotelhos/fb865fba2b4f3518c8e533c7487d5354
  # * https://qiita.com/ts-3156/items/ec4608c7c9cf1494bcc1
  def clear_sidekiq_all_queue
    Sidekiq::Queue.all.each do |queue|
      queue.clear
    end
  end
end
