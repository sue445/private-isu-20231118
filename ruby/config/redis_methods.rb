# redisの便利メソッド
require "redis"
require "connection_pool"
require "oj"

$redis = ConnectionPool::Wrapper.new(size: 32, timeout: 3) { Redis.new(host: ENV["REDIS_HOST"]) }

::Oj.default_options = { mode: :compat }

module RedisMethods
  # redisにあればredisから取得し、キャッシュになければブロック内の処理で取得しredisに保存するメソッド（Rails.cache.fetchと同様のメソッド）
  #
  # @param cache_key [String]
  # @param enabled [Boolean] キャッシュを有効にするかどうか
  # @param is_object [Boolean] String以外を保存するかどうか
  #
  # @yield キャッシュがなかった場合に実データを取得しにいくための処理
  # @yieldreturn [Object] redisに保存されるデータ
  #
  # @return [Object] redisに保存されるデータ
  def with_redis(cache_key, enabled: true, is_object: false)
    unless enabled
      return yield
    end

    cached_response = $redis.get(cache_key)
    if cached_response
      if is_object
        # return Marshal.load(cached_response)
        return Oj.load(cached_response)
      else
        return cached_response
      end
    end

    actual = yield

    if actual
      if is_object
        # data = Marshal.dump(actual)
        data = Oj.dump(actual)

        $redis.set(cache_key, data)
      else
        $redis.set(cache_key, actual)
      end
    end

    actual
  end

  def initialize_redis
    $redis.flushall
  end
end
