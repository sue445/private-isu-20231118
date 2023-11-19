module DbHelper
  def config
    @config ||= {
      db: {
        host: ENV['ISUCONP_DB_HOST'] || 'localhost',
        port: ENV['ISUCONP_DB_PORT'] && ENV['ISUCONP_DB_PORT'].to_i,
        username: ENV['ISUCONP_DB_USER'] || 'root',
        password: ENV['ISUCONP_DB_PASSWORD'],
        database: ENV['ISUCONP_DB_NAME'] || 'isuconp',
      },
    }
  end

  def db
    return Thread.current[:isuconp_db] if Thread.current[:isuconp_db]

    client = Mysql2::Client.new(
      host: config[:db][:host],
      port: config[:db][:port],
      username: config[:db][:username],
      password: config[:db][:password],
      database: config[:db][:database],
      encoding: 'utf8mb4',
      reconnect: true,
    )
    client.query_options.merge!(symbolize_keys: true, database_timezone: :local, application_timezone: :local)
    Thread.current[:isuconp_db] = client

    client
  end
end
