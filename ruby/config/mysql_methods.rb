# Rubyからmysqlコマンドをたたくためのメソッド
require 'securerandom'
require_relative "./sentry_methods"

module MysqlMethods
  include SentryMethods

  # mysqlコマンドを実行して結果を一時ファイルに出力する。ブロック内から抜けると一時ファイルは削除される
  # @param sql [String]
  # @param quote [Boolean] csvのセルをダブルクオーテーションで囲むかどうか
  # @param suffix_sql [String] クエリの末尾につける文字列
  # @yieldparam 一時ファイルのパス
  def with_create_csv_file_from_mysql(sql, quote: true, suffix_sql: nil)
    # TODO: mysqlやmariadbのserviceファイルでPrivateTmpを無効化しないと/tmpにファイルが出力できない
    dist_file = File.join("/tmp", "#{SecureRandom.uuid}.csv")

    create_csv_file_from_mysql(sql, dist_file: dist_file, quote: quote, suffix_sql: suffix_sql)

    # DBサーバに出力されているのでscpでローカルに転送する
    # TODO: scpするにはdbサーバのauthorized_keysにAPの公開鍵が登録されている必要がある
    unless ENV["DB_HOST"] == "127.0.0.1"
      system_with_sentry("scp -i /home/isucon/.ssh/id_ed25519 isucon@#{ENV["DB_HOST"]}:#{dist_file} #{dist_file}")
    end

    yield dist_file
  ensure
    FileUtils.rm_f(dist_file)
  end

  # mysqlコマンドを実行して結果をCSVファイルに出力する
  # @param sql [String]
  # @param dist_file [String] DBサーバの出力先のパス
  # @param quote [Boolean] csvのセルをダブルクオーテーションで囲むかどうか
  # @param suffix_sql [String] クエリの末尾につける文字列
  def create_csv_file_from_mysql(sql, dist_file:, quote: true, suffix_sql: nil)
    into_outfile_sql = %Q("#{sql} INTO OUTFILE '#{dist_file}' FIELDS TERMINATED BY ',')
    into_outfile_sql << %Q( OPTIONALLY ENCLOSED BY '\\"') if quote
    into_outfile_sql << " " + suffix_sql if suffix_sql
    into_outfile_sql << '"'

    command = [
      "mysql",
      "-u", ENV["DB_USER"],
      "-p#{ENV["DB_PASS"]}",
      "-h", ENV["DB_HOST"],
      ENV["DB_DATABASE"],
      "-e",
      into_outfile_sql,
    ].join(" ")

    system_with_sentry(command)
  end
end
