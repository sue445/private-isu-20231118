require "newrelic_rpm"
require "mysql2"

module NewRelicDatabaseTracePatch
  def with_newrelic(product, sql)
    callback = -> (result, metrics, elapsed) do
      NewRelic::Agent::Datastores.notice_sql(sql, metrics, elapsed)
    end
    op = sql[/^(select|insert|update|delete|begin|commit|rollback)/i] || 'other'

    table = parse_table(sql)

    NewRelic::Agent::Datastores.wrap(product, op, table, callback) do
      yield
    end
  end

  # SQL文からテーブル名のみを抽出する。サブクエリやJOINなどで複数のテーブルが含まれる場合はカンマ区切りで連結して返す
  # @param sql [String]
  # @return [String]
  def parse_table(sql)
    # Remove `FOR UPDATE` in `SELECT`
    sql = sql.gsub(/FOR\s+UPDATE/i, "")

    # Remove `ON DUPLICATE KEY UPDATE` in `INSERT`
    sql = sql.gsub(/ON\s+DUPLICATE\s+KEY\s+UPDATE/i, "")

    tables = sql.scan(/(?:FROM|INTO|UPDATE|JOIN)\s+([^(]+?)[\s(]/i).
      map { |matched| matched[0].strip.delete("`") }.reject(&:empty?).uniq

    return "other" if tables.empty?

    tables.sort_by(&:to_s).join(",")
  end
end

module NewRelicMysql2TracePatch
  include NewRelicDatabaseTracePatch

  def query(sql, *args)
    with_newrelic("MySQL", sql) do
      super
    end
  end

  private
end

# アプリケーションコードを書き換えるのが面倒なのでファイルがrequireされた時点でMysql2::ClientでNewRelicが使われるようにする
Mysql2::Client.prepend(NewRelicMysql2TracePatch)

if defined?(SQLite3)
  require_relative "./newrelic_sqlite3"
end
