module NewRelicSqlite3TracePatch
  include NewRelicDatabaseTracePatch

  def execute(sql, bind_vars = [], *args, &block)
    with_newrelic("SQLite", sql) do
      super
    end
  end
end

SQLite3::Database.prepend(NewRelicSqlite3TracePatch)
