module DatadogSqlite3TracePatch
  def execute(sql, bind_vars = [], *args, &block)
    Datadog::Tracing.trace("sqlite3.execute", service: "isucon-sqlite3", resource: sql) do
      span = ::Datadog::Tracing.active_span
      if span
        vars =
          if args.empty?
            bind_vars
          else
            Array(bind_vars) + args
          end
        span.set_tag("sqlite3.bind_vars", vars)
      end

      super(sql, bind_vars, *args, &block)
    end
  end
end

SQLite3::Database.prepend(DatadogSqlite3TracePatch)
