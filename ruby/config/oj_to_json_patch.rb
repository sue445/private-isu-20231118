# to_jsonをojに置き換えるモンキーパッチ
require "oj"

::Oj.default_options = { mode: :compat }

class Hash
  def to_json(*)
    ::Oj.dump(self)
  end
end

class Array
  def to_json(*)
    ::Oj.dump(self)
  end
end
