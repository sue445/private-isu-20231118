module HashGroupByPrefix
  refine(Hash) do
    # Hashのkeyのprefixでグループ化したHashを返す
    #
    # @param separator [String]
    # @return [Hash<Symbol, Hash>]
    #
    # @example
    #   row = { reservation_id: 1, reservation_schedule_id: 2, reservation_user_id: 3, user_id: 4, user_nickname: "sue445" }
    #   row.group_by_prefix("_")
    #   # => { reservation: { id: 1, schedule_id: 2, reservation_user_id: 3 }, user: { id: 4, nickname: "sue445" } }
    def group_by_prefix(separator)
      each_with_object({}) do |(key, value), res|
        prefix, new_key = key.to_s.split(separator, 2)
        prefix = prefix.to_sym
        new_key = new_key.to_sym
        res[prefix] ||= {}
        res[prefix][new_key] = value
      end
    end
  end
end
