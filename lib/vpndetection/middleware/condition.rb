# frozen_string_literal: true

module VPNDetection
  module Middleware
    # Deciding whether an answer is worth blocking.
    #
    # A condition is written in the shape of a served answer and keyed by the
    # same names the API uses, so what you write here reads like what you get
    # back. Symbol and string keys both work.
    #
    #   { is_vpn: true }
    #   { is_vpn: true, vpn: { provider: 'nordvpn' } }
    #   { is_resproxy: true, resproxy: { hits: { gte: 5 } } }
    #   { vpn: { confidence: %w[high medium] } }
    #   [{ is_tor: true }, { is_resproxy: true }]   # a list is OR
    #
    # A value may be a scalar (equality, strings without regard to case), an
    # Array meaning any-of, a Hash of `gte`/`gt`/`lte`/`lt` bounding a number,
    # or a nested condition. A member set to `false` or `nil` is ignored
    # entirely - a condition states the positive signals you act on, so there is
    # no way to write "block when this is false", which would otherwise read as
    # blocking everybody.
    module Condition
      BOUND_KEYS = %w[gte gt lte lt].freeze

      module_function

      # Whether an answer satisfies the condition, and should therefore be
      # blocked.
      def matches?(condition, result)
        Array(wrap(condition)).any? { |one| matches_object?(one, result.raw) }
      end

      # The top-level members a condition names that this answer did not carry.
      #
      # A field your plan does not include is absent rather than false, so a
      # condition naming one can never match and the block would silently never
      # fire. Gating is per top-level member, which is why only the first path
      # segment is checked: a detail object present but empty is a real answer
      # meaning the flag is false, not a plan gap.
      #
      # A locally answered bogon needs no special case: it is synthesized in the
      # widest shape, so every member is present and nothing reads as missing.
      def missing_members(condition, result)
        missing = []
        wrap(condition).each do |one|
          one.each do |member, want|
            name = member.to_s
            next if constraint_count(want).zero? || missing.include?(name)

            missing << name unless result.raw.key?(name)
          end
        end
        missing
      end

      # Refuse a condition that constrains nothing.
      #
      # Ignoring `false` means `{ is_vpn: false }` and `{}` have no terms left
      # to satisfy, so they would match every answer and block all traffic.
      # Nobody writes that on purpose, and failing when the middleware is built
      # beats discovering it in production.
      def validate!(condition)
        return if condition.nil?

        wrap(condition).each do |one|
          next unless constraint_count(one).zero?

          raise ArgumentError,
                "vpndetection: block condition #{one.inspect} constrains nothing, which " \
                'would block every request; a member set to false or nil is ignored, so ' \
                'state the positive signals you act on'
        end
      end

      # How many leaf constraints a condition actually carries.
      def constraint_count(condition)
        case condition
        when nil, false then 0
        when Hash
          bound?(condition) ? 1 : condition.values.sum { |v| constraint_count(v) }
        when Array then condition.sum { |v| constraint_count(v) }
        else 1
        end
      end

      def wrap(condition)
        condition.is_a?(Array) ? condition : [condition]
      end

      def matches_object?(condition, value)
        condition.all? do |member, want|
          next true if constraint_count(want).zero?

          matches_value?(want, value.is_a?(Hash) ? value[member.to_s] : nil)
        end
      end

      # An ABSENT member arrives here as nil, which is exactly what "not in your
      # plan" looks like. Every branch below must therefore reject it, which is
      # what makes an unserved member fail a match rather than pass it.
      def matches_value?(want, got)
        case want
        when Array then want.any? { |entry| matches_value?(entry, got) }
        when Hash
          bound?(want) ? matches_bound?(want, got) : matches_object?(want, got)
        when String
          # Providers are lowercase slugs on the wire and a caller should not
          # have to know that, so a string compares without case.
          got.is_a?(String) && want.casecmp?(got)
        when true, false then want == got
        when Numeric then got.is_a?(Numeric) && !got.is_a?(TrueClass) && want == got
        else want == got
        end
      end

      def matches_bound?(bound, got)
        return false unless got.is_a?(Numeric)

        normalized = bound.transform_keys(&:to_s)
        return false if normalized['gte'] && got < normalized['gte']
        return false if normalized['gt'] && got <= normalized['gt']
        return false if normalized['lte'] && got > normalized['lte']

        !(normalized['lt'] && got >= normalized['lt'])
      end

      def bound?(value)
        return false unless value.is_a?(Hash)

        !value.empty? && value.keys.all? { |k| BOUND_KEYS.include?(k.to_s) }
      end
    end
  end
end
