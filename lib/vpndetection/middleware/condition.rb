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
    # or a nested condition. A term on a member the answer holds as a list
    # matches when any element matches it. A member set to `false` or `nil` is
    # ignored entirely - a condition states the positive signals you act on, so
    # there is no way to write "block when this is false", which would otherwise
    # read as blocking everybody.
    module Condition
      BOUND_KEYS = %w[gte gt lte lt].freeze

      # The objects every plan answers whose members a plan can still leave out.
      PARTLY_PAID = %w[asn].freeze

      module_function

      # Whether an answer satisfies the condition, and should therefore be
      # blocked.
      def matches?(condition, result)
        Array(wrap(condition)).any? { |one| matches_object?(one, result.raw) }
      end

      # The members a condition names that this answer did not carry: a top-level
      # member, or the AS's paid one, `asn.type`, by its path.
      #
      # A field your plan does not include is absent rather than false, so a
      # condition naming one can never match and the block would silently never
      # fire. Gating is per top-level member, which is why only the first path
      # segment is checked: a detail object present but empty is a real answer
      # meaning the flag is false, not a plan gap. `asn` is the one object every
      # plan gets that also holds a paid member (`type`), so it is read member by
      # member, and a populated one carries every other.
      #
      # A locally answered bogon is synthesized in the widest shape, but it
      # carries no user agent verdict, which only a sent agent earns: the core
      # never asks this of a bogon's answer (report_missing returns first).
      def missing_members(condition, result)
        missing = []
        wrap(condition).each { |one| collect_missing(one, result.raw, '', missing) }
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

      def collect_missing(condition, value, prefix, missing)
        condition.each do |member, want|
          next if constraint_count(want).zero?

          name = member.to_s
          path = "#{prefix}#{name}"
          unless value.key?(name)
            missing << path unless missing.include?(path)
            next
          end
          got = value[name]
          next unless prefix.empty? && PARTLY_PAID.include?(name) && want.is_a?(Hash) && !bound?(want)

          collect_missing(want, got, "#{path}.", missing) if got.is_a?(Hash) && !got.empty?
        end
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
      #
      # A member the answer holds as a list (`pubproxy.protocols`, a `web` row)
      # matches when any element matches the term, so an object term must match
      # one element whole.
      def matches_value?(want, got)
        return got.any? { |element| matches_value?(want, element) } if got.is_a?(Array)

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
