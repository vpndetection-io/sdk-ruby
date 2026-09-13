# frozen_string_literal: true

require_relative 'condition'

module VPNDetection
  # The framework-agnostic half of a web middleware: resolve a client address,
  # classify it, and decide whether the condition matched.
  #
  # An adapter - the vpndetection-rails gem - keeps only the parts that are
  # genuinely framework-shaped and shares everything here, so the shared
  # conformance corpus is asserted once for Ruby rather than once per framework.
  module Middleware
    # What a middleware attached to the request, whether or not it succeeded.
    Lookup = Struct.new(:blocked, :ip, :result, :error, keyword_init: true) do
      # Whether the condition matched. Always false when none was configured.
      def blocked?
        blocked == true
      end
    end

    # Enough of an incoming request for a selector to work with, whatever
    # framework it came from. An adapter supplies one of these per request.
    RequestView = Struct.new(:header, :framework_ip, keyword_init: true)

    # Defaults set for a request path rather than for a script: failing open
    # quickly beats holding a visitor while we try again.
    DEFAULT_TIMEOUT = 2.5
    DEFAULT_RETRIES = 0

    # Resolve, classify, decide.
    class Core
      # @param default_ip_selector [#call] the framework's own accessor, used
      #   when the caller named none.
      def initialize(default_ip_selector, **options)
        Condition.validate!(options[:block_condition])
        @condition = options[:block_condition]
        @selector = options[:ip_selector] || default_ip_selector
        @fail_closed = options.fetch(:fail_closed, false)
        @on_missing_field = options.fetch(:on_missing_field, :warn)
        @skip = options[:skip]
        @on_warn = options[:on_warn]
        @retries = options.fetch(:retries, DEFAULT_RETRIES)
        @warned = {}
        @client = options[:client] || Client.new(
          api_key: options[:api_key],
          **{ base_url: options[:base_url] }.compact,
          timeout: options.fetch(:timeout, DEFAULT_TIMEOUT)
        )
      end

      # Whether a condition was configured at all.
      def blocking?
        !@condition.nil?
      end

      # Classify one request. Answers nil when `skip` claimed it.
      #
      # A failed LOOKUP is not raised: it lands on `Lookup#error` and the
      # request is let through. What CAN raise is a misconfiguration - a
      # condition naming a member the plan does not serve, with
      # `on_missing_field: :raise`.
      def evaluate(request)
        return nil if @skip&.call(request)

        ip = @selector.call(request).to_s.strip
        return unresolved if ip.empty?

        if Bogon.bogon?(ip)
          # Expected in local development. Anywhere else it means a proxy sits
          # in front and its own address is what reached us.
          warn_once(
            "resolved the client address as #{ip}, which is not a public address. If this " \
            'application runs behind a proxy or load balancer, configure its trusted-proxy ' \
            "setting or pass an ip_selector that reads your edge's header."
          )
        end

        begin
          result = @client.lookup(ip, retries: @retries)
        rescue VPNDetection::Error => e
          return Lookup.new(blocked: @fail_closed, ip: ip, error: e)
        end
        decide(ip, result)
      end

      private

      def unresolved
        warn_once(
          'could not resolve a client address from this request; pass an ip_selector that ' \
          'knows where yours comes from'
        )
        Lookup.new(
          blocked: @fail_closed,
          error: VPNDetection::Error.new(:bad_request, 'no client address on the request')
        )
      end

      def decide(ip, result)
        return Lookup.new(blocked: false, ip: ip, result: result) if @condition.nil?

        report_missing(result)
        Lookup.new(
          blocked: Condition.matches?(@condition, result),
          ip: ip,
          result: result
        )
      end

      def report_missing(result)
        return if @on_missing_field == :ignore

        missing = Condition.missing_members(@condition, result)
        return if missing.empty?

        message = "block_condition names #{missing.join(', ')}, which your plan does not " \
                  'include, so those terms can never match. An absent member means "not in ' \
                  'your plan", not "checked, and no".'
        raise ArgumentError, "vpndetection: #{message}" if @on_missing_field == :raise

        warn_once(message)
      end

      # A misconfiguration is the same on every request, so saying so once is a
      # warning and saying so a million times is an outage of its own.
      def warn_once(message)
        return if @warned[message]

        @warned[message] = true
        @on_warn ? @on_warn.call(message) : Kernel.warn("[vpndetection] #{message}")
      end
    end

    # The shared client-address selectors, bound to one framework's request type.
    #
    # There is no portable default: a framework's own accessor may return the
    # socket peer, or may already have walked a proxy chain, depending on the
    # framework and on how the application configured it.
    class Selectors
      def initialize(&view)
        @view = view
      end

      # The framework's own client-address accessor.
      def default
        ->(request) { @view.call(request).framework_ip.call }
      end

      # An address from `X-Forwarded-For`.
      #
      # The LEFT-MOST entry (depth 0) is whatever the caller sent, because
      # proxies append to this header, so a visitor who sets it themselves
      # appears first and this returns their forgery. It is only trustworthy
      # when an edge you control overwrites the header. When you know how many
      # proxies sit in front, count from the right: depth 1 is the address your
      # nearest proxy saw.
      def xff(depth = 0)
        lambda do |request|
          seen = @view.call(request)
          chain = (seen.header.call('X-Forwarded-For') || '').split(',').map(&:strip).reject(&:empty?)
          next seen.framework_ip.call if chain.empty?
          next chain.first if depth <= 0 || depth > chain.length

          chain[-depth]
        end
      end

      # An address from a single-value header your edge writes -
      # `header('CF-Connecting-IP')` behind Cloudflare. Falls back to the
      # framework's accessor when the header is absent.
      def header(name)
        lambda do |request|
          seen = @view.call(request)
          value = (seen.header.call(name) || '').strip
          value.empty? ? seen.framework_ip.call : value
        end
      end
    end
  end
end
