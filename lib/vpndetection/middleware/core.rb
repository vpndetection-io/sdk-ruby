# frozen_string_literal: true

require 'digest'
require 'lru_redux'

require_relative 'condition'
require_relative 'crawlers'

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

    # The most crawler agents one address is looked up with while it is remembered.
    MAX_AGENTS_PER_ADDRESS = 4

    # How long an address's crawler agents are remembered, from its first one: the
    # client's default cache TTL.
    AGENTS_TTL = 60 * 60

    # How many addresses' agents are remembered at once.
    AGENTS_MAX_ADDRESSES = 10_000
    private_constant :AGENTS_TTL, :AGENTS_MAX_ADDRESSES

    # Whether a `User-Agent` names a crawler, the only kind of agent whose verdict
    # can be `verified` or `spoofed`. It errs toward a match, which costs a lookup.
    # Case is folded for A to Z alone, as the corpus's terms are written.
    def self.names_crawler?(agent)
      lower = agent.b.downcase(:ascii)
      Crawlers::TERMS.any? { |term| lower.include?(term) }
    end

    # Reads a request's `User-Agent` where the adapter names no reader: Rack's
    # request has `user_agent`, and so do Sinatra's and Hanami's.
    DEFAULT_USER_AGENT = ->(request) { request.user_agent if request.respond_to?(:user_agent) }

    # Resolve, classify, decide.
    class Core
      # @param default_ip_selector [#call] the framework's own accessor, used
      #   when the caller named none.
      # @param user_agent_of [#call] reads the request's own `User-Agent`, which
      #   `allow_bots: true` sends with the lookup.
      # @option options [Boolean] :allow_bots (false) send the request's own
      #   `User-Agent` with its lookup when it names a crawler, and never refuse
      #   a request whose answer says `user_agent.verdict` is `verified`,
      #   whatever the condition matches; the answer is still attached. Any other
      #   agent, an absent or an empty header sends none, since the verdict could
      #   only be `not_bot`. One address is looked up with at most
      #   {MAX_AGENTS_PER_ADDRESS} crawler agents an hour: past those, the lookup
      #   sends none, and the request passes as a crawler only where the answer's
      #   `bot.verified` is true. A keyless client, or a free key past its trial,
      #   never gets a verdict, so nothing is let through there, and that is
      #   warned of once under `on_missing_field`.
      def initialize(default_ip_selector, user_agent_of = DEFAULT_USER_AGENT, **options)
        Condition.validate!(options[:block_condition])
        @condition = options[:block_condition]
        @selector = options[:ip_selector] || default_ip_selector
        @allow_bots = options.fetch(:allow_bots, false) == true
        @user_agent_of = user_agent_of
        @agents = @allow_bots ? CrawlerAgents.new : nil
        @fail_closed = options.fetch(:fail_closed, false)
        @on_missing_field = options.fetch(:on_missing_field, :warn)
        @skip = options[:skip]
        @on_warn = options[:on_warn]
        @retries = options.fetch(:retries, DEFAULT_RETRIES)
        Retries.checked_count(@retries) unless @retries.nil?
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

        # A bogon is answered locally, so nothing is sent for it.
        claim = @allow_bots && !Bogon.bogon?(ip) ? claim_agent(ip, request) : nil
        agent = claim&.agent
        begin
          result = @client.lookup(ip, retries: @retries, **(agent ? { user_agent: agent } : {}))
        rescue VPNDetection::Error => e
          return Lookup.new(blocked: @fail_closed, ip: ip, error: e)
        end
        decide(ip, result, claim)
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

      # What this request's agent comes to: nil when it names no crawler (or sent
      # none), else a claim whose agent is the one to send, or nil past the
      # address's bound.
      def claim_agent(ip, request)
        agent = @user_agent_of.call(request)
        return nil unless agent.is_a?(String) && !agent.empty? && Middleware.names_crawler?(agent)

        Claim.new(@agents.admit(ip, agent))
      end

      def decide(ip, result, claim)
        report_unanswered_agent(result) unless claim&.agent.nil?
        return Lookup.new(blocked: false, ip: ip, result: result) if @condition.nil?

        report_missing(result, sent: !claim&.agent.nil?)
        Lookup.new(
          blocked: Condition.matches?(@condition, result) && !verified?(result, claim),
          ip: ip,
          result: result
        )
      end

      # Whether `allow_bots` lets this answer through: its agent's operator
      # vouches for the address, or, past the bound, the answer says a crawler's
      # operator does.
      def verified?(result, claim)
        return false if claim.nil?
        return result.bot.is_a?(Hash) && result.bot['verified'] == true if claim.agent.nil?

        result.user_agent.is_a?(Hash) && result.user_agent['verdict'] == 'verified'
      end

      def report_missing(result, sent:)
        return if @on_missing_field == :ignore
        # A bogon is answered locally in the widest shape, which carries every
        # member but `user_agent`, and no agent is sent for it.
        return if result.bogon?

        missing = Condition.missing_members(@condition, result)
        # A request that sent no agent has no verdict to lack, whatever the plan serves.
        missing -= ['user_agent'] if @allow_bots && !sent
        return if missing.empty?

        message = "block_condition names #{missing.join(', ')}, which your plan does not " \
                  'include, so those terms can never match. An absent member means "not in ' \
                  'your plan", not "checked, and no".'
        if missing.include?('user_agent') && !@allow_bots
          message += ' user_agent is answered only to a lookup that sends one, which allow_bots does.'
        end
        report(message)
      end

      # An agent went with the lookup and the served answer carries no verdict:
      # a keyless client, or a free key past its trial, is never answered one,
      # so allow_bots lets no crawler through.
      def report_unanswered_agent(result)
        return if @on_missing_field == :ignore || result.included?(:user_agent)

        report('allow_bots sends the request\'s User-Agent, but the answer carries no user_agent ' \
               'verdict, which your plan does not include, so no crawler is let through. A key on ' \
               'a paid plan, or on its trial, is answered one.')
      end

      def report(message)
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

    # A crawler's agent as one request makes it: `agent` is what the lookup sends,
    # nil once the address is past its bound.
    Claim = Struct.new(:agent)
    private_constant :Claim

    # The crawler agents each address was looked up with. An address claiming more
    # than MAX_AGENTS_PER_ADDRESS of them in an hour sends none past those, so a
    # visitor inventing an agent per request spends at most that many lookups.
    #
    # An agent is kept as its digest, so what an address costs in memory is
    # bounded whatever length of header it sends. Adding one changes the stored
    # list in place, which leaves the address's hour running from its first.
    class CrawlerAgents
      def initialize
        @seen = LruRedux::TTL::Cache.new(AGENTS_MAX_ADDRESSES, AGENTS_TTL)
        @lock = Mutex.new
      end

      # The agent to send for `ip`, or nil once the address has its bound.
      def admit(ip, agent)
        digest = Digest::SHA256.digest(agent)
        @lock.synchronize do
          known = @seen[ip]
          if known.nil?
            @seen[ip] = [digest]
          elsif !known.include?(digest)
            return nil if known.length >= MAX_AGENTS_PER_ADDRESS

            known << digest
          end
          agent
        end
      end
    end
    private_constant :CrawlerAgents

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

      # The request's own `User-Agent` header, which `allow_bots` sends.
      def user_agent
        ->(request) { @view.call(request).header.call('User-Agent') }
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
