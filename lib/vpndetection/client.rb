# frozen_string_literal: true

require 'typhoeus'

module VPNDetection
  DEFAULT_BASE_URL = 'https://api.vpndetection.io'
  DEFAULT_CACHE_MAX_SIZE = 10_000
  DEFAULT_CACHE_TTL = 3600
  DEFAULT_CONCURRENCY = 8
  DEFAULT_RETRIES = 2
  DEFAULT_TIMEOUT = 10

  # A client for the VPNDetection API.
  #
  # The cache is per instance, so an answer is never shared between two clients
  # holding different API keys and therefore entitled to different fields.
  class Client
    # The licensed dataset downloads, for keys that carry the `db.download` scope.
    attr_reader :database

    # @param api_key [String, nil] omit it entirely to use the free tier, which
    #   answers `ip` and `is_vpn` and allows 1000 requests per day per source
    #   address.
    # @param cache [Boolean] pass false to disable caching.
    # @param cache_ttl [Numeric] how long an answer stays fresh, in seconds.
    # @param concurrency [Integer] in-flight requests during a batch.
    # @param retries [Integer] extra attempts for a transient failure.
    # @param transport [Transport, nil] override the HTTP layer, mostly for tests.
    def initialize(api_key: nil, base_url: DEFAULT_BASE_URL, cache: true,
                   cache_max_size: DEFAULT_CACHE_MAX_SIZE, cache_ttl: DEFAULT_CACHE_TTL,
                   concurrency: DEFAULT_CONCURRENCY, retries: DEFAULT_RETRIES,
                   timeout: DEFAULT_TIMEOUT, transport: nil)
      @transport = transport || Transport.new(
        Transport::Config.new(api_key: api_key, base_url: base_url, timeout: timeout),
      )
      @cache = cache ? Cache.new(max_size: cache_max_size, ttl: cache_ttl) : nil
      @concurrency = concurrency
      @retries = retries
      @database = DatabaseApi.new(@transport, retries: retries)
    end

    # Whether an address is private, loopback, link-local, documentation,
    # multicast or otherwise not routable, including the IPv6 equivalents and
    # the 6to4 and Teredo ranges.
    #
    # These are the addresses {#lookup} answers locally. Exposed here so the
    # check is reachable from the client you already hold; the same predicate is
    # also on the module itself, for code with no client to hand.
    def bogon?(ip)
      Bogon.bogon?(ip)
    end

    # Classify one address.
    #
    # A bogon is answered locally and never reaches the network. Everything else
    # is served, then cached for this instance.
    def lookup(ip, retries: nil)
      return Bogon.result(ip) if Bogon.bogon?(ip)

      hit = @cache&.get(ip)
      return hit unless hit.nil?

      result = Retries.with_retries(retries || @retries) do
        Transport.lookup_result(@transport.lookup_request(ip).run)
      end
      @cache&.set(ip, result)
      result
    end

    # Classify the address this client is calling from.
    #
    # The same answer {#lookup} would give for that address, at the same cost
    # against your allowance. The address is the one our edge observed, so a
    # call made through a proxy or a VPN reports the exit it left through -
    # usually the point of asking.
    #
    # Deliberately NOT cached. The cache is keyed by address, and which address
    # this is IS the question: a machine that moves between networks would
    # otherwise be told where it used to be.
    def my_ip(retries: nil)
      Retries.with_retries(retries || @retries) do
        Transport.lookup_result(@transport.myip_request.run)
      end
    end

    # What this client's key is entitled to, and how much of it has been used.
    #
    # Named for what it answers rather than `me`, which sits one letter from
    # {#my_ip} and means something quite different: one is which address you are
    # calling FROM, the other is what the key you are calling WITH may spend.
    #
    # Unlike a lookup there is no useful unauthenticated answer, so a client
    # built without an API key gets an unauthorized error rather than a partial
    # one.
    #
    # Usage counts against the ALLOWANCE WINDOW - the anniversary of the
    # subscription, not the calendar month and not the billing period - and it
    # is the same number a lookup is gated on. It can lag by a few seconds,
    # because requests are counted in memory and flushed in aggregate.
    #
    # Deliberately NOT cached: the whole point is what has been spent, and a
    # cached answer is a wrong one within seconds of the next request.
    #
    # @return [Entitlement]
    def my_entitlement(retries: nil)
      Retries.with_retries(retries || @retries) do
        Transport.entitlement_result(@transport.entitlement_request.run)
      end
    end

    # Classify many addresses in parallel.
    #
    # Keyed by address rather than positional, so duplicates in the input
    # collapse to a single request and the caller never has to line two lists
    # up. An address that fails carries its error as its value, so one bad entry
    # cannot lose the rest of the answers.
    #
    # @return [Hash{String => Result, Error}] in the order the addresses were given
    def lookup_batch(ips, concurrency: nil, retries: nil)
      addresses = ips.to_a.uniq
      answers = {}
      pending = []

      addresses.each do |ip|
        hit = Bogon.bogon?(ip) ? Bogon.result(ip) : @cache&.get(ip)
        hit.nil? ? pending << ip : answers[ip] = hit
      end
      unless pending.empty?
        run_batch(pending, answers, concurrency || @concurrency, retries || @retries)
      end

      # Reinstated in input order: a hydra settles in completion order, and a
      # caller iterating the hash should see what they passed in.
      addresses.to_h { |ip| [ip, answers[ip]] }
    end

    private

    # One hydra per call, sized for THIS call. Reusing an instance-level hydra
    # would silently cap a per-call concurrency at the client's setting, and
    # would not be safe to drive from two threads either.
    def run_batch(pending, answers, concurrency, retries)
      hydra = Typhoeus::Hydra.new(max_concurrency: concurrency)
      attempts = Hash.new(0)

      enqueue = lambda do |ip|
        request = @transport.lookup_request(ip)
        request.on_complete do |response|
          outcome = settle(ip, response, attempts, retries, enqueue)
          answers[ip] = outcome unless outcome.nil?
        end
        hydra.queue(request)
      end

      pending.each { |ip| enqueue.call(ip) }
      hydra.run
    end

    def settle(ip, response, attempts, retries, enqueue)
      result = Transport.lookup_result(response)
      @cache&.set(ip, result)
      result
    rescue Error => e
      return e unless e.retryable? && attempts[ip] < retries

      attempts[ip] += 1
      # Sleeping here stalls the whole hydra, which is what a server-supplied
      # delay asks for: it is telling every request to this host to back off.
      sleep(Retries.delay_for(e, attempts[ip]))
      enqueue.call(ip)
      nil
    end
  end
end
