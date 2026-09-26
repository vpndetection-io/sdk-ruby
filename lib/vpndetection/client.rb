# frozen_string_literal: true

require 'typhoeus'

module VPNDetection
  DEFAULT_BASE_URL = 'https://api.vpndetection.io'
  DEFAULT_CACHE_MAX_SIZE = 10_000
  DEFAULT_CACHE_TTL = 3600
  DEFAULT_CONCURRENCY = 8
  DEFAULT_RETRIES = 2
  DEFAULT_TIMEOUT = 30
  # The most addresses POST /batch takes in one call; a larger batch is sent in
  # chunks of this size.
  BATCH_MAX = 1000

  # A client for the VPNDetection API.
  #
  # The cache is per instance, so an answer is never shared between two clients
  # holding different API keys and therefore entitled to different fields.
  class Client
    # The licensed dataset downloads, for keys that carry the `db.download` scope.
    attr_reader :database
    # Signing a person in with OAuth, which needs no API key at all.
    attr_reader :oauth

    # @param api_key [String, nil] omit it entirely to use the free tier, which
    #   answers `ip` and `is_vpn` and allows 1000 requests per day per source
    #   address.
    # @param cache [Boolean] pass false to disable caching.
    # @param cache_ttl [Numeric] how long an answer stays fresh, in seconds.
    # @param concurrency [Integer] batch requests - chunks of up to 1000 addresses - in flight during a batch.
    # @param retries [Integer] extra attempts for a transient failure. Each waits
    #   the server's `Retry-After` when it sent one of at most about 24.8 days,
    #   and otherwise a backoff of 250 ms that doubles per retry.
    # @param timeout [Numeric] seconds one request may take before it is
    #   abandoned, 0 for no bound. Applies per ATTEMPT, so a retried call may take
    #   longer in total, and every call that takes `retries:` also takes
    #   `timeout:` to override it. A dataset transfer bounds only its connect
    #   phase with it.
    # @raise [ArgumentError] for a `timeout`, here or on any call, that is
    #   negative, not a finite number, or past 2147483.647 seconds (2**31 - 1 ms),
    #   the longest curl holds.
    # @param transport [Transport, nil] override the HTTP layer, mostly for tests.
    def initialize(api_key: nil, base_url: DEFAULT_BASE_URL, cache: true,
                   cache_max_size: DEFAULT_CACHE_MAX_SIZE, cache_ttl: DEFAULT_CACHE_TTL,
                   concurrency: DEFAULT_CONCURRENCY, retries: DEFAULT_RETRIES,
                   timeout: DEFAULT_TIMEOUT, transport: nil)
      @transport = transport || Transport.new(
        Transport::Config.new(api_key: api_key, base_url: base_url, timeout: timeout),
      )
      @cache = cache ? Cache.new(max_size: cache_max_size, ttl: cache_ttl) : nil
      # The addresses with a request in flight, each a Flight its waiters block on.
      @flights = {}
      @flights_lock = Mutex.new
      @concurrency = concurrency
      @retries = retries
      @database = DatabaseApi.new(@transport, retries: retries)
      @oauth = OauthApi.new(@transport, retries: retries)
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
    #
    # @param retries [Integer, nil] extra attempts, for THIS call only.
    # @param timeout [Numeric, nil] seconds each attempt may take, for THIS call only.
    def lookup(ip, retries: nil, timeout: nil)
      # Here as well as in the transport: a bogon or a cached answer returns before any request.
      Transport.checked_timeout(timeout) unless timeout.nil?
      return Bogon.result(ip) if Bogon.bogon?(ip)

      loop do
        hit = @cache&.get(ip)
        return hit unless hit.nil?

        flight, leader = board(ip)
        return fetch(ip, retries, timeout) if flight.nil?

        if leader
          # Read once more now the address is boarded: a leader that landed
          # between the miss above and boarding has already cached its answer.
          hit = @cache.get(ip)
          return unboard(ip, flight, :served, hit) unless hit.nil?

          return lead(ip, flight) { fetch(ip, retries, timeout) }
        end
        state, value = flight.wait
        return value if state == :served
        raise value if state == :failed
        # :abandoned - its leader never finished, so this caller asks again.
      end
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
    def my_ip(retries: nil, timeout: nil)
      Retries.with_retries(retries || @retries) do
        Transport.lookup_result(@transport.myip_request(timeout: timeout).run)
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
    def my_entitlement(retries: nil, timeout: nil)
      Retries.with_retries(retries || @retries) do
        Transport.entitlement_result(@transport.entitlement_request(timeout: timeout).run)
      end
    end

    # Classify many addresses in as few requests as possible.
    #
    # Bogons are answered locally and cached answers are reused; everything else
    # goes to the batch endpoint in chunks of up to 1000 addresses, with at most
    # `concurrency` chunks in flight. Keyed by address rather than positional, so
    # duplicates in the input collapse to a single entry and the caller never has
    # to line two lists up. An address that fails carries its error as its value,
    # so one bad entry cannot lose the rest of the answers: the API reports a
    # per-entry failure with the status the single lookup would have answered,
    # and a chunk that fails as a whole marks every address in it.
    #
    # @param concurrency [Integer, nil] chunks in flight, for THIS batch only. Below 1
    #   is refused as `:bad_request` before any request, since nothing could ever run.
    # @param retries [Integer, nil] extra attempts for a failed chunk, for THIS batch only.
    # @param timeout [Numeric, nil] seconds each chunk's attempt may take, for THIS batch only.
    # @return [Hash{String => Result, Error}] in the order the addresses were given
    def lookup_batch(ips, concurrency: nil, retries: nil, timeout: nil)
      limit = concurrency || @concurrency
      unless limit.is_a?(Numeric) && limit >= 1
        raise Error.new(:bad_request, "concurrency must be at least 1, not #{limit.inspect}")
      end
      Transport.checked_timeout(timeout) unless timeout.nil?

      addresses = ips.to_a.uniq
      answers = {}
      pending = []

      addresses.each do |ip|
        hit = Bogon.bogon?(ip) ? Bogon.result(ip) : @cache&.get(ip)
        hit.nil? ? pending << ip : answers[ip] = hit
      end
      # Boarded before any chunk is built, so a lookup arriving meanwhile waits
      # for this batch; an address already in flight is not sent again.
      boarded = {}
      joined = {}
      pending.each do |ip|
        flight, leader = board(ip)
        if leader == false
          joined[ip] = flight
        else
          boarded[ip] = flight
        end
      end
      begin
        unless boarded.empty?
          chunks = boarded.keys.each_slice(BATCH_MAX).to_a
          run_batch(chunks, answers, limit, retries || @retries, timeout, boarded)
        end
      ensure
        boarded.each { |ip, flight| unboard(ip, flight, :abandoned) unless flight.nil? }
      end
      joined.each { |ip, flight| answers[ip] = joined_answer(ip, flight, retries, timeout) }

      # Reinstated in input order: a hydra settles in completion order, and a
      # caller iterating the hash should see what they passed in.
      addresses.to_h { |ip| [ip, answers[ip]] }
    end

    private

    # Concurrent misses for one address share ONE request (docs/sdk/contract.md,
    # UMAN-4645): 5.4.2 sent one per calling thread. The first miss boards the
    # address and every miss after it, a batch's included, waits on its Flight.
    class Flight
      def initialize
        @lock = Mutex.new
        @landed = ConditionVariable.new
        @state = :pending
      end

      # Settles the flight once, for every waiter: :served with a Result,
      # :failed with an Error, or :abandoned when its leader never finished.
      def land(state, value = nil)
        @lock.synchronize do
          next unless @state == :pending

          @state = state
          @value = value
          @landed.broadcast
        end
      end

      # Blocks until the flight lands, then [state, value].
      def wait
        @lock.synchronize do
          @landed.wait(@lock) while @state == :pending
          [@state, @value]
        end
      end
    end

    # [flight, true] when this caller leads the request for `ip`, [flight,
    # false] when one is already in flight, and nil without a cache: every
    # lookup is then served, so nothing is shared.
    def board(ip)
      return nil if @cache.nil?

      @flights_lock.synchronize do
        existing = @flights[ip]
        existing ? [existing, false] : [@flights[ip] = Flight.new, true]
      end
    end

    # Takes `ip` off the board and lands its flight. Returns `value`.
    def unboard(ip, flight, state, value = nil)
      @flights_lock.synchronize { @flights.delete(ip) if @flights[ip].equal?(flight) }
      flight.land(state, value)
      value
    end

    # Runs the request a flight is waiting on, under the options of the call
    # that leads it. A served answer is cached before it lands; a failure
    # reaches every waiter and is cached for none; and a leader that never
    # finishes - a killed thread, a Timeout.timeout - abandons the flight, so
    # its waiters ask again rather than failing with it.
    def lead(ip, flight)
      unboard(ip, flight, :served, yield)
    rescue Error => e
      unboard(ip, flight, :failed, e)
      raise
    ensure
      unboard(ip, flight, :abandoned)
    end

    def fetch(ip, retries, timeout)
      result = Retries.with_retries(retries || @retries) do
        Transport.lookup_result(@transport.lookup_request(ip, timeout: timeout).run)
      end
      @cache&.set(ip, result)
      result
    end

    # One hydra per call, sized for THIS call. Reusing an instance-level hydra
    # would silently cap a per-call concurrency at the client's setting, and
    # would not be safe to drive from two threads either. Each request is one
    # chunk of up to 1000 addresses.
    def run_batch(chunks, answers, concurrency, retries, timeout, boarded)
      hydra = Typhoeus::Hydra.new(max_concurrency: concurrency)
      attempts = Hash.new(0)

      enqueue = lambda do |chunk|
        request = @transport.batch_request(chunk, timeout: timeout)
        request.on_complete do |response|
          outcome = settle(chunk, response, attempts, retries, enqueue)
          outcome&.each do |ip, answer|
            answers[ip] = answer
            flight = boarded[ip]
            unboard(ip, flight, answer.is_a?(Result) ? :served : :failed, answer) unless flight.nil?
          end
        end
        hydra.queue(request)
      end

      chunks.each { |chunk| enqueue.call(chunk) }
      hydra.run
    end

    # One POST /batch, mapped back onto the addresses it was asked about. A
    # chunk-level failure - the call refused, the transport failing, the retries
    # exhausted - becomes every address's error, exactly as it would have been
    # had each been looked up alone.
    def settle(chunk, response, attempts, retries, enqueue)
      body = Transport.batch_body(response)
      chunk.to_h do |ip|
        answer = batch_answer(ip, body)
        @cache&.set(ip, answer) if answer.is_a?(Result)
        [ip, answer]
      end
    rescue Error => e
      return chunk.to_h { |ip| [ip, e] } unless e.retryable? && attempts[chunk] < retries

      attempts[chunk] += 1
      # Sleeping here stalls the whole hydra, which is what a server-supplied
      # delay asks for: it is telling every request to this host to back off.
      sleep(Retries.delay_for(e, attempts[chunk]))
      enqueue.call(chunk)
      nil
    end

    # What a batch takes for an address another call was fetching: that call's
    # answer or error, or, when its leader never finished, its own lookup.
    def joined_answer(ip, flight, retries, timeout)
      state, value = flight.wait
      return value unless state == :abandoned

      lookup(ip, retries: retries, timeout: timeout)
    rescue Error => e
      e
    end

    # Every address lands in exactly one of `results` and `errors`; an address in
    # neither is the server breaking its own contract, and is reported as such
    # rather than lost.
    def batch_answer(ip, body)
      if (served = body['results'][ip])
        Result.new(served)
      elsif (failed = body['errors'][ip])
        Error.from_entry(failed['status'], failed['error'])
      else
        Error.new(:server_error, "the batch answer did not include #{ip}", status: 200)
      end
    end
  end
end
