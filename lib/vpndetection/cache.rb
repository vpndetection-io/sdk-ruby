# frozen_string_literal: true

require 'lru_redux'

module VPNDetection
  # The per-client answer cache.
  #
  # Per instance and never global: two clients with different keys are on
  # different plans and entitled to different fields, so a shared cache would
  # serve one of them the other's shape. Errors are never stored and bogons
  # never reach it.
  #
  # A reduced answer, a spent trial's or a reached cap's, ends with the trial's
  # renewal or a raised cap, so it stays a minute at most rather than the TTL. It
  # is still cached, or a busy process would send every repeat to the API.
  class Cache
    # The longest a spent trial's or a reached cap's answer is held, in seconds.
    REDUCED_TTL = 60

    def initialize(max_size:, ttl:)
      raise ArgumentError, 'cache_max_size must be positive' unless max_size.to_i.positive?

      @ttl = ttl
      @store = LruRedux::TTL::ThreadSafeCache.new(max_size.to_i, ttl)
    end

    def get(key)
      value, expires = @store[key]
      return nil if expires.nil?
      return value if now < expires

      @store.delete(key)
      nil
    end

    def set(key, value)
      @store[key] = [value, now + life_of(value)]
    end

    # When the answer held for `key` goes stale, on the monotonic clock, or nil.
    def expiry(key)
      @store[key]&.last
    end

    def clear
      @store.clear
    end

    def size
      @store.count
    end

    private

    def life_of(value)
      reduced = value.respond_to?(:trial_expired?) && (value.trial_expired? || value.cap_reached?)
      reduced ? [@ttl, REDUCED_TTL].min : @ttl
    end

    def now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
