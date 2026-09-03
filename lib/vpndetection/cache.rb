# frozen_string_literal: true

require 'lru_redux'

module VPNDetection
  # The per-client answer cache.
  #
  # Per instance and never global: two clients with different keys are on
  # different plans and entitled to different fields, so a shared cache would
  # serve one of them the other's shape. Errors are never stored and bogons
  # never reach it.
  class Cache
    def initialize(max_size:, ttl:)
      raise ArgumentError, 'cache_max_size must be positive' unless max_size.to_i.positive?

      @store = LruRedux::TTL::ThreadSafeCache.new(max_size.to_i, ttl)
    end

    def get(key)
      @store[key]
    end

    def set(key, value)
      @store[key] = value
    end

    def clear
      @store.clear
    end

    def size
      @store.count
    end
  end
end
