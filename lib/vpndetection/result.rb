# frozen_string_literal: true

module VPNDetection
  # What a lookup answers.
  #
  # An **absent** member is one your plan does not include. It never means "we
  # could not check", so `nil` and `false` are genuinely different answers: `nil`
  # is "not in your plan", `false` is "checked, and no".
  #
  # Ruby makes that easy to lose, because `nil` and `false` are both falsy. Read
  # the field itself (`is_hosting`) when the difference matters, ask
  # {#included?} when you need to know whether your plan carries it at all, and
  # use the predicate (`hosting?`) when you only care whether the address is
  # flagged. A predicate always answers `true` or `false`, never `nil`.
  #
  # A detail object that is present but empty (`{}`) means the flag above it is
  # false. A populated one always carries every one of its keys. Details are the
  # wire hashes with their original string keys, so `result.vpn['provider']`.
  class Result
    FLAGS = %w[
      is_vpn is_hosting is_relay is_tor is_cdn is_resproxy is_dcproxy is_mobproxy
      is_pubproxy
    ].freeze

    DETAILS = %w[vpn hosting relay tor cdn resproxy dcproxy mobproxy pubproxy].freeze

    # Where the address is, and the AS announcing it: every keyed answer carries
    # both, each member present, an empty string or AS 0 where nothing is known.
    LOCATION = %w[
      continent continent_name country country_name timezone currency_code currency_name currency_symbol
      flag_emoji flag_unicode
    ].freeze

    ASN = %w[asn name domain type prefix].freeze

    # The response exactly as it came off the wire, with its original names.
    # Frozen, because the cache hands this same object to every later caller of
    # the address.
    attr_reader :raw

    def initialize(raw, bogon: false)
      @raw = deep_freeze(raw)
      @bogon = bogon
      freeze
    end

    # The address that was looked up, normalized.
    def ip
      @raw['ip']
    end

    # Set when this answer was computed locally rather than served. Always
    # `true` or `false`.
    def bogon?
      @bogon
    end

    # Whether your plan includes a member at all, told apart from a member your
    # plan includes that answered false.
    #
    #   result.included?(:is_hosting)   # => false, not in your plan
    #   result.is_hosting               # => nil
    def included?(field)
      @raw.key?(field.to_s)
    end

    # Whether the address is VPN infrastructure. Every plan includes this.
    def is_vpn
      @raw['is_vpn']
    end

    # `is_vpn` with an absent member read as false.
    def vpn?
      @raw['is_vpn'] == true
    end

    # Whether the address belongs to a hosting or cloud provider, or nil when
    # your plan does not include it. Every paid plan.
    def is_hosting
      @raw['is_hosting']
    end

    # `is_hosting` with an absent member read as false.
    def hosting?
      @raw['is_hosting'] == true
    end

    # Whether the address is a privacy relay egress, or nil when your plan does
    # not include it. Free and paid plans.
    def is_relay
      @raw['is_relay']
    end

    # `is_relay` with an absent member read as false.
    def relay?
      @raw['is_relay'] == true
    end

    # Whether the address is a Tor node, or nil when your plan does not include
    # it. Free and paid plans.
    def is_tor
      @raw['is_tor']
    end

    # `is_tor` with an absent member read as false.
    def tor?
      @raw['is_tor'] == true
    end

    # Whether the address belongs to a CDN, or nil when your plan does not
    # include it. Every paid plan.
    def is_cdn
      @raw['is_cdn']
    end

    # `is_cdn` with an absent member read as false.
    def cdn?
      @raw['is_cdn'] == true
    end

    # Whether the address was seen in a residential proxy pool, or nil when your
    # plan does not include it. Every paid plan.
    def is_resproxy
      @raw['is_resproxy']
    end

    # `is_resproxy` with an absent member read as false.
    def resproxy?
      @raw['is_resproxy'] == true
    end

    # Whether the address was seen in a datacenter proxy pool, or nil when your
    # plan does not include it. Every paid plan.
    def is_dcproxy
      @raw['is_dcproxy']
    end

    # `is_dcproxy` with an absent member read as false.
    def dcproxy?
      @raw['is_dcproxy'] == true
    end

    # Whether the address was seen in a mobile proxy pool, or nil when your plan
    # does not include it. Every paid plan.
    def is_mobproxy
      @raw['is_mobproxy']
    end

    # `is_mobproxy` with an absent member read as false.
    def mobproxy?
      @raw['is_mobproxy'] == true
    end

    # Whether a public proxy, one anyone can connect through, listens on the
    # address or sends its traffic out from it, or nil when your plan does not
    # include it. Every paid plan.
    def is_pubproxy
      @raw['is_pubproxy']
    end

    # `is_pubproxy` with an absent member read as false.
    def pubproxy?
      @raw['is_pubproxy'] == true
    end

    # Detail for `is_vpn`: provider, last_seen and confidence. Every paid plan.
    # `method` is deprecated: no plan is answered with it since 2026-10-20.
    def vpn
      @raw['vpn']
    end

    # Detail for `is_hosting`. Every paid plan.
    def hosting
      @raw['hosting']
    end

    # Detail for `is_relay`. Free and paid plans.
    def relay
      @raw['relay']
    end

    # Detail for `is_tor`. Free and paid plans.
    def tor
      @raw['tor']
    end

    # Detail for `is_cdn`. Every paid plan.
    def cdn
      @raw['cdn']
    end

    # Detail for `is_resproxy`. Every paid plan.
    def resproxy
      @raw['resproxy']
    end

    # Detail for `is_dcproxy`. Every paid plan.
    def dcproxy
      @raw['dcproxy']
    end

    # Detail for `is_mobproxy`. Every paid plan.
    def mobproxy
      @raw['mobproxy']
    end

    # Detail for `is_pubproxy`: entry, exit, protocols, num_ports,
    # num_proxies, last_seen and last_usable. num_ports is 0 when the address
    # is only an exit and num_proxies 0 when it is only an entry; last_usable is
    # an empty string when no request through a proxy on the address was
    # answered. Every paid plan.
    def pubproxy
      @raw['pubproxy']
    end

    # Where the address is: continent, country, timezone, the country's
    # currency and flag, as a wire hash (`result.location['country']`). Free and
    # paid plans.
    def location
      @raw['location']
    end

    # The AS announcing the address: asn, name, domain, type and prefix, as a
    # wire hash (`result.asn['name']`), with asn 0 where none does. Free and paid
    # plans.
    def asn
      @raw['asn']
    end

    def to_h
      @raw
    end

    def ==(other)
      other.is_a?(Result) && other.raw == @raw && other.bogon? == @bogon
    end
    alias eql? ==

    def hash
      [@raw, @bogon].hash
    end

    def inspect
      "#<#{self.class} ip=#{ip.inspect} is_vpn=#{is_vpn.inspect} bogon=#{@bogon}>"
    end

    private

    def deep_freeze(value)
      case value
      when Hash then value.each { |_, v| deep_freeze(v) }.freeze
      when Array then value.each { |v| deep_freeze(v) }.freeze
      else value.freeze
      end
    end
  end
end
