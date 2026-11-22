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
  # A detail object that is present but empty (`{}`, or `web`'s `[]`) means the
  # flag above it is false. A populated one always carries every one of its keys. Details are the
  # wire hashes with their original string keys, so `result.vpn['provider']`.
  class Result
    FLAGS = %w[
      is_vpn is_hosting is_relay is_tor is_cdn is_bot is_resproxy is_dcproxy is_mobproxy
      is_pubproxy is_anycast is_carrier is_satellite is_ssh is_smtp is_web is_dns_resolver
      is_bittorrent
    ].freeze

    # The detail object behind each flag that has one; `is_anycast` has none.
    DETAILS = %w[
      vpn hosting relay tor cdn bot resproxy dcproxy mobproxy pubproxy carrier satellite ssh smtp
      dns_resolver bittorrent
    ].freeze

    # The details that are a list of rows rather than one object.
    DETAIL_LISTS = %w[web].freeze

    # Where the address is, and the AS announcing it: every answer carries both,
    # with or without a key, each member present, an empty string or AS 0 where
    # nothing is known. The location's finer members, from `region` down, are a
    # paid plan's, and absent on an answer without them.
    LOCATION = %w[
      continent continent_name country country_name timezone currency_code currency_name currency_symbol
      flag_emoji flag_unicode region region_code city postal_code latitude longitude accuracy_radius
      geoname_id dma_code last_changed
    ].freeze

    ASN = %w[asn name domain type prefix country rpki_status].freeze

    # Who uses the address, and where to report abuse from it: a paid plan's,
    # each member present whenever the object is, an empty string where no
    # record covers the address.
    COMPANY = %w[name domain type country].freeze

    ABUSE = %w[email name phone address country network validated unvalidated_since].freeze

    # The response exactly as it came off the wire, with its original names.
    # Frozen, because the cache hands this same object to every later caller of
    # the address.
    attr_reader :raw

    def initialize(raw, bogon: raw['is_bogon'] == true)
      @raw = deep_freeze(raw)
      @bogon = bogon
      freeze
    end

    # The address that was looked up, normalized.
    def ip
      @raw['ip']
    end

    # Whether the address is reserved space (private, loopback, documentation
    # and the like), which this library answers locally without a request. A
    # served answer carries the API's own `is_bogon`, which this reads. Always
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
    # your plan does not include it. On every paid plan.
    def is_hosting
      @raw['is_hosting']
    end

    # `is_hosting` with an absent member read as false.
    def hosting?
      @raw['is_hosting'] == true
    end

    # Whether the address is a privacy relay egress, or nil when your plan does
    # not include it. Every answer, with or without a key.
    def is_relay
      @raw['is_relay']
    end

    # `is_relay` with an absent member read as false.
    def relay?
      @raw['is_relay'] == true
    end

    # Whether the address is a Tor node, or nil when your plan does not include
    # it. Every answer, with or without a key.
    def is_tor
      @raw['is_tor']
    end

    # `is_tor` with an absent member read as false.
    def tor?
      @raw['is_tor'] == true
    end

    # Whether the address belongs to a CDN, or nil when your plan does not
    # include it. On every paid plan.
    def is_cdn
      @raw['is_cdn']
    end

    # `is_cdn` with an absent member read as false.
    def cdn?
      @raw['is_cdn'] == true
    end

    # Whether an automated client uses the address, such as a search engine's
    # or an AI company's crawler, an uptime monitor, an internet scanner or a
    # webhook sender, or nil when your plan does not include it. Every answer,
    # with or without a key.
    def is_bot
      @raw['is_bot']
    end

    # `is_bot` with an absent member read as false.
    def bot?
      @raw['is_bot'] == true
    end

    # Whether the address was seen in a residential proxy pool, or nil when your
    # plan does not include it. On every paid plan.
    def is_resproxy
      @raw['is_resproxy']
    end

    # `is_resproxy` with an absent member read as false.
    def resproxy?
      @raw['is_resproxy'] == true
    end

    # Whether the address is one a datacenter proxy service sells or runs on, a
    # proxy company's own ranges included, or nil when your plan does not
    # include it. On every paid plan.
    def is_dcproxy
      @raw['is_dcproxy']
    end

    # `is_dcproxy` with an absent member read as false.
    def dcproxy?
      @raw['is_dcproxy'] == true
    end

    # Whether the address was seen in a mobile proxy pool, or nil when your plan
    # does not include it. On every paid plan.
    def is_mobproxy
      @raw['is_mobproxy']
    end

    # `is_mobproxy` with an absent member read as false.
    def mobproxy?
      @raw['is_mobproxy'] == true
    end

    # Whether a public proxy, one anyone can connect through, listens on the
    # address or sends its traffic out from it, or nil when your plan does not
    # include it. On every paid plan.
    def is_pubproxy
      @raw['is_pubproxy']
    end

    # `is_pubproxy` with an absent member read as false.
    def pubproxy?
      @raw['is_pubproxy'] == true
    end

    # Whether the address is announced from many places at once, as a public
    # DNS resolver's or a CDN's edge is, or nil when your plan does not include
    # it. Every answer, with or without a key.
    def is_anycast
      @raw['is_anycast']
    end

    # `is_anycast` with an absent member read as false.
    def anycast?
      @raw['is_anycast'] == true
    end

    # Whether the address is a mobile carrier's, where many phones can share one
    # address, or nil when your plan does not include it. On every paid plan.
    def is_carrier
      @raw['is_carrier']
    end

    # `is_carrier` with an absent member read as false.
    def carrier?
      @raw['is_carrier'] == true
    end

    # Whether the address is a satellite operator's, or nil when your plan does
    # not include it. On every paid plan.
    def is_satellite
      @raw['is_satellite']
    end

    # `is_satellite` with an absent member read as false.
    def satellite?
      @raw['is_satellite'] == true
    end

    # Whether an SSH server answered on the address, or nil when your plan does
    # not include it. On every paid plan.
    def is_ssh
      @raw['is_ssh']
    end

    # `is_ssh` with an absent member read as false.
    def ssh?
      @raw['is_ssh'] == true
    end

    # Whether a mail server answered on the address, or nil when your plan does
    # not include it. On every paid plan.
    def is_smtp
      @raw['is_smtp']
    end

    # `is_smtp` with an absent member read as false.
    def smtp?
      @raw['is_smtp'] == true
    end

    # Whether a web server answered on the address, on port 80 or 443, or nil
    # when your plan does not include it. On every paid plan.
    def is_web
      @raw['is_web']
    end

    # `is_web` with an absent member read as false.
    def web?
      @raw['is_web'] == true
    end

    # Whether an open DNS resolver answered on the address, or nil when your
    # plan does not include it. On every paid plan.
    def is_dns_resolver
      @raw['is_dns_resolver']
    end

    # `is_dns_resolver` with an absent member read as false.
    def dns_resolver?
      @raw['is_dns_resolver'] == true
    end

    # Whether a BitTorrent client was seen on the address in the last 90 days,
    # or nil when your plan does not include it. On every paid plan.
    def is_bittorrent
      @raw['is_bittorrent']
    end

    # `is_bittorrent` with an absent member read as false.
    def bittorrent?
      @raw['is_bittorrent'] == true
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

    # Detail for `is_relay`. Every answer, with or without a key.
    def relay
      @raw['relay']
    end

    # Detail for `is_tor`. Every answer, with or without a key.
    def tor
      @raw['tor']
    end

    # Detail for `is_cdn`. Every paid plan.
    def cdn
      @raw['cdn']
    end

    # Detail for `is_bot`: provider, provider_name, agents, categories,
    # verified, identity, verified_by, confidence, first_seen and last_seen.
    # agents and categories are lists, in the order served, and `[]` where none
    # is known; verified_by is an empty string when verified is false. Every
    # paid plan.
    def bot
      @raw['bot']
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

    # Detail for `is_carrier`: name, mcc, mnc, country and confidence. Every
    # paid plan.
    def carrier
      @raw['carrier']
    end

    # Detail for `is_satellite`: provider, provider_name, orbit, segment,
    # country, asn and confidence. Every paid plan.
    def satellite
      @raw['satellite']
    end

    # Detail for `is_ssh`: port, banner, host_key_fp, session_ok, first_seen and
    # last_seen. Every paid plan.
    def ssh
      @raw['ssh']
    end

    # Detail for `is_smtp`: port, banner, session_ok, first_seen and last_seen.
    # Every paid plan.
    def smtp
      @raw['smtp']
    end

    # Detail for `is_web`: a row per port that answered, lowest first, and `[]`
    # when the flag is false. Every paid plan.
    def web
      @raw['web']
    end

    # Detail for `is_dns_resolver`: port, recursion_available, rcode,
    # answer_correct, first_seen and last_seen. Every paid plan.
    def dns_resolver
      @raw['dns_resolver']
    end

    # Detail for `is_bittorrent`: verified, id_matches_ip, first_seen,
    # last_seen, last_reachable, days_seen, num_ports, peak_num_ports, indexer
    # and clients. Every paid plan.
    def bittorrent
      @raw['bittorrent']
    end

    # Where the address is: continent, country, timezone, the country's
    # currency and flag, as a wire hash (`result.location['country']`). Every
    # answer, with or without a key; the region, city, postal code, coordinates
    # and the rest of the finer members on every paid plan.
    def location
      @raw['location']
    end

    # The AS announcing the address: asn, name, domain, type, prefix, the
    # country its registry assigned it to and the announcement's RPKI status, as
    # a wire hash (`result.asn['name']`), with asn 0 where none does. Every
    # answer, with or without a key.
    def asn
      @raw['asn']
    end

    # Who uses the address: name, domain, type and country, as a wire hash.
    # Every paid plan.
    def company
      @raw['company']
    end

    # The name the address's reverse DNS (PTR) record points to, an empty string
    # when it has none. Every answer, with or without a key.
    def hostname
      @raw['hostname']
    end

    # Where to report abuse from the address: email, name, phone, address,
    # country, network, validated and unvalidated_since, as a wire hash. Every
    # paid plan.
    def abuse
      @raw['abuse']
    end

    # On answers to a key on the free plan only: false while its organization's
    # trial of every field lasts, true once the answer has Unlimited's; nil on any
    # other answer.
    def trial_expired
      @raw['trial_expired']
    end

    # `trial_expired` with an absent member read as false.
    def trial_expired?
      @raw['trial_expired'] == true
    end

    # On answers to a key on a paid plan only: false while the answer has every
    # field, true once its organization's overage cap is reached and the answer
    # has Unlimited's; nil on any other answer. Lookups answered past the cap are
    # not billed.
    def cap_reached
      @raw['cap_reached']
    end

    # `cap_reached` with an absent member read as false.
    def cap_reached?
      @raw['cap_reached'] == true
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
