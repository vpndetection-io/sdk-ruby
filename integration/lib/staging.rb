# frozen_string_literal: true

# The staging fixtures the test files share: the guard that this is the PUBLISHED
# gem, one client and one lookup per tier, and the shape rules that hold whatever
# the plan.

require 'json'
require 'minitest/autorun'
require 'typhoeus'
require 'vpndetection'

require_relative 'tiers'

module Staging
  BASE_URL = 'https://api-staging.vpndetection.io'
  # A stable VPN address, and the one the README teaches.
  PROBE = '45.83.91.1'

  # What a POPULATED detail object carries on every tier, and the max-only
  # remainder, which is absent rather than empty on a lower plan.
  MEMBERS = {
    'vpn' => { required: %w[provider provider_name last_seen], optional: %w[confidence method] },
    'hosting' => { required: %w[provider provider_name confidence last_seen] },
    'relay' => { required: %w[provider provider_name confidence last_seen] },
    'tor' => { required: %w[provider provider_name confidence last_seen] },
    'cdn' => { required: %w[provider provider_name confidence last_seen] },
    'bot' => {
      required: %w[provider provider_name agents categories verified identity verified_by confidence first_seen
                   last_seen],
    },
    'resproxy' => { required: %w[provider provider_name first_seen last_seen hits hits_days_pct providers_num] },
    'dcproxy' => { required: %w[provider provider_name first_seen last_seen hits hits_days_pct providers_num] },
    'mobproxy' => { required: %w[provider provider_name first_seen last_seen hits hits_days_pct providers_num] },
    'carrier' => { required: %w[name mcc mnc country confidence] },
    'satellite' => { required: %w[provider provider_name orbit segment country asn confidence] },
    'ssh' => { required: %w[port banner host_key_fp session_ok first_seen last_seen] },
    'smtp' => { required: %w[port banner session_ok first_seen last_seen] },
    'dns_resolver' => { required: %w[port recursion_available rcode answer_correct first_seen last_seen] },
    'bittorrent' => {
      required: %w[verified id_matches_ip first_seen last_seen last_reachable days_seen num_ports peak_num_ports
                   indexer clients],
    },
  }.freeze

  # The keys of each row of `web`, a list with a row per port that answered.
  WEB_KEYS = %w[
    port tls_ok session_ok status_code server location title cert_subject_cn cert_subject_o cert_issuer_dn
    cert_browser_trusted tls_version first_seen last_seen
  ].freeze

  # The objects that are never empty: `required` is on every answer carrying the
  # object, `optional` only on a plan that includes it.
  OBJECTS = {
    'location' => {
      required: %w[continent continent_name country country_name timezone currency_code currency_name
                   currency_symbol flag_emoji flag_unicode],
      optional: %w[region region_code city postal_code latitude longitude accuracy_radius geoname_id dma_code
                   last_changed],
    },
    'asn' => { required: %w[asn name domain prefix country rpki_status], optional: %w[type] },
    'company' => { required: %w[name domain], optional: %w[type country] },
    'abuse' => { required: %w[email], optional: %w[name phone address country network validated unvalidated_since] },
  }.freeze

  # What a test is allowed to remember about a request it made.
  #
  # Only derived facts leave here. An assertion that fails prints its operands,
  # and these logs are public, so which tier's key was carried is recorded as a
  # name and the key itself is never held. `ips` is what a POST /batch asked
  # about, which is the test's own input.
  Fact = Struct.new(:origin, :path, :tiers, :ips, keyword_init: true)

  module_function

  # The whole point of this package: exercise the gem a stranger installs.
  #
  # A suite pointed at the working tree passes every test and says nothing, and
  # bundler makes that easy to do by accident, so the resolved source is checked
  # rather than assumed. Called at load, so no test can run before it holds.
  def assert_published!
    spec = Gem.loaded_specs['vpndetection']
    raise 'vpndetection is not in the bundle at all' if spec.nil?

    if defined?(Bundler::Source::Path) && spec.source.is_a?(Bundler::Source::Path)
      raise "vpndetection came from a path source at #{spec.gem_dir}, which is not a release"
    end

    repo = File.expand_path('../..', __dir__)
    if spec.gem_dir == repo || spec.gem_dir.start_with?("#{repo}/")
      raise "vpndetection was loaded from #{spec.gem_dir}, inside this repository, not from RubyGems"
    end

    puts "==> testing vpndetection #{spec.version} from #{spec.gem_dir}"
  end

  def facts
    @facts ||= begin
      # A `before` hook that answers nil or false SKIPS the request outright, and
      # a hook ending on an assignment does exactly that. It must return true.
      Typhoeus.before { |request| note(request) }
      []
    end
  end

  def note(request)
    carried = Tiers::RUNGS.filter_map do |rung|
      key = Tiers.key(rung)
      rung[:tier] if key && (request.url.include?(key) || headers_carry?(request, key))
    end
    uri = URI.parse(request.url)
    facts << Fact.new(origin: "#{uri.scheme}://#{uri.host}", path: uri.path, tiers: carried,
                      ips: batch_ips(request))
    true
  end

  def batch_ips(request)
    body = request.options[:body]
    return [] unless body.is_a?(String) && !body.empty?

    JSON.parse(body).fetch('ips', [])
  rescue JSON::ParserError
    []
  end

  def headers_carry?(request, key)
    (request.options[:headers] || {}).any? { |_, value| value.to_s.include?(key) }
  end

  # The payload as the API actually served it.
  #
  # The typed decode cannot answer this: a generated model drops any field it has
  # no home for, so asking IT whether `docsGroup` is published would answer no
  # whether or not the API publishes it.
  def wire_json(path, rung)
    key = Tiers.key(rung)
    headers = { 'Accept' => 'application/json' }
    headers['Authorization'] = "Bearer #{key}" if key
    response = Typhoeus.get("#{BASE_URL}#{path}", headers: headers)
    raise "#{path} answered #{response.code}" unless response.code == 200

    JSON.parse(response.body)
  end

  def client_for(rung, **options)
    facts
    VPNDetection::Client.new(api_key: Tiers.key(rung), base_url: BASE_URL, **options)
  end

  # One lookup per tier for the whole run. The client caches, so a second reader
  # of the same tier would cost no request either, but the fixture also carries
  # what the wire said, which the client does not keep.
  def answer_for(rung)
    @answers ||= {}
    @answers[rung[:tier]] ||= begin
      result = client_for(rung).lookup(PROBE)
      # Checked here rather than in one test, so no comparison anywhere can be
      # made against a tier that silently ran unauthenticated: an unsent key
      # answers the keyless shape, which satisfies every containment check
      # vacuously.
      if rung[:secret] && facts.none? { |fact| fact.tiers.include?(rung[:tier]) }
        raise "#{rung[:tier]}: the key never reached the wire"
      end

      { rung: rung, result: result, raw: result.raw }
    end
  end
end

Staging.assert_published!

# Every assertion about a served answer that holds whatever the plan is:
# presence is the plan, the value is the answer.
module StagingAssertions
  def assert_served_by_tier(fixture)
    tier = fixture[:rung][:tier]
    raw = fixture[:raw]

    assert_equal Staging::PROBE, fixture[:result].ip, "#{tier}: answered about the wrong address"
    refute fixture[:result].bogon?, "#{tier}: a served answer is not a local one"
    assert_kind_of String, raw['ip'], "#{tier}: ip is #{raw['ip'].inspect}, want a string"
    assert_includes [true, false], raw['is_vpn'], "#{tier}: is_vpn is on every plan"
    assert_equal raw['is_vpn'], fixture[:result].is_vpn, "#{tier}: is_vpn disagrees with the wire"

    Staging::MEMBERS.each { |name, spec| assert_member(tier, raw, name, spec) }
    %w[is_anycast is_web].each do |flag|
      assert_includes [true, false], raw[flag], "#{tier}: #{flag} must be a real boolean" if raw.key?(flag)
    end
    assert_kind_of String, raw['hostname'], "#{tier}: hostname must be a string" if raw.key?('hostname')
    assert_web(tier, raw) if raw.key?('web')
    Staging::OBJECTS.each do |name, spec|
      assert_keys(tier, raw[name], name, spec) if raw.key?(name)
    end
    # The AS's type is a paid plan's, so it may be absent or served, and served it is a string.
    assert_kind_of String, raw['asn']['type'], "#{tier}: asn.type must be a string" if raw['asn']&.key?('type')
  end

  def assert_web(tier, raw)
    assert_kind_of Array, raw['web'], "#{tier}: web must be a list when present"
    assert raw.key?('is_web'), "#{tier}: web is served without is_web"
    assert_equal !raw['web'].empty?, raw['is_web'], "#{tier}: web has rows exactly when is_web is true"
    raw['web'].each { |row| assert_keys(tier, row, 'web[]', { required: Staging::WEB_KEYS }) }
  end

  def assert_keys(tier, object, name, spec)
    assert_kind_of Hash, object, "#{tier}: #{name} must be an object when present"
    spec[:required].each do |field|
      assert object.key?(field), "#{tier}: #{name} carries no #{field}"
    end
    documented = spec[:required] + (spec[:optional] || [])
    (object.keys - documented).each do |field|
      flunk "#{tier}: #{name}.#{field} is not a documented key of this object"
    end
  end

  def assert_member(tier, raw, name, spec)
    flag = "is_#{name}"
    if raw.key?(flag)
      assert_includes [true, false], raw[flag], "#{tier}: #{flag} must be a real boolean"
    end
    return unless raw.key?(name)

    # A detail object without its flag would leave a caller reading the object to
    # find out whether the address is flagged at all.
    assert raw.key?(flag), "#{tier}: #{name} is served without #{flag}"
    assert_kind_of Hash, raw[name], "#{tier}: #{name} must be an object when present"
    if raw[name].empty?
      return assert_equal(false, raw[flag], "#{tier}: #{name} is empty, so #{flag} must be false")
    end

    spec[:required].each do |field|
      assert raw[name].key?(field), "#{tier}: #{name} is populated but carries no #{field}"
    end
    documented = spec[:required] + (spec[:optional] || [])
    (raw[name].keys - documented).each do |field|
      flunk "#{tier}: #{name}.#{field} is not a documented key of this detail object"
    end
  end
end
