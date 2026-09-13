# frozen_string_literal: true

require_relative 'test_helper'
require 'vpndetection/middleware'

# The middleware half of the shared conformance corpus, plus the Ruby-specific
# parts of it.
#
# The corpus needs no translation here at all: this SDK's Result is backed by
# the raw wire hash, so `{ 'is_vpn' => true, 'vpn' => { 'provider' => ... } }`
# is both what the corpus holds and what a caller writes. Symbol keys work too.
class MiddlewareTest < Minitest::Test
  include TestHelper

  PUBLIC_IP = '45.83.91.1'
  MIDDLEWARE = TestHelper::CORPUS['middleware']

  # The least a framework can offer, so the core is exercised without one.
  Req = Struct.new(:headers, :ip) do
    def initialize(headers = {}, ip = PUBLIC_IP)
      super(headers.transform_keys { |k| k.to_s.downcase }, ip)
    end
  end

  SELECTORS = VPNDetection::Middleware::Selectors.new do |request|
    VPNDetection::Middleware::RequestView.new(
      header: ->(name) { request.headers[name.downcase] },
      framework_ip: -> { request.ip }
    )
  end

  def setup
    Typhoeus::Expectation.clear
  end

  def teardown
    Typhoeus::Expectation.clear
  end

  def core(**options)
    VPNDetection::Middleware::Core.new(SELECTORS.default, **options)
  end

  def serving(body, status: 200)
    ip = body['ip'] || PUBLIC_IP
    calls = stub_lookups(ip => { status: status, body: body })
    [VPNDetection::Client.new(cache: false, retries: 0), calls]
  end

  def test_corpus_conditions
    MIDDLEWARE['conditions'].each do |c|
      why = "#{c['name']}: #{c['why']}"
      result = if c['bogon']
                 VPNDetection::Bogon.result(c['bogon'])
               else
                 client, = serving(c['body'])
                 client.lookup(c['body']['ip'])
               end

      assert_equal c['expect']['blocked'],
                   VPNDetection::Middleware::Condition.matches?(c['condition'], result), why
      assert_equal c['expect']['missing'].sort,
                   VPNDetection::Middleware::Condition.missing_members(c['condition'], result).sort,
                   why
      Typhoeus::Expectation.clear
    end
  end

  def test_corpus_refuses_a_condition_that_constrains_nothing
    MIDDLEWARE['invalidConditions'].each do |c|
      error = assert_raises(ArgumentError, "#{c['name']}: #{c['why']}") do
        core(block_condition: c['condition'])
      end
      assert_match(/constrains nothing/, error.message)
    end
  end

  def test_enriches_without_blocking_when_no_condition_is_configured
    client, = serving({ 'ip' => PUBLIC_IP, 'is_vpn' => true })
    lookup = core(client: client, ip_selector: ->(_r) { PUBLIC_IP }).evaluate(Req.new)

    refute lookup.blocked?
    assert lookup.result.vpn?
    assert_equal PUBLIC_IP, lookup.ip
  end

  def test_skip_claims_the_request_and_costs_no_lookup
    client, calls = serving({ 'ip' => PUBLIC_IP, 'is_vpn' => true })
    assert_nil core(client: client, skip: ->(_r) { true }).evaluate(Req.new)
    assert_empty calls
  end

  def test_fails_open_on_a_lookup_error_and_closed_only_when_asked
    client, = serving({ 'ip' => PUBLIC_IP, 'error' => 'boom' }, status: 500)
    opened = core(client: client, ip_selector: ->(_r) { PUBLIC_IP },
                  block_condition: { 'is_vpn' => true })
    lookup = opened.evaluate(Req.new)

    refute lookup.blocked?
    assert_kind_of VPNDetection::Error, lookup.error
    assert_nil lookup.result

    closed = core(client: client, ip_selector: ->(_r) { PUBLIC_IP },
                  block_condition: { 'is_vpn' => true }, fail_closed: true)
    assert closed.evaluate(Req.new).blocked?
  end

  def test_a_private_client_address_warns_once_and_never_reaches_the_network
    client, calls = serving({ 'ip' => '10.0.0.7', 'is_vpn' => true })
    warnings = []
    subject = core(client: client, block_condition: { 'is_vpn' => true },
                   on_warn: ->(m) { warnings << m })

    2.times do
      lookup = subject.evaluate(Req.new({}, '10.0.0.7'))
      refute lookup.blocked?
      assert lookup.result.bogon?
    end

    assert_empty calls
    assert_equal 1, warnings.length, 'a per-request warning is an outage of its own'
    assert_match(/not a public address/, warnings.first)
  end

  def test_a_missing_member_warns_once_or_raises_on_request
    client, = serving({ 'ip' => PUBLIC_IP, 'is_vpn' => true })
    warnings = []
    warned = core(client: client, ip_selector: ->(_r) { PUBLIC_IP },
                  block_condition: { 'is_hosting' => true }, on_warn: ->(m) { warnings << m })
    2.times { warned.evaluate(Req.new) }

    assert_equal 1, warnings.length
    assert_match(/is_hosting/, warnings.first)

    strict = core(client: client, ip_selector: ->(_r) { PUBLIC_IP },
                  block_condition: { 'is_hosting' => true }, on_missing_field: :raise)
    error = assert_raises(ArgumentError) { strict.evaluate(Req.new) }
    assert_match(/does not include/, error.message)
  end

  def test_symbol_keys_work_as_well_as_strings
    client, = serving({ 'ip' => PUBLIC_IP, 'is_vpn' => true,
                        'vpn' => { 'provider' => 'nordvpn' } })
    lookup = core(client: client, ip_selector: ->(_r) { PUBLIC_IP },
                  block_condition: { is_vpn: true, vpn: { provider: 'NordVPN' } }).evaluate(Req.new)

    # A Ruby caller writes symbols; the corpus and the wire use strings. Both
    # have to reach the same answer or one of the two is a trap.
    assert lookup.blocked?
  end

  def test_selectors_read_what_they_say_they_read
    request = Req.new({ 'X-Forwarded-For' => '203.0.113.9, 70.41.3.18, 150.172.238.178' },
                      '10.0.0.1')

    assert_equal '10.0.0.1', SELECTORS.default.call(request)
    assert_equal '203.0.113.9', SELECTORS.xff.call(request)
    assert_equal '150.172.238.178', SELECTORS.xff(1).call(request)
    assert_equal '70.41.3.18', SELECTORS.xff(2).call(request)
    assert_equal '10.0.0.1', SELECTORS.header('CF-Connecting-IP').call(request)

    cloudflared = Req.new({ 'CF-Connecting-IP' => '198.51.100.4' }, '10.0.0.1')
    assert_equal '198.51.100.4', SELECTORS.header('CF-Connecting-IP').call(cloudflared)
    assert_equal '10.0.0.1', SELECTORS.xff.call(Req.new({}, '10.0.0.1'))
  end

  def test_an_unresolvable_address_warns_and_does_not_block
    warnings = []
    subject = VPNDetection::Middleware::Core.new(
      ->(_r) { nil },
      block_condition: { 'is_vpn' => true },
      on_warn: ->(m) { warnings << m }
    )
    lookup = subject.evaluate(Req.new)

    refute lookup.blocked?
    assert_kind_of VPNDetection::Error, lookup.error
    assert_match(/could not resolve a client address/, warnings.first)
  end
end

# A regression test for a collision the Rails gem created, not a hypothetical:
# `defined?(Rails)` inside `module VPNDetection` resolves to
# `VPNDetection::Rails` before the top-level one, so the moment the
# vpndetection-rails gem defines that namespace, building any client raised
# NoMethodError on a module that has no `.logger`.
class RailsConstantCollisionTest < Minitest::Test
  def test_a_nested_rails_namespace_does_not_break_the_client
    VPNDetection.const_set(:Rails, Module.new) unless VPNDetection.const_defined?(:Rails, false)
    VPNDetection::Client.new(cache: false)
  ensure
    VPNDetection.send(:remove_const, :Rails) if VPNDetection.const_defined?(:Rails, false)
  end
end
