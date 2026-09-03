# frozen_string_literal: true

# What the shared corpus cannot pin: the Ruby surface, the retry policy's cost in
# requests, and the concurrency a batch genuinely reaches.

require_relative 'test_helper'

class ClientTest < Minitest::Test
  include TestHelper

  OK_BODY = { 'ip' => '1.1.1.1', 'is_vpn' => false }.freeze

  def teardown
    Typhoeus::Config.block_connection = false
    Typhoeus::Expectation.clear
  end

  def test_the_bogon_predicate_is_the_same_answer_on_the_module_and_on_a_client
    client = VPNDetection::Client.new
    %w[10.0.0.1 8.8.8.8 ::1 2606:4700:4700::1111 notanip].each do |ip|
      assert_equal VPNDetection.bogon?(ip), client.bogon?(ip), ip
    end
  end

  def test_a_bogon_answer_is_wider_than_a_free_plan_answer
    stub_lookups('1.1.1.1' => { body: OK_BODY })
    client = VPNDetection::Client.new
    served = client.lookup('1.1.1.1')

    refute served.included?('is_hosting')
    assert client.lookup('10.0.0.1').included?('is_hosting'),
           'a bogon answer carries the widest shape whatever the plan'
  end

  def test_a_result_is_frozen_so_a_cached_answer_cannot_be_poisoned
    body = { 'ip' => '45.83.91.1', 'is_vpn' => true, 'vpn' => { 'provider' => 'mullvad' } }
    stub_lookups('45.83.91.1' => { body: body })
    result = VPNDetection::Client.new.lookup('45.83.91.1')

    assert result.frozen?
    assert result.raw.frozen?
    assert result.vpn.frozen?
    assert_raises(FrozenError) { result.raw['is_vpn'] = false }
  end

  def test_a_404_is_never_retried
    calls = stub_lookups('1.1.1.1' => { status: 404, body: { 'rc' => 'NOT_FOUND' } })
    client = VPNDetection::Client.new(retries: 2)

    error = assert_raises(VPNDetection::Error) { client.lookup('1.1.1.1') }
    assert_equal :bad_request, error.kind
    assert_equal 1, calls.length, 'a client error must cost exactly one request'
  end

  def test_a_429_without_retry_after_is_never_retried
    calls = stub_lookups('1.1.1.1' => { status: 429, body: { 'error' => 'daily limit exceeded' } })
    client = VPNDetection::Client.new(retries: 2)

    error = assert_raises(VPNDetection::Error) { client.lookup('1.1.1.1') }
    assert_equal :quota_exceeded, error.kind
    assert_equal 1, calls.length, 'a spent allowance must not be hammered'
  end

  def test_a_429_carrying_retry_after_is_retried
    calls = []
    Typhoeus.stub(%r{\A#{Regexp.escape(BASE_URL)}/}).and_return(
      [
        lambda { |request|
          calls << request.url
          json_response(429, { 'error' => 'slow down' }, { 'Retry-After' => '0' })
        },
        lambda { |request|
          calls << request.url
          json_response(200, OK_BODY)
        },
      ],
    )
    result = VPNDetection::Client.new(retries: 2).lookup('1.1.1.1')

    assert_equal false, result.is_vpn
    assert_equal 2, calls.length
  end

  def test_a_server_error_is_retried_up_to_the_per_call_limit
    calls = stub_lookups('1.1.1.1' => { status: 500, body: { 'error' => 'lookup failed' } })
    client = VPNDetection::Client.new(retries: 0)

    assert_raises(VPNDetection::Error) { client.lookup('1.1.1.1') }
    assert_equal 1, calls.length, 'the client default of zero retries applies'

    calls.clear
    assert_raises(VPNDetection::Error) { client.lookup('1.1.1.1', retries: 2) }
    assert_equal 3, calls.length, 'a per-call retries override must be honored'
  end

  def test_a_transport_failure_is_a_network_error
    Typhoeus.stub(%r{\A#{Regexp.escape(BASE_URL)}/}).and_return(
      Typhoeus::Response.new(code: 0, return_code: :couldnt_connect, body: ''),
    )
    error = assert_raises(VPNDetection::Error) { VPNDetection::Client.new(retries: 0).lookup('1.1.1.1') }

    assert_equal :network, error.kind
    assert error.retryable?
  end

  def test_a_cached_answer_expires_with_its_ttl
    calls = stub_lookups('1.1.1.1' => { body: OK_BODY })
    client = VPNDetection::Client.new(cache_ttl: 0.05)

    client.lookup('1.1.1.1')
    client.lookup('1.1.1.1')
    assert_equal 1, calls.length

    sleep 0.1
    client.lookup('1.1.1.1')
    assert_equal 2, calls.length
  end

  def test_a_batch_reaches_the_concurrency_it_was_given
    server = TestServer.new(delay: 0.05)
    client = VPNDetection::Client.new(base_url: server.base_url, concurrency: 2, cache: false)
    addresses = (1..12).map { |n| "203.0.114.#{n}" }

    client.lookup_batch(addresses)
    assert_equal 2, server.peak, 'the client setting bounds a batch that does not override it'

    per_call = TestServer.new(delay: 0.05)
    VPNDetection::Client.new(base_url: per_call.base_url, concurrency: 2, cache: false)
                        .lookup_batch(addresses, concurrency: 8)
    assert_equal 8, per_call.peak, 'a per-call concurrency must widen the batch, not be swallowed'
  ensure
    server&.stop
    per_call&.stop
  end

  def test_a_batch_honors_a_per_call_retries_override
    attempts = Hash.new(0)
    server = TestServer.new(delay: 0.0) do |path|
      attempts[path] += 1
      if attempts[path] < 3
        [500, '{"error":"lookup failed"}']
      else
        [200, JSON.generate({ 'ip' => path[1..], 'is_vpn' => true })]
      end
    end
    client = VPNDetection::Client.new(base_url: server.base_url, retries: 0, cache: false)

    assert_kind_of VPNDetection::Error, client.lookup_batch(['203.0.114.50'])['203.0.114.50']
    got = client.lookup_batch(['203.0.114.51'], retries: 2)['203.0.114.51']
    assert_equal true, got.is_vpn
  ensure
    server&.stop
  end

  def test_a_keyless_client_presents_no_credential_at_all
    request = VPNDetection::Transport.new(VPNDetection::Transport::Config.new).lookup_request('1.1.1.1')

    # The generated Configuration would apply all three schemes at once, and an
    # empty `Authorization: Bearer ` is answered with a 401.
    refute request.options[:headers].key?('Authorization')
    refute request.options[:headers].key?('X-Api-Key')
    assert_empty request.options[:params]
  end

  def test_an_api_key_is_presented_as_a_bearer_token
    config = VPNDetection::Transport::Config.new(api_key: 'secret')
    request = VPNDetection::Transport.new(config).lookup_request('1.1.1.1')

    assert_equal 'Bearer secret', request.options[:headers]['Authorization']
    assert_match %r{\Avpndetection-ruby/}, request.options[:headers]['User-Agent']
  end

  def test_no_request_this_library_builds_follows_a_redirect
    request = VPNDetection::Transport.new(VPNDetection::Transport::Config.new).lookup_request('1.1.1.1')

    assert_equal false, request.options[:followlocation],
                 'the generated client always follows, which would download a whole dataset'
  end

  def test_the_batch_builds_the_same_lookup_url_as_the_generated_api
    transport = VPNDetection::Transport.new(VPNDetection::Transport::Config.new)
    capturing = Class.new(VPNDetection::Transport) do
      attr_reader :captured_path

      def call_api(_method, path, _opts = {})
        @captured_path = path
        [nil, nil, nil]
      end
    end.new(VPNDetection::Transport::Config.new)

    %w[45.83.91.1 2606:4700:4700::1111].each do |ip|
      VPNDetection::LookupApi.new(capturing).lookup_ip(ip)
      built = transport.lookup_request(ip).base_url.delete_prefix(VPNDetection::DEFAULT_BASE_URL)
      assert_equal capturing.captured_path, built, "#{ip}: the hand-built path drifted from the generated one"
    end
  end
end
