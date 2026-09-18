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
    # Enough addresses for nine chunks of the batch endpoint's 1000, so a
    # concurrency of eight has something to bound: one request per chunk, and
    # only the chunks overlap.
    addresses = (0...8001).map { |n| "9.#{1 + (n / 65536)}.#{(n / 256) % 256}.#{n % 256}" }

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
    server = TestServer.new(delay: 0.0) do |path, body|
      attempts[path] += 1
      if attempts[path] < 3
        [500, '{"error":"lookup failed"}']
      else
        [200, TestServer.batch_body(body, is_vpn: true)]
      end
    end
    client = VPNDetection::Client.new(base_url: server.base_url, retries: 0, cache: false)

    assert_kind_of VPNDetection::Error, client.lookup_batch(['203.0.114.50'])['203.0.114.50']
    got = client.lookup_batch(['203.0.114.51'], retries: 2)['203.0.114.51']
    assert_equal true, got.is_vpn
  ensure
    server&.stop
  end

  # The per-call bound is set BELOW the client's against a server that stalls
  # past both, so a call that ignored it would wait out the client's bound
  # instead, and the elapsed time says which one fired.
  def test_a_per_call_timeout_below_the_clients_is_the_one_that_fires
    server = TestServer.new(delay: 8)
    client = VPNDetection::Client.new(base_url: server.base_url, timeout: 4, retries: 0, cache: false)
    calls = {
      lookup: -> { client.lookup('1.1.1.1', timeout: 0.3) },
      my_ip: -> { client.my_ip(timeout: 0.3) },
      my_entitlement: -> { client.my_entitlement(timeout: 0.3) },
      lookup_batch: -> { client.lookup_batch(['1.1.1.1'], timeout: 0.3)['1.1.1.1'] },
    }

    calls.each do |name, call|
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      error = begin
        call.call
      rescue VPNDetection::Error => e
        e
      end
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

      assert_kind_of VPNDetection::Error, error, name
      assert_equal :network, error.kind, name
      assert error.retryable?, "#{name}: a timeout is a transport failure, and worth retrying"
      assert_operator elapsed, :<, 2, "#{name}: the client's 4s bound fired rather than the per-call one"
    end
  ensure
    server&.stop
  end

  # No cap on what one call accepts: chunking to the endpoint's 1000 is the
  # client's job, so 2,500 addresses are three requests rather than an error.
  def test_a_batch_of_2500_addresses_is_three_requests_and_one_answer_each
    addresses = (0...2500).map { |n| "9.1.#{n / 256}.#{n % 256}" }
    lock = Mutex.new
    sizes = []
    server = TestServer.new(delay: 0) do |_path, body|
      lock.synchronize { sizes << JSON.parse(body)['ips'].length }
      [200, TestServer.batch_body(body)]
    end

    got = VPNDetection::Client.new(base_url: server.base_url, cache: false).lookup_batch(addresses)

    assert_equal ['/batch'] * 3, server.paths
    assert_equal [500, 1000, 1000], sizes.sort
    assert_equal addresses, got.keys
    addresses.each { |ip| assert_equal ip, got[ip].ip, "#{ip} should be answered for itself" }
  ensure
    server&.stop
  end

  # A hydra that may run nothing never finishes, so a limit below 1 is the
  # caller's mistake to hear about at once, not a batch that hangs.
  def test_a_batch_concurrency_below_one_is_refused_before_any_request
    calls = stub_lookups({})
    client = VPNDetection::Client.new

    [0, -1, 0.5].each do |limit|
      error = assert_raises(VPNDetection::Error) { client.lookup_batch(['9.9.9.9'], concurrency: limit) }
      assert_equal :bad_request, error.kind, "concurrency #{limit}"
      refute error.retryable?
    end
    error = assert_raises(VPNDetection::Error) do
      VPNDetection::Client.new(concurrency: 0).lookup_batch(['9.9.9.9'])
    end
    assert_equal :bad_request, error.kind, 'a client built with concurrency 0'
    assert_empty calls
  end

  def test_the_default_timeout_is_thirty_seconds_per_attempt
    transport = VPNDetection::Client.new.instance_variable_get(:@transport)

    assert_equal 30, transport.config.timeout
  end

  # The bound must cover the BODY: a limit that stops at the response head lets a
  # body stalled after its headers run for as long as the server likes.
  def test_a_body_stalled_after_its_headers_is_bounded
    assert_body_bounded(stall: 8)
  end

  # A byte every 20 ms never leaves one read waiting long, so only a bound on the
  # whole attempt ends it.
  def test_a_body_trickled_a_byte_at_a_time_is_bounded
    assert_body_bounded(trickle: 0.02)
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
      VPNDetection::LookupWireApi.new(capturing).lookup_ip(ip)
      built = transport.lookup_request(ip).base_url.delete_prefix(VPNDetection::DEFAULT_BASE_URL)
      assert_equal capturing.captured_path, built, "#{ip}: the hand-built path drifted from the generated one"
    end

    VPNDetection::LookupWireApi.new(capturing).lookup_batch(VPNDetection::BatchLookupRequest.new(ips: ['1.1.1.1']))
    built = transport.batch_request(['1.1.1.1']).base_url.delete_prefix(VPNDetection::DEFAULT_BASE_URL)
    assert_equal capturing.captured_path, built, 'the hand-built batch path drifted from the generated one'
  end
  ENTITLEMENT_BODY = {
    'org_id' => '85bb51e4-2eb6-4a31-8e4d-02ba8b98fe61',
    'apikey' => {
      'id' => '0ab424cc-7619-4dad-b027-afacdc2cedb0',
      'expires' => nil,
      'allowed_cidrs' => [],
    },
    'plan' => { 'key' => 'max', 'tier' => 'max' },
    'usage' => {
      'requests' => 580,
      'quota' => 5_000_000,
      'hard_limit' => nil,
      'window_start' => '2026-09-04T07:00:00Z',
      'window_end' => '2026-10-04T07:00:00Z',
    },
  }.freeze

  def test_my_ip_classifies_the_calling_address
    stub_lookups('myip' => { body: { 'ip' => '45.83.91.1', 'is_vpn' => true } })
    result = VPNDetection::Client.new.my_ip

    assert_equal '45.83.91.1', result.ip
    assert result.is_vpn
  end

  def test_my_ip_is_not_cached
    # The cache is keyed by address, and which address this is IS the question.
    calls = stub_lookups('myip' => { body: { 'ip' => '45.83.91.1', 'is_vpn' => true } })
    client = VPNDetection::Client.new
    client.my_ip
    client.my_ip

    assert_equal 2, calls.length
  end

  def test_my_entitlement_reports_the_plan_and_the_usage
    stub_lookups('api/v1/entitlement' => { body: ENTITLEMENT_BODY })
    ent = VPNDetection::Client.new.my_entitlement

    assert_equal 'max', ent.plan.key
    assert_equal 'max', ent.plan.tier
    assert_equal 580, ent.usage.requests
    assert_equal 5_000_000, ent.usage.quota
    # Null means NEVER stop, which is not the same as a limit of zero.
    assert_nil ent.usage.hard_limit
    assert_empty ent.apikey.allowed_cidrs
  end

  def test_my_entitlement_is_not_cached
    # The whole point is what has been spent.
    calls = stub_lookups('api/v1/entitlement' => { body: ENTITLEMENT_BODY })
    client = VPNDetection::Client.new
    client.my_entitlement
    client.my_entitlement

    assert_equal 2, calls.length
  end

  def test_my_entitlement_surfaces_an_unauthorized_key
    stub_lookups('api/v1/entitlement' => { status: 401, body: { 'error' => 'invalid API key' } })
    client = VPNDetection::Client.new(retries: 0)

    assert_raises(VPNDetection::Error) { client.my_entitlement }
  end

  private

  # Each call's per-call bound (0.3 s) fires first, then a call with no override
  # waits for the client's own (1 s), and the elapsed time says which one fired.
  def assert_body_bounded(pace)
    padded = "#{JSON.generate({ 'ip' => '1.1.1.1', 'is_vpn' => false })}#{' ' * 400}"
    server = TestServer.new(delay: 0) { |_path, _body| [200, padded, {}, pace] }
    client = VPNDetection::Client.new(base_url: server.base_url, timeout: 1, retries: 0, cache: false)
    per_call = {
      lookup: -> { client.lookup('1.1.1.1', timeout: 0.3) },
      lookup_batch: -> { client.lookup_batch(['1.1.1.1'], timeout: 0.3)['1.1.1.1'] },
      oauth_exchange: -> { client.oauth.exchange_device_code('cli', 'mo_dc_x', timeout: 0.3) },
      database_list: -> { client.database.list(timeout: 0.3) },
      database_metadata: -> { client.database.metadata('cdn_ip_v1', timeout: 0.3) },
      database_checksums: -> { client.database.checksums('cdn_ip_v1', 'mmdb', timeout: 0.3) },
      database_downloads: -> { client.database.downloads(limit: 5, timeout: 0.3) },
      # Minting a link is an ordinary JSON call, so it takes the bound; the
      # transfer that link is for is the one that must not.
      database_download_url: -> { client.database.download_url('cdn_ip_v1', 'mmdb', timeout: 0.3) },
    }
    client_bound = {
      my_entitlement: -> { client.my_entitlement },
      database_list: -> { client.database.list },
      database_downloads: -> { client.database.downloads(limit: 5) },
      oauth_metadata: -> { client.oauth.metadata },
    }

    per_call.each { |name, call| assert_times_out(name, call, 0.25..0.9) }
    client_bound.each { |name, call| assert_times_out(name, call, 0.9..2.5) }
  ensure
    server&.stop
  end

  def assert_times_out(name, call, window)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    error = begin
      call.call
    rescue VPNDetection::Error => e
      e
    end
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    assert_kind_of VPNDetection::Error, error, name
    assert_equal :network, error.kind, "#{name}: #{error.message}"
    assert error.retryable?, "#{name}: a timeout is a transport failure, and worth retrying"
    assert_includes window, elapsed, "#{name} settled after #{elapsed.round(2)}s"
  end
end
