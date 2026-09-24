# frozen_string_literal: true

# The five licensed-dataset endpoints. The shapes here nest their payload one
# level down, so an unwrap at the wrong depth returns nothing against a healthy
# API; each test pins the depth.

require 'tmpdir'

require_relative 'test_helper'

class DatabaseTest < Minitest::Test
  include TestHelper

  CHECKSUMS = {
    'md5' => 'd41d8cd98f00b204e9800998ecf8427e',
    'sha1' => 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    'sha256' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'sha512' => 'cf83e1357eefb8bd',
  }.freeze

  def setup
    Typhoeus::Config.block_connection = true
    @client = VPNDetection::Client.new(api_key: 'test-key', retries: 0)
  end

  def teardown
    Typhoeus::Config.block_connection = false
    Typhoeus::Expectation.clear
  end

  def stub_database(path, status, body, headers = {})
    calls = []
    Typhoeus.stub("#{BASE_URL}#{path}").and_return do |request|
      calls << request.url
      json_response(status, body, headers)
    end
    calls
  end

  # A license is held against the FAMILY, and the ids a download takes hang off
  # `versions`. Reading an id off the family is how list() -> download() was
  # broken in every SDK while the published schema disagreed with the service.
  def test_list_unwraps_the_families_and_their_versions
    stub_database('/api/v1/database/list', 200, {
                    'databases' => [{
                      'base' => 'vpn_ip_extended', 'name' => 'VPN IP Extended',
                      'summary' => 'extended rows', 'license_type' => 'standard',
                      'starts' => '2026-01-01T00:00:00.000Z', 'expires' => nil,
                      'renews_at' => nil, 'notice_due_at' => nil,
                      'in_term' => true, 'standing' => 'licensed',
                      'versions' => [{
                        'id' => 'vpn_ip_extended_v1', 'version' => 1,
                        'formats' => [{ 'format' => 'csvgz', 'bytes' => 1024 }],
                        'sample_formats' => ['csvgz'],
                      }],
                    }],
                  })
    databases = @client.database.list

    assert_equal 1, databases.length
    assert_equal 'vpn_ip_extended', databases.first.base
    assert_equal 'licensed', databases.first.standing
    assert_equal 'vpn_ip_extended_v1', databases.first.versions.first.id
    assert_equal 1, databases.first.versions.first.version
    assert_equal 'csvgz', databases.first.versions.first.formats.first.format
    assert_equal ['csvgz'], databases.first.versions.first.sample_formats
  end

  def test_metadata_returns_the_document_itself
    stub_database('/api/v1/database/metadata', 200, {
                    'id' => 'vpn_ip_extended_v1', 'updated' => '2026-09-02',
                    'entries' => 42, 'update_freq' => 'daily',
                    'schema' => { 'csvgz' => [{ 'name' => 'ip', 'type' => 'string' }] },
                  })
    metadata = @client.database.metadata('vpn_ip_extended_v1')

    assert_equal 'vpn_ip_extended_v1', metadata.id
    assert_equal 42, metadata.entries
    assert_equal 'ip', metadata.schema['csvgz'].first.name
  end

  def test_checksums_returns_the_whole_digest_set_from_one_level_down
    stub_database('/api/v1/database/checksum', 200, {
                    'id' => 'vpn_ip_extended_v1', 'format' => 'csvgz', 'checksums' => CHECKSUMS,
                  })
    checksums = @client.database.checksums('vpn_ip_extended_v1', 'csvgz')

    # Reading a top-level sha256 answers nil against a healthy API, which is
    # exactly what the Node SDK shipped in 1.0.x.
    assert_equal CHECKSUMS['sha256'], checksums.sha256
    assert_equal CHECKSUMS['md5'], checksums.md5
    assert_equal CHECKSUMS['sha1'], checksums.sha1
    assert_equal CHECKSUMS['sha512'], checksums.sha512
  end

  def test_downloads_unwraps_the_array_and_passes_a_limit
    calls = stub_database('/api/v1/database/downloads', 200, {
                            'downloads' => [{
                              'dataset_id' => 'vpn_ip_extended_v1', 'format' => 'csvgz',
                              'outcome' => 'ok', 'sample' => false, 'bytes' => 10,
                              'http_status' => 302, 'apikey_id' => 'mk_1234abcd',
                              'client_ip' => '203.0.113.7', 'user_agent' => 'vpndetection-ruby/1.0.0',
                              'created' => '2026-09-02T10:00:00Z',
                            }],
                          })
    downloads = @client.database.downloads(limit: 5)

    assert_equal 'ok', downloads.first.outcome
    assert_includes calls.first, 'limit=5'
  end

  def test_download_url_reads_the_location_off_the_302
    location = 'https://s3.example.test/vpn_ip_extended_v1.csv.gz?sig=abc'
    stub_database('/api/v1/database/download', 302, { 'rc' => '' }, { 'Location' => location })

    assert_equal location, @client.database.download_url('vpn_ip_extended_v1', 'csvgz')
  end

  def test_download_url_does_not_follow_the_redirect
    # The redirect points back at this same server, so a follow shows up as a
    # second request. Pointing it at an unresolvable host would not: curl still
    # reports the 302 and its Location after failing to chase it, so the library
    # would look correct while downloading the dataset against a real bucket.
    location = nil
    server = TestServer.new(delay: 0.0) do |path|
      if path.start_with?('/api/v1/database/download')
        [302, '', { 'Location' => location }]
      else
        [200, 'a whole dataset']
      end
    end
    location = "#{server.base_url}/vpn_ip_extended_v1.csv.gz"
    client = VPNDetection::Client.new(base_url: server.base_url, api_key: 'k', retries: 0)
    Typhoeus::Config.block_connection = false

    url = client.database.download_url('vpn_ip_extended_v1', 'csvgz')

    assert_equal location, url
    assert_equal 1, server.paths.length, 'following the redirect would download the dataset'
  ensure
    server&.stop
  end

  # The sibling brand's suite caught this and this one had no equivalent, so the
  # same leak sat here unnoticed: the generated client applies EVERY security
  # scheme the spec declares, and the spec declares `?apikey=` for curl users.
  def test_the_key_travels_as_a_bearer_header_and_never_in_the_query
    server = TestServer.new(delay: 0.0) { |_path| [200, '{"databases":[]}'] }
    client = VPNDetection::Client.new(base_url: server.base_url, api_key: 'k', retries: 0)
    Typhoeus::Config.block_connection = false

    client.database.list

    assert_equal 1, server.paths.length
    refute_includes server.paths.first, 'apikey'
    refute_includes server.paths.first, 'k='
  ensure
    server&.stop
  end

  def test_an_unknown_dataset_is_a_client_error_and_is_not_retried
    calls = stub_database('/api/v1/database/metadata', 404, { 'rc' => 'NOT_FOUND' })
    client = VPNDetection::Client.new(api_key: 'k', retries: 2)

    error = assert_raises(VPNDetection::Error) { client.database.metadata('nope') }
    assert_equal :bad_request, error.kind
    refute error.retryable?
    assert_equal 1, calls.length
  end

  def test_a_missing_scope_is_unauthorized
    stub_database('/api/v1/database/list', 401, { 'rc' => 'UNAUTHORIZED' })

    error = assert_raises(VPNDetection::Error) { @client.database.list }
    assert_equal :unauthorized, error.kind
    assert_equal 'UNAUTHORIZED', error.message
  end
  # Naming the format enum in the spec made openapi-generator stop emitting its
  # inline parameter check, so an unknown format silently became a network call
  # and a 400. The guard lives in the hand-written layer now; this is what stops
  # it going missing again.
  def test_an_unpublished_format_is_refused_before_any_request
    assert_raises(ArgumentError) { @client.database.checksums('vpn_ip_extended_v1', 'parquet') }
    assert_raises(ArgumentError) { @client.database.download_url('vpn_ip_extended_v1', 'parquet') }
  end

  # A transfer takes no per-call timeout and REFUSES one rather than accepting it
  # and quietly ignoring it: a dataset runs to gigabytes and minutes, so any
  # bound that suits a JSON call would abandon a healthy download, and a caller
  # who passed one would be told nothing. The option is simply not in the
  # signature, so Ruby refuses it for us - this is what stops it being added.
  def test_a_transfer_refuses_a_per_call_timeout
    path = File.join(Dir.tmpdir, 'vpndetection-timeout-refusal.mmdb')

    assert_raises(ArgumentError) { @client.database.download('cdn_ip_v1', 'mmdb', path, timeout: 1) }
    assert_raises(ArgumentError) { @client.database.download_bytes('cdn_ip_v1', 'mmdb', timeout: 1) }

    refute_path_exists path
  end

  # The other half of the rule above: every call that is NOT a transfer takes the
  # option. Without this, the refusal test would pass just as well on a surface
  # that had never been given a per-call timeout at all.
  def test_every_json_call_takes_a_per_call_timeout
    %i[list metadata checksums downloads download_url].each do |name|
      assert_includes @client.database.method(name).parameters, %i[key timeout],
                      "#{name} must take a per-call timeout"
    end
  end

  # Refused where it is set, on the client and per call. Accepted, a negative or
  # anything past 2147483 s ran with no bound at all, since libcurl refuses the
  # option and Ethon ignores the refusal, and NaN, Infinity, 2**63 or a string
  # failed every call with an error from Ruby, FFI or Ethon (measured on 5.4.1).
  def test_a_timeout_curl_cannot_hold_is_refused_where_it_is_set
    calls = stub_database('/api/v1/database/list', 200, { 'databases' => [] })
    [-1, -0.5, Float::NAN, Float::INFINITY, 2_147_484, 2**63, Complex(1, 0), '30', :x, true].each do |value|
      assert_raises(ArgumentError, "client #{value.inspect}") { VPNDetection::Client.new(timeout: value) }
      assert_raises(ArgumentError, "per call #{value.inspect}") { @client.database.list(timeout: value) }
    end
    assert_empty calls, 'no refused timeout reached the network'

    [0, 0.5, 30, VPNDetection::Transport::LONGEST_TIMEOUT].each do |value|
      client = VPNDetection::Client.new(api_key: 'test-key', retries: 0, timeout: value)
      assert_equal [], client.database.list, "client #{value}"
      assert_equal [], @client.database.list(timeout: value), "per call #{value}"
    end
  end

  def test_the_retry_schedule_and_the_longest_retry_after_honored
    throttle = ->(seconds) { VPNDetection::Error.new(:rate_limited, 'x', status: 429, retry_after_seconds: seconds) }
    delays = (1..4).map { |attempt| VPNDetection::Retries.delay_for(throttle.call(nil), attempt) }

    assert_equal [0.25, 0.5, 1.0, 2.0], delays, 'the backoff doubles from 250 ms'
    assert_equal 3.0, VPNDetection::Retries.delay_for(throttle.call(3.0), 4), 'a Retry-After is waited as given'
    assert_equal 0.0, VPNDetection::Retries.delay_for(throttle.call(0.0), 2), 'and 0 means now'
    assert_equal 2_147_483.647, VPNDetection::Retries.delay_for(throttle.call(2_147_483.647), 1), 'up to 2**31 - 1 ms'
    assert_equal 0.25, VPNDetection::Retries.delay_for(throttle.call(2_147_483.648), 1), 'and past it, the backoff'
  end

  # Honored, 2147484 held the call for 24.8 days, and 9223372036854775807 and
  # 1e400 raised a raw RangeError out of `sleep` (measured on 5.4.1).
  def test_a_retry_after_past_the_bound_is_waited_out_on_the_backoff
    %w[2147484 9223372036854775807 1e400].each do |value|
      Typhoeus.stub("#{BASE_URL}/api/v1/database/list").and_return(
        [json_response(429, { 'rc' => 'RATE_LIMITED' }, 'Retry-After' => value),
         json_response(200, { 'databases' => [] })],
      )
      worker = Thread.new { VPNDetection::Client.new(api_key: 'test-key', retries: 1).database.list }
      worker.report_on_exception = false

      assert worker.join(5), "Retry-After #{value}: the call waited on the header"
      assert_equal [], worker.value, "Retry-After #{value}: the retry succeeded"
    ensure
      worker&.kill
      Typhoeus::Expectation.clear
    end
  end
end
