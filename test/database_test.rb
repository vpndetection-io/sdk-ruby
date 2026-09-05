# frozen_string_literal: true

# The five licensed-dataset endpoints. The shapes here nest their payload one
# level down, so an unwrap at the wrong depth returns nothing against a healthy
# API; each test pins the depth.

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
                    'datasets' => [{
                      'base' => 'vpn_ip_extended', 'name' => 'VPN IP Extended',
                      'license_type' => 'standard', 'in_term' => true,
                      'standing' => 'licensed',
                      'versions' => [{
                        'id' => 'vpn_ip_extended_v1', 'version' => 1,
                        'formats' => [{ 'format' => 'csvgz', 'bytes' => 1024 }],
                        'sampleFormats' => ['csvgz'],
                      }],
                    }],
                  })
    datasets = @client.database.list

    assert_equal 1, datasets.length
    assert_equal 'vpn_ip_extended', datasets.first.base
    assert_equal 'licensed', datasets.first.standing
    assert_equal 'vpn_ip_extended_v1', datasets.first.versions.first.id
    assert_equal 1, datasets.first.versions.first.version
    assert_equal 'csvgz', datasets.first.versions.first.formats.first.format
    assert_equal ['csvgz'], datasets.first.versions.first.sample_formats
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
    server = TestServer.new(delay: 0.0) { |_path| [200, '{"datasets":[]}'] }
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
end
