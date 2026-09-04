# frozen_string_literal: true

# The dataset transfer, exercised against a real HTTP origin rather than the
# stub. These methods exist to answer what curl does with a 302 and with a body
# too large to hold, and a stubbed response exercises neither: Typhoeus answers a
# stub without ever building an easy handle, so the streaming callbacks, the
# redirect guard and the headers the far side saw all go untested.

require 'digest'
require 'fileutils'
require 'tmpdir'

require_relative 'test_helper'

class DownloadTest < Minitest::Test
  include TestHelper

  API_KEY = 'test-key-6f2a'
  BLOB = 'a whole dataset, gzipped in real life'
  MIB = 1024 * 1024

  def setup
    @dir = Dir.mktmpdir('vpndetection-download-')
  end

  def teardown
    @origin&.stop
    FileUtils.remove_entry(@dir)
  end

  def test_download_follows_the_redirect_and_writes_the_file
    client = origin_client
    path = File.join(@dir, 'cdn_ip_v1.csv.gz')

    written = client.database.download('cdn_ip_v1', 'csvgz', path)

    assert_equal BLOB.bytesize, written
    assert_equal BLOB, File.binread(path)
    refute_path_exists "#{path}.part", 'the .part file outlived a successful transfer'
    assert_equal ['/api/v1/database/download', '/blob'], @origin.paths
  end

  def test_download_bytes_agrees_with_the_streamed_copy
    client = origin_client
    path = File.join(@dir, 'cdn_ip_v1.csv.gz')
    client.database.download('cdn_ip_v1', 'csvgz', path)

    bytes = client.database.download_bytes('cdn_ip_v1', 'csvgz')

    assert_equal Encoding::BINARY, bytes.encoding
    assert_equal File.binread(path), bytes
    assert_equal Digest::SHA256.hexdigest(File.binread(path)), Digest::SHA256.hexdigest(bytes)
  end

  # The key authorizes the API call that mints the link. The link is presigned
  # and authorizes itself, so forwarding the key on would hand a credential to a
  # host that has no business seeing it.
  def test_the_api_key_reaches_the_api_and_never_object_storage
    client = origin_client

    client.database.download_bytes('cdn_ip_v1', 'csvgz')

    minted = @origin.request('/api/v1/database/download')
    assert_equal "Bearer #{API_KEY}", minted[:headers]['authorization']

    fetched = @origin.request('/blob')
    refute_includes fetched[:target], API_KEY, 'the key was put in the object storage URL'
    fetched[:headers].each do |name, value|
      refute_includes value, API_KEY, "the key was sent to object storage as #{name}"
    end
  end

  # The assertion that matters most: a body far larger than any sane buffer has
  # to move through the process without ever being resident.
  #
  # Half the payload, not the eighth the compiled SDKs can hold to. Streaming in
  # Ruby is not free of garbage: curl hands each 16 KB chunk over as a fresh
  # String, and absorbing that allocation rate grows the GC arena sub-linearly.
  # Measured in a fresh process at 64/256/512 MiB, peak RSS grows 43/69/99 MiB
  # streamed and 99/327/603 MiB buffered, so half the body separates the two
  # with better than a factor of two either side.
  def test_a_large_body_is_streamed_not_buffered
    skip 'peak RSS is only readable through /proc' if peak_rss.nil?

    size = 512 * MIB
    client = origin_client(blob_bytes: size)
    before = peak_rss
    written = client.database.download('cdn_ip_v1', 'csvgz', File.join(@dir, 'big'))
    grew = peak_rss - before

    assert_equal size, written
    # Peak resident, not the live heap: an implementation that buffers frees the
    # buffer at the end of the call but cannot hide having held it.
    assert_operator grew, :<=, size / 2,
                    "peak RSS grew #{grew / MIB} MiB for a #{size / MIB} MiB body, so it was held"
  end

  # Nothing bounds the size of an object storage error page, so a refusal is
  # classified on the status with the body left unread. The origin promises a
  # page far larger than any socket buffer; the client hanging up before it
  # arrives is what shows the page was never taken.
  def test_object_storage_refusing_the_link_is_typed_with_its_page_left_unread
    page = 64 * MIB
    client = origin_client(blob_status: 403, blob_bytes: page)

    error = assert_raises(VPNDetection::Error) { client.database.download_bytes('cdn_ip_v1', 'csvgz') }

    assert_equal :forbidden, error.kind
    assert_equal 403, error.status
    refute error.retryable?
    assert_includes error.message, 'object storage refused the download link'
    assert_operator @origin.request('/blob')[:sent], :<, page,
                    'the whole refusal page was read before it was classified'
  end

  # A truncated file that looks complete is worse than no file: the next run
  # reads it as a whole dataset. The bytes land beside the destination and the
  # name only appears on success.
  def test_a_transfer_that_dies_part_way_leaves_nothing_at_the_destination
    client = origin_client(blob_bytes: 4 * MIB, die_after: MIB)
    path = File.join(@dir, 'cdn_ip_v1.csv.gz')

    error = assert_raises(VPNDetection::Error) { client.database.download('cdn_ip_v1', 'csvgz', path) }

    assert_equal :network, error.kind
    refute_path_exists path, 'a short file was left where a whole dataset should be'
    refute_path_exists "#{path}.part", 'the partial file survived a failed transfer'
  end

  def test_a_truncated_transfer_fails_for_download_bytes_too
    client = origin_client(blob_bytes: 4 * MIB, die_after: MIB)

    error = assert_raises(VPNDetection::Error) { client.database.download_bytes('cdn_ip_v1', 'csvgz') }

    assert_equal :network, error.kind
  end

  # The half of the .part guard a cleanup step cannot fake: a destination opened
  # directly is truncated before the first byte arrives, so yesterday's good copy
  # is gone whether or not the refresh then succeeds.
  def test_a_failed_refresh_leaves_the_previous_copy_intact
    client = origin_client(blob_bytes: 4 * MIB, die_after: MIB)
    path = File.join(@dir, 'cdn_ip_v1.csv.gz')
    File.binwrite(path, 'yesterday')

    assert_raises(VPNDetection::Error) { client.database.download('cdn_ip_v1', 'csvgz', path) }

    assert_path_exists path, 'the failed refresh took yesterdays copy with it'
    assert_equal 'yesterday', File.binread(path)
  end

  # An unlicensed dataset is refused by the API, before any link is minted. It is
  # a client error, so the retry schedule must not touch it.
  def test_an_unlicensed_dataset_is_forbidden_and_asked_for_exactly_once
    client = origin_client(mint_status: 403, retries: 3)
    path = File.join(@dir, 'cdn_ip_v1.csv.gz')

    error = assert_raises(VPNDetection::Error) { client.database.download('cdn_ip_v1', 'csvgz', path) }

    assert_equal :forbidden, error.kind
    assert_equal 403, error.status
    refute error.retryable?
    assert_equal 'NOT_LICENSED', error.message
    assert_equal ['/api/v1/database/download'], @origin.paths
    refute_path_exists "#{path}.part", 'a refusal left a partial file behind'
  end

  def test_download_bytes_refuses_an_unlicensed_dataset_the_same_way
    client = origin_client(mint_status: 403, retries: 3)

    error = assert_raises(VPNDetection::Error) { client.database.download_bytes('cdn_ip_v1', 'csvgz') }

    assert_equal :forbidden, error.kind
    assert_equal 'NOT_LICENSED', error.message
    assert_equal ['/api/v1/database/download'], @origin.paths
  end

  private

  def origin_client(retries: 0, **options)
    @origin = Origin.new(body: BLOB, **options)
    Typhoeus::Config.block_connection = false
    VPNDetection::Client.new(base_url: @origin.base_url, api_key: API_KEY, retries: retries)
  end

  # VmHWM is the highest resident set the process has ever reached, so a buffer
  # that was allocated and freed still shows. Linux only, which is where CI runs.
  def peak_rss
    File.read('/proc/self/status')[/^VmHWM:\s+(\d+) kB/, 1].to_i * 1024
  rescue Errno::ENOENT
    nil
  end
end

# Serves the API's 302 and the object storage it points at, on one origin, and
# records every request so a test can assert what did NOT happen.
class Origin
  FILLER = ('x' * (1024 * 1024)).freeze

  def initialize(body:, blob_bytes: nil, blob_status: 200, mint_status: 302, die_after: nil)
    @body = body
    @blob_bytes = blob_bytes
    @blob_status = blob_status
    @mint_status = mint_status
    @die_after = die_after
    @socket = TCPServer.new('127.0.0.1', 0)
    @lock = Mutex.new
    @seen = []
    @acceptor = Thread.new { accept_loop }
  end

  def base_url
    "http://127.0.0.1:#{@socket.addr[1]}"
  end

  def stop
    @socket.close
    @acceptor.kill
  end

  def paths
    @lock.synchronize { @seen.map { |r| r[:path] } }
  end

  def request(path)
    @lock.synchronize { @seen.find { |r| r[:path] == path } } ||
      raise("the origin was never asked for #{path}, it saw #{paths.inspect}")
  end

  private

  def accept_loop
    loop do
      connection = @socket.accept
      Thread.new(connection) { |c| serve(c) }
    end
  rescue IOError, Errno::EBADF
    nil
  end

  def serve(connection)
    record = read_request(connection)
    return if record.nil?

    @lock.synchronize { @seen << record }
    record[:path] == '/blob' ? serve_blob(connection, record) : mint(connection)
  ensure
    begin
      connection.close
    rescue IOError
      nil
    end
  end

  # Absolute, as the real 302 to object storage is: a presigned URL is on another
  # host entirely, so nothing here may lean on a relative one.
  def mint(connection)
    return head(connection, 302, 0, 'Location' => "#{base_url}/blob") if @mint_status == 302

    body = JSON.generate({ 'rc' => 'NOT_LICENSED' })
    head(connection, @mint_status, body.bytesize, 'Content-Type' => 'application/json')
    connection.write(body)
  end

  # Promises `declared` bytes and stops after `@die_after` of them, so a transfer
  # can be made to die with the destination already part written. A client that
  # hangs up mid-body is the point of several of these tests, so a broken pipe is
  # an outcome rather than an error, and what got out before it is what the test
  # reads back.
  def serve_blob(connection, record)
    declared = @blob_bytes || @body.bytesize
    stop_at = @die_after || declared
    head(connection, @blob_status, declared)
    sent = 0
    begin
      if @blob_bytes.nil?
        sent = connection.write(@body)
      else
        while sent < stop_at
          size = [FILLER.bytesize, stop_at - sent].min
          connection.write(size == FILLER.bytesize ? FILLER : FILLER[0, size])
          sent += size
        end
      end
    rescue Errno::EPIPE, Errno::ECONNRESET
      nil
    end
    record[:sent] = sent
  end

  def head(connection, status, declared, headers = {})
    extra = headers.map { |name, value| "#{name}: #{value}\r\n" }.join
    connection.print(
      "HTTP/1.1 #{status} X\r\n#{extra}Content-Length: #{declared}\r\nConnection: close\r\n\r\n",
    )
  end

  def read_request(connection)
    request_line = connection.gets
    return nil if request_line.nil?

    headers = {}
    loop do
      line = connection.gets
      break if line.nil? || line.strip.empty?

      name, _, value = line.partition(':')
      headers[name.strip.downcase] = value.strip
    end
    target = request_line.split(' ')[1]
    { target: target, path: target.split('?').first, headers: headers, sent: 0 }
  end
end
