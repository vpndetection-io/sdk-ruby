# frozen_string_literal: true

# The `oauth` accessor against the shared corpus. Everything runs over a real
# socket, so the method, path, headers and form are read where they ARRIVE: a
# Typhoeus stub answers before curl builds the request, and would prove nothing
# about what leaves the client.

require_relative 'test_helper'

class OauthTest < Minitest::Test
  include TestHelper

  OAUTH = TestHelper::CORPUS['oauth']
  CLIENT_ID = 'vpndetection-cli'
  # The corpus's metadata document still carries a member the published spec
  # dropped, so the generated model has no reader for it.
  NOT_IN_SPEC = %w[client_id_metadata_document_supported].freeze
  ERROR_CLASSES = {
    'oauth' => VPNDetection::OauthRequestError,
    'accessDenied' => VPNDetection::OauthAccessDeniedError,
    'expiredToken' => VPNDetection::OauthExpiredTokenError,
  }.freeze

  def setup
    Typhoeus::Config.block_connection = false
    Typhoeus::Expectation.clear
  end

  def teardown
    @origin&.stop
  end

  def test_each_operation_requests_its_own_method_and_path
    operations = [
      ['metadata', 'metadata', {}],
      ['deviceAuthorization', 'deviceAuthorization', { 'clientId' => CLIENT_ID }],
      ['token', 'exchangeDeviceCode', { 'clientId' => CLIENT_ID, 'deviceCode' => 'mo_dc_x' }],
      ['token', 'exchangeRefreshToken', { 'clientId' => CLIENT_ID, 'refreshToken' => 'mo_rt_x' }],
      ['revoke', 'revoke', { 'clientId' => CLIENT_ID, 'token' => 'mo_rt_x' }],
    ]
    operations.each do |endpoint, operation, args|
      api = keyless([success_for(endpoint)]).oauth

      assert_equal :ok, bounded { call(api, operation, args) }.first, operation
      assert_requested(endpoint, @origin.requests.last, operation)
    end
  end

  def test_every_form_leaves_encoded_exactly_as_the_corpus_says
    OAUTH['forms']['cases'].each do |c|
      api = keyless([success_for(c['endpoint'])]).oauth

      outcome = bounded { call(api, c['operation'], c['args']) }

      assert_equal :ok, outcome.first, "#{c['name']}: #{outcome.last.inspect}"
      seen = @origin.requests.last
      assert_requested(c['endpoint'], seen, c['name'])
      assert seen.headers.fetch('content-type', '').start_with?(OAUTH['forms']['contentType']), c['name']
      pairs = URI.decode_www_form(seen.body)
      assert_equal c['fields'], pairs.to_h, c['name']
      assert_equal pairs.length, pairs.to_h.length, "#{c['name']}: a field was sent twice"
    end
  end

  def test_every_corpus_response_decodes_with_absent_left_absent
    calls = {
      'metadata' => ->(api) { api.metadata },
      'deviceAuthorization' => ->(api) { api.device_authorization(CLIENT_ID) },
      'token' => ->(api) { api.exchange_device_code(CLIENT_ID, 'mo_dc_x') },
    }
    calls.each do |type, call|
      OAUTH['responses'][type].each do |c|
        api = keyless([c]).oauth

        kind, value = bounded { call.call(api) }

        assert_equal :ok, kind, "#{c['name']}: #{value.inspect}"
        c['expect']['present'].each do |member, expected|
          next if NOT_IN_SPEC.include?(member)

          assert_equal expected, value.public_send(member), "#{c['name']}: #{member}"
        end
        c['expect']['absent'].each do |member|
          assert_nil value.public_send(member), "#{c['name']}: #{member}"
        end
      end
    end
  end

  def test_revoke_reads_no_body
    OAUTH['responses']['revoke'].each do |c|
      api = keyless([c]).oauth

      kind, value = bounded { api.revoke(CLIENT_ID, 'mo_rt_x') }

      assert_equal :ok, kind, "#{c['name']}: #{value.inspect}"
      assert_nil value, c['name']
    end
  end

  def test_every_corpus_error_is_classified
    OAUTH['errors']['cases'].each do |c|
      api = keyless([c]).oauth

      kind, error = bounded { api.exchange_device_code(CLIENT_ID, 'mo_dc_x') }

      assert_equal :error, kind, c['name']
      expect = c['expect']
      assert_error_type(expect['type'], error, c['name'])
      assert_equal expect['status'], error.status, "#{c['name']}: status"
      assert_equal expect['kind'], error.kind.to_s, "#{c['name']}: kind"
      assert_equal expect['retryable'], error.retryable?, "#{c['name']}: retryable"
      next if expect['type'] == 'client'

      assert_equal expect['errorCode'], error.error_code, "#{c['name']}: error_code"
      assert_value expect['errorDescription'], error.error_description, "#{c['name']}: error_description"
      assert_equal expect['message'], error.message, "#{c['name']}: message"
    end
  end

  # The request count is asserted BEFORE the outcome: an extra retry would
  # otherwise pick up the origin's fallback 503 and fail on the error's type,
  # which is the wrong reason.
  def test_only_the_idempotent_operations_retry
    OAUTH['retries']['cases'].each do |c|
      @origin&.stop
      @origin = OauthOrigin.new(c['responses'])
      api = VPNDetection::Client.new(base_url: @origin.base_url, timeout: 2, cache: false).oauth

      kind, value = bounded { call(api, c['operation'], c['args']) }

      assert_equal c['expect']['requests'], @origin.requests.length, "#{c['name']}: requests"
      case c['expect']['outcome']
      when 'ok'
        assert_equal :ok, kind, "#{c['name']}: #{value.inspect}"
      when 'client'
        assert_error_type('client', value, c['name'])
        assert_equal c['expect']['kind'], value.kind.to_s, c['name']
      else
        assert_error_type(c['expect']['outcome'], value, c['name'])
        assert_equal c['expect']['errorCode'], value.error_code, c['name']
      end
    end
  end

  def test_poll_device_token_follows_every_corpus_case
    OAUTH['poll']['cases'].each do |c|
      api = keyless(c['responses']).oauth
      clock = FakeClock.new.install(api)
      device = VPNDetection::DeviceAuthorization.build_from_hash(c['device'])

      outcome = bounded { api.poll_device_token(c['clientId'], device) }

      seen = @origin.requests
      assert_equal c['expect']['requests'], seen.length, "#{c['name']}: requests"
      seen.each { |request| assert_polled(request, c) }
      assert_equal c['expect']['waits'], clock.waits, "#{c['name']}: waits"
      assert_poll_outcome(c, outcome)
    end
  end

  def test_no_oauth_request_carries_the_api_key
    rule = OAUTH['noCredential']
    token = success_for('token')
    @origin = OauthOrigin.new([success_for('metadata'), success_for('deviceAuthorization'), token, token,
                               success_for('revoke'), token])
    client = VPNDetection::Client.new(api_key: rule['apiKey'], base_url: @origin.base_url, timeout: 2,
                                      cache: false)
    api = client.oauth
    FakeClock.new.install(api)

    outcome, printed = with_deprecations_shown do
      bounded do
        api.metadata
        device = api.device_authorization(CLIENT_ID, scope: 'account.read')
        api.exchange_device_code(CLIENT_ID, 'mo_dc_x')
        api.exchange_refresh_token(CLIENT_ID, 'mo_rt_x')
        api.revoke(CLIENT_ID, 'mo_rt_x')
        api.poll_device_token(CLIENT_ID, device)
      end
    end

    assert_equal :ok, outcome.first, outcome.last.inspect
    refute_match(/deprecated/, printed, 'the accessor went through a deprecated class')
    seen = @origin.requests
    assert_equal 6, seen.length
    seen.each do |request|
      rule['forbiddenHeaders'].each do |name|
        refute request.headers.key?(name), "#{request.path} carried #{name}"
      end
      query = URI.decode_www_form(URI.parse(request.target).query.to_s).map(&:first)
      rule['forbiddenQuery'].each { |name| refute_includes query, name, request.path }
      leaked = [request.target, request.body, *request.headers.values].any? { |v| v.include?(rule['apiKey']) }
      refute leaked, "the key left the client on #{request.path}"
    end
  end

  def test_a_2xx_that_is_not_its_type_is_an_ordinary_server_error
    answers = [
      { 'status' => 200, 'body' => { 'token_type' => 'Bearer', 'expires_in' => 3600 } },
      { 'status' => 200,
        'body' => { 'access_token' => 'mo_at_x', 'token_type' => 'Bearer', 'expires_in' => '3600' } },
      { 'status' => 200, 'rawBody' => 'this is not JSON' },
    ]
    answers.each do |answer|
      api = keyless([answer]).oauth

      kind, error = bounded { api.exchange_device_code(CLIENT_ID, 'mo_dc_x') }

      assert_equal 1, @origin.requests.length, answer.inspect
      assert_equal :error, kind, answer.inspect
      assert_instance_of VPNDetection::Error, error, answer.inspect
      assert_equal :server_error, error.kind, answer.inspect
      assert_equal 200, error.status, answer.inspect
    end
  end

  # Against a server that stalls past both bounds, each method's own 0.3 s fires
  # rather than the client's 4 s. The poll's bounds its exchange.
  def test_every_oauth_method_takes_a_per_call_timeout
    server = TestServer.new(delay: 8)
    api = VPNDetection::Client.new(base_url: server.base_url, timeout: 4, retries: 0, cache: false).oauth
    FakeClock.new.install(api)
    device = VPNDetection::DeviceAuthorization.build_from_hash(OAUTH['poll']['cases'].first['device'])
    calls = {
      metadata: -> { api.metadata(timeout: 0.3) },
      device_authorization: -> { api.device_authorization(CLIENT_ID, timeout: 0.3) },
      exchange_device_code: -> { api.exchange_device_code(CLIENT_ID, 'mo_dc_x', timeout: 0.3) },
      exchange_refresh_token: -> { api.exchange_refresh_token(CLIENT_ID, 'mo_rt_x', timeout: 0.3) },
      revoke: -> { api.revoke(CLIENT_ID, 'mo_rt_x', timeout: 0.3) },
      poll_device_token: -> { api.poll_device_token(CLIENT_ID, device, timeout: 0.3) },
    }

    calls.each do |name, call|
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      kind, error = bounded { call.call }
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

      assert_equal :error, kind, name
      assert_equal :network, error.kind, "#{name}: #{error.message}"
      assert_operator elapsed, :<, 2, "#{name}: the client's 4s bound fired rather than the per-call one"
    end
  ensure
    server&.stop
  end

  def test_the_generated_authorization_class_is_deprecated
    _api, printed = with_deprecations_shown { VPNDetection::AuthorizationWireApi.new }

    assert_match(/AuthorizationWireApi is deprecated/, printed)
  end

  private

  def keyless(responses)
    @origin&.stop
    @origin = OauthOrigin.new(responses)
    VPNDetection::Client.new(base_url: @origin.base_url, timeout: 2, cache: false)
  end

  def call(api, operation, args)
    case operation
    when 'metadata' then api.metadata
    when 'deviceAuthorization'
      api.device_authorization(args['clientId'], scope: args['scope'], resource: args['resource'])
    when 'exchangeDeviceCode' then api.exchange_device_code(args['clientId'], args['deviceCode'])
    when 'exchangeRefreshToken' then api.exchange_refresh_token(args['clientId'], args['refreshToken'])
    when 'revoke' then api.revoke(args['clientId'], args['token'])
    else raise ArgumentError, "the corpus names an operation this suite does not know: #{operation}"
    end
  end

  def success_for(endpoint)
    OAUTH['responses'].fetch(endpoint).first
  end

  # Runs the call on a thread of its own and fails the test from OUTSIDE when it
  # has not settled: the code under test rescues errors, so a bound that raises
  # inside it bounds nothing.
  def bounded(seconds = 15)
    outcome = nil
    worker = Thread.new do
      outcome = [:ok, yield]
    rescue StandardError => e
      outcome = [:error, e]
    end
    worker.report_on_exception = false
    return outcome if worker.join(seconds)

    worker.kill
    flunk "still running after #{seconds}s, which is a loop that never ends"
  end

  # What the block returned, and what it printed with deprecation warnings on.
  def with_deprecations_shown
    was = Warning[:deprecated]
    Warning[:deprecated] = true
    result = nil
    _out, err = capture_io { result = yield }
    [result, err]
  ensure
    Warning[:deprecated] = was
  end

  def assert_requested(endpoint, seen, name)
    expected = OAUTH['endpoints'].fetch(endpoint)
    assert_equal [expected['method'], expected['path']], [seen.method, seen.path], name
  end

  def assert_polled(request, c)
    assert_requested('token', request, c['name'])
    fields = { 'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
               'device_code' => c['device']['device_code'], 'client_id' => c['clientId'] }
    assert_equal fields, URI.decode_www_form(request.body).to_h, "#{c['name']}: a poll is the device exchange"
  end

  def assert_poll_outcome(c, outcome)
    expect = c['expect']
    kind, value = outcome
    if expect['outcome'] == 'token'
      assert_equal :ok, kind, "#{c['name']}: #{value.inspect}"
      expect.fetch('token', {}).each { |member, v| assert_equal v, value.public_send(member), c['name'] }
      return
    end

    assert_equal :error, kind, "#{c['name']}: answered #{value.inspect}"
    assert_error_type(expect['outcome'], value, c['name'])
    assert_value expect['status'], value.status, "#{c['name']}: status" if expect.key?('status')
    assert_equal expect['errorCode'], value.error_code, c['name'] if expect.key?('errorCode')
    assert_equal expect['kind'], value.kind.to_s, c['name'] if expect.key?('kind')
    assert_equal expect['retryable'], value.retryable?, c['name'] if expect.key?('retryable')
  end

  def assert_error_type(type, error, name)
    assert_kind_of VPNDetection::Error, error, name
    if type == 'client'
      refute_kind_of VPNDetection::OauthRequestError, error, "#{name}: an ordinary failure is not a refusal"
    else
      assert_instance_of ERROR_CLASSES.fetch(type), error, name
    end
  end

  # `assert_equal nil, x` is deprecated in minitest, and absent is the point.
  def assert_value(expected, actual, message)
    expected.nil? ? assert_nil(actual, message) : assert_equal(expected, actual, message)
  end
end

# Replaces BOTH the poll's wait and its clock, so the waits are asserted exactly
# and cost nothing. Past CAP waits it never returns, which parks a runaway poll
# where the test's own bound can end it.
class FakeClock
  CAP = 30

  attr_reader :waits

  def initialize
    @now = 0.0
    @waits = []
  end

  def install(api)
    api.instance_variable_set(:@wait, method(:wait))
    api.instance_variable_set(:@now, method(:now))
    self
  end

  def now
    @now
  end

  def wait(seconds)
    @waits << seconds
    sleep if @waits.length > CAP
    @now += seconds
  end
end

# An authorization server on a real socket, answering a script of responses in
# order and recording each request as it arrived. Past the script it answers
# 503; past CAP requests it answers nothing at all, so a loop in the client
# parks in a request rather than spinning.
class OauthOrigin
  CAP = 40

  Seen = Struct.new(:method, :target, :path, :headers, :body, keyword_init: true)

  def initialize(responses)
    @responses = responses.dup
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

  def requests
    @lock.synchronize { @seen.dup }
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
    request = read_request(connection)
    return if request.nil?

    response = @lock.synchronize do
      @seen << request
      @seen.length > CAP ? nil : @responses.shift || { 'status' => 503, 'rawBody' => '' }
    end
    sleep if response.nil?

    body = response.key?('rawBody') ? response['rawBody'] : JSON.generate(response['body'])
    connection.print("HTTP/1.1 #{response['status']} X\r\nContent-Type: application/json\r\n" \
                     "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
  rescue Errno::EPIPE, Errno::ECONNRESET
    nil
  ensure
    connection.close unless connection.closed?
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
    length = headers['content-length'].to_i
    body = length.positive? ? connection.read(length) : String.new
    method, target = request_line.split(' ')
    Seen.new(method: method, target: target, path: target.split('?').first, headers: headers,
             body: body.force_encoding(Encoding::UTF_8))
  end
end
