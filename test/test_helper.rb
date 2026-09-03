# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'socket'
require 'typhoeus'

require 'vpndetection'

module TestHelper
  CORPUS = JSON.parse(File.read(File.expand_path('../testdata/testdata.json', __dir__))).freeze

  BASE_URL = VPNDetection::DEFAULT_BASE_URL

  # Answers lookups from a table and records every request, so "never touched
  # the network" is asserted rather than assumed. Any address the table does not
  # know gets the 400 the real API answers.
  def stub_lookups(routes)
    calls = []
    Typhoeus.stub(%r{\A#{Regexp.escape(BASE_URL)}/}).and_return do |request|
      calls << request.url
      route = routes[address_of(request)]
      if route.nil?
        json_response(400, { 'error' => 'not a valid IP address' })
      else
        json_response(route[:status] || 200, route[:body], route[:headers] || {})
      end
    end
    calls
  end

  def json_response(status, body, headers = {})
    Typhoeus::Response.new(
      code: status,
      body: body.is_a?(String) ? body : JSON.generate(body),
      headers: { 'Content-Type' => 'application/json' }.merge(headers),
    )
  end

  def address_of(request)
    CGI.unescape(URI.parse(request.url).path.delete_prefix('/'))
  end

  def corpus_batch(name)
    TestHelper::CORPUS['batch'].find { |c| c['name'] == name }
  end
end

# A real HTTP server on a real socket, which is the only way to observe how many
# requests a hydra genuinely has in flight at once. A stubbed response is
# answered before the next one is even queued, so it would measure a peak of one
# whatever the concurrency was set to.
class TestServer
  attr_reader :peak, :paths

  def initialize(delay: 0.05, &handler)
    @socket = TCPServer.new('127.0.0.1', 0)
    @delay = delay
    @handler = handler || ->(path) { [200, JSON.generate({ 'ip' => path[1..], 'is_vpn' => false })] }
    @lock = Mutex.new
    @in_flight = 0
    @peak = 0
    @paths = []
    @acceptor = Thread.new { accept_loop }
  end

  def base_url
    "http://127.0.0.1:#{@socket.addr[1]}"
  end

  def stop
    @socket.close
    @acceptor.kill
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
    path = read_request(connection)
    return if path.nil?

    enter(path)
    sleep(@delay)
    status, body, headers = @handler.call(path)
    extra = (headers || {}).map { |name, value| "#{name}: #{value}\r\n" }.join
    connection.print(
      "HTTP/1.1 #{status} OK\r\nContent-Type: application/json\r\n#{extra}" \
      "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}",
    )
  ensure
    leave
    begin
      connection.close
    rescue IOError
      nil
    end
  end

  def read_request(connection)
    request_line = connection.gets
    return nil if request_line.nil?

    loop do
      header = connection.gets
      break if header.nil? || header.strip.empty?
    end
    request_line.split(' ')[1]
  end

  def enter(path)
    @lock.synchronize do
      @paths << path
      @in_flight += 1
      @peak = [@peak, @in_flight].max
    end
  end

  def leave
    @lock.synchronize { @in_flight -= 1 }
  end
end
