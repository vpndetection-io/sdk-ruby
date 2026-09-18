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
      if request.url == "#{BASE_URL}/batch"
        batch_response(routes, request.options[:body])
      else
        route = routes[address_of(request)]
        if route.nil?
          json_response(400, { 'error' => 'not a valid IP address' })
        else
          json_response(route[:status] || 200, route[:body], route[:headers] || {})
        end
      end
    end
    calls
  end

  # A POST /batch is answered the way the API answers one: every address the
  # table knows is a result if its route is a 200 and an entry error otherwise,
  # and an unknown address is the 400 the API gives a string that is not one.
  # One call however many addresses, which is what the request counts measure.
  def batch_response(routes, body)
    results = {}
    errors = {}
    JSON.parse(body.to_s).fetch('ips', []).each do |ip|
      route = routes[ip]
      if route.nil?
        errors[ip] = { 'status' => 400, 'error' => 'not a valid IP address' }
      elsif (route[:status] || 200) == 200
        results[ip] = route[:body]
      else
        errors[ip] = { 'status' => route[:status], 'error' => route[:body]['error'] }
      end
    end
    json_response(200, { 'results' => results, 'errors' => errors })
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
    @handler = handler || lambda do |path, body|
      if path == '/batch'
        [200, TestServer.batch_body(body)]
      else
        [200, JSON.generate({ 'ip' => path[1..], 'is_vpn' => false })]
      end
    end
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

  # The answer a batch gets from a server that has nothing to say about any
  # address: every address in the body, answered with `is_vpn`. A POST /batch
  # carries its addresses in the body rather than the path, so this is where
  # they are read.
  def self.batch_body(body, is_vpn: false)
    ips = JSON.parse(body.to_s).fetch('ips', [])
    JSON.generate({
      'results' => ips.to_h { |ip| [ip, { 'ip' => ip, 'is_vpn' => is_vpn }] },
      'errors' => {},
    })
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

    path, request_body = request
    status, body, headers, pace = in_flight(path) { @handler.call(path, request_body) }
    extra = (headers || {}).map { |name, value| "#{name}: #{value}\r\n" }.join
    connection.print(
      "HTTP/1.1 #{status} OK\r\nContent-Type: application/json\r\n#{extra}" \
      "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n",
    )
    write_body(connection, body, pace)
  ensure
    begin
      connection.close
    rescue IOError
      nil
    end
  end

  # Counts this request as in flight while it is being ANSWERED, ending before
  # the first response byte goes out. Held any longer the count RACES the hydra:
  # curl finishes on the last body byte and the next chunk leaves at once, so a
  # request whose thread had not yet booked itself out is seen alongside the new
  # one and `peak` reads one too high. Nothing is undercounted either - a client
  # cannot send its next request before reading the response this releases ahead
  # of. Pairing the two here also stops a connection that carried no request at
  # all from decrementing a count it never incremented.
  def in_flight(path)
    enter(path)
    sleep(@delay)
    yield
  ensure
    leave
  end

  # The headers are already out, so a stall here is one no bound that stops at
  # the headers can see. `stall:` sends half the body and then waits; `trickle:`
  # sends a byte per gap, so no single read ever waits long.
  def write_body(connection, body, pace)
    case pace
    in nil
      connection.print(body)
    in { stall: seconds }
      connection.print(body.byteslice(0, body.bytesize / 2))
      connection.flush
      sleep(seconds)
      connection.print(body.byteslice(body.bytesize / 2, body.bytesize))
    in { trickle: gap }
      body.each_char do |char|
        connection.print(char)
        connection.flush
        sleep(gap)
      end
    end
  rescue Errno::EPIPE, Errno::ECONNRESET
    nil
  end

  def read_request(connection)
    request_line = connection.gets
    return nil if request_line.nil?

    length = 0
    loop do
      header = connection.gets
      break if header.nil? || header.strip.empty?

      name, value = header.split(':', 2)
      length = value.to_i if name.casecmp?('content-length')
    end
    # A POST carries its body after the blank line, sized by Content-Length.
    body = length.positive? ? connection.read(length) : ''
    [request_line.split(' ')[1], body]
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
