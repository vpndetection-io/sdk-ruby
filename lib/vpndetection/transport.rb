# frozen_string_literal: true

require 'cgi'
require 'json'
require 'uri'

module VPNDetection
  # The generated wire client, with the three things it gets wrong for this API
  # corrected in one place.
  class Transport < ApiClient
    # The same path template the generated LookupWireApi holds. Both are asserted
    # against each other in the test suite, because the batch builds its own
    # requests to queue them on a hydra and cannot go through the generated
    # method, which runs each request as it builds it.
    LOOKUP_PATH = '/{ip}'
    MYIP_PATH = '/myip'
    ENTITLEMENT_PATH = '/api/v1/entitlement'
    BATCH_PATH = '/batch'

    # The generated Configuration applies EVERY security scheme the spec lists,
    # so a keyless client would send `Authorization: Bearer `, an empty
    # `X-Api-Key` and an empty `apikey` query parameter. The API answers 401 to
    # the first of those, which is not what a keyless caller asked for.
    class Config < Configuration
      def initialize(api_key: nil, base_url: DEFAULT_BASE_URL, timeout: DEFAULT_TIMEOUT)
        super()
        uri = URI.parse(base_url)
        self.scheme = uri.scheme
        self.host = uri.port == uri.default_port ? uri.host : "#{uri.host}:#{uri.port}"
        self.base_path = uri.path
        self.access_token = api_key
        self.timeout = timeout
      end

      def auth_settings
        return {} if access_token.nil? || access_token.to_s.empty?

        {
          'bearerAuth' => {
            type: 'bearer', in: 'header', key: 'Authorization',
            value: "Bearer #{access_token}"
          }
        }
      end
    end

    def initialize(config = Config.new)
      super
      @default_headers['User-Agent'] = "vpndetection-ruby/#{VERSION}"
    end

    # `follow_location = opts[:follow_location] || true` in the generated client
    # is true for every value it can be given, so the database download's 302
    # would be chased and a multi-gigabyte dataset read into memory. Nothing
    # this API serves is meant to be followed.
    #
    # `opts[:timeout]` is a per-call override of the configured bound, which the
    # generated client would otherwise apply to every request it builds.
    def build_request(http_method, path, opts = {})
      request = super
      request.options[:followlocation] = false
      request.options[:timeout] = opts[:timeout] unless opts[:timeout].nil?
      request
    end

    # A GET for the presigned link the download endpoint hands out.
    #
    # Built here rather than through {#build_request} so it carries NO
    # credential: the presigned URL authorizes itself, and forwarding the API key
    # would hand it to a host with no business holding it. Redirects ARE followed,
    # unlike every other request this client makes, because this one IS the far
    # side of a redirect; the guard exists to stop the API's own 302 pulling a
    # dataset into memory, not to stop object storage from moving a bucket.
    #
    # The whole-request timeout is dropped and only the connect phase is bounded.
    # Ten seconds is a sane ceiling on a lookup and the wrong one on 1.79 GB.
    def storage_request(url)
      options = {
        method: :get,
        headers: { 'User-Agent' => @default_headers['User-Agent'] },
        followlocation: true,
        maxredirs: 5,
        connecttimeout: @config.timeout,
        ssl_verifypeer: @config.verify_ssl,
        ssl_verifyhost: @config.verify_ssl_host ? 2 : 0,
      }
      options[:cainfo] = @config.ssl_ca_cert if @config.ssl_ca_cert
      Typhoeus::Request.new(url, options)
    end

    def lookup_request(ip, timeout: nil)
      build_request(
        :GET, LOOKUP_PATH.sub('{ip}', CGI.escape(ip.to_s)),
        header_params: { 'Accept' => 'application/json' },
        auth_names: %w[bearerAuth apiKeyHeader apiKeyQuery],
        timeout: timeout,
      )
    end

    def myip_request(timeout: nil)
      build_request(
        :GET, MYIP_PATH,
        header_params: { 'Accept' => 'application/json' },
        auth_names: %w[bearerAuth apiKeyHeader apiKeyQuery],
        timeout: timeout,
      )
    end

    def entitlement_request(timeout: nil)
      build_request(
        :GET, ENTITLEMENT_PATH,
        header_params: { 'Accept' => 'application/json' },
        auth_names: %w[bearerAuth apiKeyHeader apiKeyQuery],
        timeout: timeout,
      )
    end

    # The one request with a body: the batch.
    def batch_request(ips, timeout: nil)
      build_request(
        :POST, BATCH_PATH,
        header_params: { 'Accept' => 'application/json', 'Content-Type' => 'application/json' },
        body: { ips: ips },
        auth_names: %w[bearerAuth apiKeyHeader apiKeyQuery],
        timeout: timeout,
      )
    end

    def self.entitlement_result(response)
      raise Error.from_transport(response) if transport_failure?(response)
      raise Error.from_status(response.code, response.headers, response.body) unless response.success?

      Entitlement.build_from_hash(parse_object(response))
    end

    def self.lookup_result(response)
      raise Error.from_transport(response) if transport_failure?(response)
      raise Error.from_status(response.code, response.headers, response.body) unless response.success?

      Result.new(parse_object(response))
    end

    # The two maps of a batch answer, each present even when empty.
    def self.batch_body(response)
      raise Error.from_transport(response) if transport_failure?(response)
      raise Error.from_status(response.code, response.headers, response.body) unless response.success?

      body = parse_object(response)
      {
        'results' => body['results'].is_a?(Hash) ? body['results'] : {},
        'errors' => body['errors'].is_a?(Hash) ? body['errors'] : {},
      }
    end

    def self.transport_failure?(response)
      response.timed_out? || response.code.to_i.zero?
    end

    def self.parse_object(response)
      body = JSON.parse(response.body.to_s)
      return body if body.is_a?(Hash)

      raise Error.new(:server_error, 'the API answered with something other than an object',
                      status: response.code)
    rescue JSON::ParserError => e
      raise Error.new(:server_error, "could not parse the response body: #{e.message}",
                      status: response.code)
    end

    private_class_method :transport_failure?, :parse_object
  end
end
