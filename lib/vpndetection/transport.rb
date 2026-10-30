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

    # The longest `timeout` curl holds, in seconds: 2**31 - 1 ms, about 24.8 days.
    # libcurl refuses a longer one, and any negative, and Ethon ignores the
    # refusal, so the call would run with no bound at all.
    LONGEST_TIMEOUT = 2_147_483.647

    # `timeout`, once it is a bound curl can hold: seconds, 0 for none. Refused
    # where it is set, because nothing downstream refuses it: a negative ran with
    # no bound, and NaN, Infinity, a number past curl's ceiling or a string failed
    # every call with an error from Ruby, FFI or Ethon that names none of this.
    # NaN fails both comparisons, and an infinity one of them.
    def self.checked_timeout(timeout)
      return timeout if timeout.is_a?(Numeric) && timeout.real? && timeout >= 0 && timeout <= LONGEST_TIMEOUT

      raise ArgumentError,
            "timeout must be a number of seconds from 0 (no bound) to #{LONGEST_TIMEOUT}, not #{timeout.inspect}"
    end

    # The key as sent: trimmed, and nil when nothing is left. Through 5.10.1 a key
    # of blanks went out as `Authorization: Bearer` and a padded one padded, and
    # curl passed a control character on, so a key ending in a CR LF and a line
    # of its own wrote that line onto the wire as a header. Refused where it is
    # set, without the key in the message, since the key is a secret.
    def self.checked_key(api_key)
      return nil if api_key.nil?

      key = api_key.to_s.strip
      raise ArgumentError, 'api_key must not contain a control character' if key.match?(/[[:cntrl:]]/)

      key.empty? ? nil : key
    end

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
        self.access_token = Transport.checked_key(api_key)
        self.timeout = timeout.nil? ? nil : Transport.checked_timeout(timeout)
      end

      def auth_settings
        token = access_token.to_s.strip
        return {} if token.empty?

        {
          'bearerAuth' => {
            type: 'bearer', in: 'header', key: 'Authorization',
            value: "Bearer #{token}"
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
      request.options[:timeout] = Transport.checked_timeout(opts[:timeout]) unless opts[:timeout].nil?
      request
    end

    # A 2xx the generated client cannot read as the answer it promises is the
    # server's fault, and a retryable :server_error, as it is on the OAuth calls:
    # a proxy's HTML page, a cut-off or empty body, or an object missing a member
    # the spec requires. The generated reader raised a RuntimeError, a
    # JSON::ParserError or an ArgumentError for those, none of them retried, and
    # handed an empty or non-object body back as nil, as if it were the answer.
    #
    # Every member present is checked against the type the spec gives it, at any
    # depth, before the answer is handed back: the generated reader converts with
    # `to_i`, so `"version":"x"` came back as 0 and `"version":"3"` as 3, and it
    # skips a list member sent as null, so `"versions": null` came back as nil
    # (5.9.0, measured 2026-10-20).
    def deserialize(response, return_type)
      data = super
      raise Error.new(:server_error, "the API answered with no #{return_type}", status: response.code) if data.nil?

      Transport.check_type!(JSON.parse(response.body.to_s), return_type.to_s, 'the answer')
      data
    rescue Error
      raise
    rescue StandardError => e
      raise Error.new(:server_error, "could not read the answer as #{return_type}: #{e.message}",
                      status: response.code)
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

    # A request to the authorization server, which carries NO credential whatever
    # this client was built with: these endpoints have no use for the API key, and
    # on the token endpoint an `Authorization` header reads as client
    # authentication, which a public client does not have.
    #
    # The form is encoded here rather than by curl, so a `+` in a value leaves as
    # `%2B` and never arrives as a space.
    def oauth_request(http_method, path, form: nil, json: nil, timeout: nil)
      headers = { 'Accept' => 'application/json' }
      headers['Content-Type'] = 'application/x-www-form-urlencoded' unless form.nil?
      headers['Content-Type'] = 'application/json' unless json.nil?
      request = build_request(http_method, path, header_params: headers, auth_names: [], timeout: timeout)
      request.options[:body] = URI.encode_www_form(form) unless form.nil?
      request.options[:body] = JSON.generate(json) unless json.nil?
      request
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

      body = parse_object(response)
      begin
        check_type!(body, 'Entitlement', 'the answer')
        Entitlement.build_from_hash(body)
      rescue StandardError => e
        raise Error.new(:server_error, "could not read the answer as Entitlement: #{e.message}",
                        status: response.code)
      end
    end

    def self.lookup_result(response)
      raise Error.from_transport(response) if transport_failure?(response)
      raise Error.from_status(response.code, response.headers, response.body) unless response.success?

      body = parse_object(response)
      begin
        check_type!(body, 'LookupResponse', 'the answer')
      rescue TypeError => e
        raise Error.new(:server_error, "could not read the answer as LookupResponse: #{e.message}",
                        status: response.code)
      end
      Result.new(body)
    end

    # Whether a parsed value is the generated `type`: a batch entry that is not
    # is that address's error alone.
    def self.conforms?(value, type)
      check_type!(value, type, 'the entry')
    rescue TypeError
      false
    end

    # The two maps of a batch answer, each present even when empty. An answer
    # carrying neither is unreadable as a whole, and is retried as one.
    def self.batch_body(response)
      raise Error.from_transport(response) if transport_failure?(response)
      raise Error.from_status(response.code, response.headers, response.body) unless response.success?

      body = parse_object(response)
      unless body['results'].is_a?(Hash) || body['errors'].is_a?(Hash)
        raise Error.new(:server_error, 'the batch answer carried neither results nor errors',
                        status: response.code)
      end

      {
        'results' => body['results'].is_a?(Hash) ? body['results'] : {},
        'errors' => body['errors'].is_a?(Hash) ? body['errors'] : {},
      }
    end

    # The JSON object a 2xx OAuth answer carries. A refusal the authorization
    # server words as an RFC 6749 error raises that; anything else that is not a
    # 2xx raises the ordinary error its status maps to.
    def self.oauth_object(response)
      oauth_success!(response)
      parse_object(response)
    end

    def self.oauth_success!(response)
      raise Error.from_transport(response) if transport_failure?(response)
      return if response.success?

      raise oauth_refusal(response) || Error.from_status(response.code, response.headers, response.body)
    end

    # Only a 4xx whose body is a JSON object with a STRING `error` is the
    # authorization server's own refusal. A 5xx is an outage whatever its body
    # says, and a gateway's page names no OAuth code at all.
    def self.oauth_refusal(response)
      return nil unless (400..499).cover?(response.code)

      body = JSON.parse(response.body.to_s)
      return nil unless body.is_a?(Hash) && body['error'].is_a?(String)

      description = body['error_description'].is_a?(String) ? body['error_description'] : nil
      OauthRequestError.for_code(body['error'], description, status: response.code, headers: response.headers)
    rescue JSON::ParserError
      nil
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

    private_class_method :transport_failure?, :parse_object, :oauth_refusal

    # The members the spec requires of each answer a lookup, a batch, the
    # entitlement or a database call reads. One that is not nullable must be
    # there and not null. Every plan's lookup carries `ip` and `is_vpn`, and a
    # detail's members are as optional as the plan makes them.
    # test/client_test.rb holds this to spec/openapi.yaml.
    REQUIRED = {
      'LookupResponse' => %i[ip is_vpn],
      'VpnDetail' => [],
      'ClassDetail' => [],
      'ProxyDetail' => [],
      'PubproxyDetail' => [],
      'Location' => %i[continent continent_name country country_name timezone currency_code currency_name
                       currency_symbol flag_emoji flag_unicode],
      'Asn' => %i[asn name domain type prefix],
      'BatchLookupError' => %i[status error],
      'Entitlement' => %i[org_id apikey plan usage],
      'EntitlementApikey' => %i[id expires allowed_cidrs],
      'EntitlementPlan' => %i[key tier],
      'EntitlementUsage' => %i[requests quota hard_limit window_start window_end],
      'DatabaseList' => %i[databases],
      'Database' => %i[base name summary license_type starts expires renews_at notice_due_at in_term standing
                       open versions],
      'DatabaseVersion' => %i[id version formats],
      'DatabaseFormatSize' => %i[format bytes],
      'DatabaseMetadata' => %i[id updated entries schema],
      'DatabaseMetadataColumn' => %i[name type],
      'DatabaseChecksumsResponse' => %i[id format checksums],
      'DbChecksums' => %i[md5 sha1 sha256 sha512],
      'DownloadList' => %i[downloads],
      'Download' => %i[dataset_id format outcome sample open bytes http_status apikey_id client_ip user_agent
                       created],
    }.freeze

    # RFC 3339's full-date, the spec's `date`, and its date-time, the spec's
    # `date-time`, its `T` and `Z` in either case, as RFC 3339 allows: through
    # 5.11.1 a lowercase one failed the call. Anything else reached the
    # generated reader's Date.parse or Time.parse, which read "monday" as this
    # week's, "10:00" as today in the process's zone and 30 February as 2 March,
    # or a lookup's detail handed it back as served (5.10.0, measured 2026-10-21).
    RFC3339_DATE = /\A(\d{4})-(\d{2})-(\d{2})\z/
    RFC3339_DATE_TIME = /\A(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|[+-](\d{2}):(\d{2}))\z/

    # A date in the form its type names, on a day and at a time that exist: an
    # hour of 24 rolls over the way a missing day does.
    def self.date?(value, type)
      m = (type == 'Date' ? RFC3339_DATE : RFC3339_DATE_TIME).match(value)
      return false unless m && Date.valid_date?(m[1].to_i, m[2].to_i, m[3].to_i)

      type == 'Date' || (m[4].to_i < 24 && m[5].to_i < 60 && m[6].to_i < 60 && m[7].to_i < 24 && m[8].to_i < 60)
    end

    # True when the parsed `value` has the generated `type`, a model's members
    # recursively; raises TypeError naming where it does not. No list entry or
    # map value the spec describes may be null: through 5.9.0 one came back as
    # nil, or as 0 in `size`, and a lookup's `"is_hosting": "yes"` came back as
    # the answer.
    def self.check_type!(value, type, where)
      raise TypeError, "#{where} is null" if value.nil?

      typed =
        case type
        when 'String' then value.is_a?(String)
        when 'Date', 'Time' then value.is_a?(String) && date?(value, type)
        when 'Integer' then value.is_a?(Integer)
        when 'Float' then value.is_a?(Numeric)
        when 'Boolean' then [true, false].include?(value)
        when 'Object' then true
        when /\AArray<(?<inner>.+)>\z/
          inner = Regexp.last_match(:inner)
          value.is_a?(Array) && value.each_with_index.all? { |v, i| check_type!(v, inner, "#{where}[#{i}]") }
        when /\AHash<String, ?(?<inner>.+)>\z/
          inner = Regexp.last_match(:inner)
          value.is_a?(Hash) && value.all? { |k, v| check_type!(v, inner, "#{where}.#{k}") }
        else
          model = VPNDetection.const_get(type)
          if model.respond_to?(:openapi_types)
            value.is_a?(Hash) && model.openapi_types.all? { |attr, member| check_member!(model, attr, member, value, where) }
          else
            value.is_a?(String) # an enum
          end
        end
      return true if typed

      raise TypeError, "#{where} is not a #{type}"
    end

    # A member absent or null reads as absent, unless the spec requires it and
    # does not make it nullable.
    def self.check_member!(model, attr, member, value, where)
      key = model.attribute_map[attr].to_s
      return check_type!(value[key], member.to_s, "#{where}.#{key}") unless value[key].nil?
      return true unless REQUIRED.fetch(model.name.split('::').last).include?(attr)
      return true if model.openapi_nullable.include?(attr)

      raise TypeError, "#{where}.#{key} is #{value.key?(key) ? 'null' : 'missing'}"
    end

    private_class_method :check_member!
  end
end
