# frozen_string_literal: true

require 'digest'
require 'securerandom'

module VPNDetection
  # One sign-in's PKCE pair: `challenge` goes in the authorization URL, and
  # `verifier` to {OauthApi#exchange_authorization_code}.
  # `code_challenge_method` is always `S256`, the only method the server
  # accepts; a reader called `method` would hide Object#method. The verifier is
  # left out of `inspect`, so logging the pair does not leak it.
  Pkce = Data.define(:verifier, :challenge, :code_challenge_method) do
    def inspect
      "#<data VPNDetection::Pkce challenge=#{challenge.inspect} code_challenge_method=#{code_challenge_method.inspect}>"
    end
    alias_method :to_s, :inspect
  end

  # Signing a person in with OAuth, reached as `client.oauth`.
  #
  # A program on the person's own machine starts a device sign-in, shows them a
  # code to approve in their browser, and waits for the tokens, which can carry
  # one of their API keys so nobody pastes a key by hand. Only a registered
  # client ID works; they are issued on request from support@vpndetection.io.
  #
  # No request made here carries the API key this client was built with, and a
  # client built without one works exactly the same. Every method that makes a
  # request takes `timeout:`, seconds per attempt, for that call alone.
  #
  # An app that can take a browser redirect signs the person in with the
  # authorization code flow instead: {#authorization_url} with a {#create_pkce}
  # pair, then {#exchange_authorization_code}.
  class OauthApi
    METADATA_PATH = '/.well-known/oauth-authorization-server'
    DEVICE_AUTHORIZATION_PATH = '/oauth/device_authorization'
    TOKEN_PATH = '/oauth/token'
    REVOKE_PATH = '/oauth/revoke'
    AUTHORIZE_PATH = '/oauth/authorize'
    DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'
    # The longest single `sleep` the poll asks Ruby for, in seconds.
    LONGEST_SLEEP = 2**31 - 1

    # The members a 2xx must carry for its type to mean anything.
    REQUIRED = {
      OauthMetadata => %i[issuer authorization_endpoint token_endpoint],
      DeviceAuthorization => %i[device_code user_code verification_uri expires_in interval],
      TokenResponse => %i[access_token token_type expires_in],
    }.freeze

    def initialize(transport, retries:)
      @transport = transport
      @retries = retries
      # The poll's wait and its monotonic clock, which a test replaces together.
      @wait = ->(seconds) { sleep_in_parts(seconds) }
      @now = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
    end

    # The authorization server's discovery document.
    #
    # @return [OauthMetadata]
    def metadata(timeout: nil)
      Retries.with_retries(@retries) do
        decode(OauthMetadata, @transport.oauth_request(:GET, METADATA_PATH, timeout: timeout).run)
      end
    end

    # Start a device sign-in: show the person `user_code` and `verification_uri`,
    # then {#poll_device_token}.
    #
    # @param scope [String, nil] space-delimited, sent as given; the server grants
    #   what this client may ask for and silently drops the rest.
    # @param resource [String, nil] the API the tokens are for.
    # @return [DeviceAuthorization]
    def device_authorization(client_id, scope: nil, resource: nil, timeout: nil)
      form = { 'client_id' => client_id, 'scope' => scope, 'resource' => resource }.compact
      Retries.with_retries(@retries) do
        request = @transport.oauth_request(:POST, DEVICE_AUTHORIZATION_PATH, form: form, timeout: timeout)
        decode(DeviceAuthorization, request.run)
      end
    end

    # Exchange a device code for tokens, once. Until the person approves this
    # raises {OauthRequestError} coded `authorization_pending`;
    # {#poll_device_token} is the loop that waits for them.
    #
    # Never retried: the server spends the code when it answers, so a retry after
    # a lost success could only fail and lose the tokens.
    #
    # @return [TokenResponse] with `apikey_id` and `apikey` when the person picked a key.
    def exchange_device_code(client_id, device_code, timeout: nil)
      form = { 'grant_type' => DEVICE_CODE_GRANT, 'device_code' => device_code, 'client_id' => client_id }
      exchange(form, timeout)
    end

    # Exchange a refresh token for a new pair. The token presented is spent, so
    # keep the `refresh_token` this returns. Never retried, for the same reason as
    # {#exchange_device_code}.
    #
    # @return [TokenResponse] which may name the key in `apikey_id`, but never carries `apikey`.
    def exchange_refresh_token(client_id, refresh_token, timeout: nil)
      form = { 'grant_type' => 'refresh_token', 'refresh_token' => refresh_token, 'client_id' => client_id }
      exchange(form, timeout)
    end

    # Exchange the `code` a sign-in's redirect brought back for tokens.
    # `code_verifier` is the PKCE verifier whose challenge went into the
    # authorization URL, and `redirect_uri` that URL's, exactly.
    #
    # Never retried: the server spends the code on first read, before it checks
    # the verifier, so a retry could only be refused.
    #
    # @return [TokenResponse]
    def exchange_authorization_code(client_id, code, code_verifier, redirect_uri, timeout: nil)
      form = {
        'grant_type' => 'authorization_code', 'code' => code, 'redirect_uri' => redirect_uri,
        'client_id' => client_id, 'code_verifier' => code_verifier
      }
      exchange(form, timeout)
    end

    # The URL to open in the person's browser for the authorization code flow.
    # Makes no request. Once they decide, the server redirects to `redirect_uri`
    # with a `code` for {#exchange_authorization_code} (and `state`, when one was
    # given), or with an `error`. An option given empty is left out; a required
    # value that is empty or not UTF-8 raises ArgumentError.
    #
    # @return [String]
    def authorization_url(client_id, redirect_uri, code_challenge, scope: nil, state: nil, resource: nil)
      required = { 'client_id' => client_id, 'redirect_uri' => redirect_uri, 'code_challenge' => code_challenge }
      required.each do |name, value|
        raise ArgumentError, "#{name} must be a non-empty String" unless value.is_a?(String) && !value.empty?
      end
      optional = { 'scope' => scope, 'state' => state, 'resource' => resource }.reject { |_, v| v.nil? || v.empty? }
      params = { 'response_type' => 'code', **required, 'code_challenge_method' => 'S256', **optional }
      query = params.map { |name, value| "#{name}=#{percent_encode(name, value)}" }.join('&')
      "#{@transport.config.base_url}#{AUTHORIZE_PATH}?#{query}"
    end

    # A fresh PKCE pair for one sign-in, from 32 bytes of SecureRandom.
    #
    # @return [Pkce]
    def create_pkce
      verifier = SecureRandom.urlsafe_base64(32)
      Pkce.new(verifier: verifier, challenge: pkce_challenge(verifier), code_challenge_method: 'S256')
    end

    # The `S256` challenge for a PKCE verifier: its SHA-256, as unpadded base64url.
    #
    # @return [String]
    def pkce_challenge(verifier)
      [Digest::SHA256.digest(verifier)].pack('m0').tr('+/', '-_').delete('=')
    end

    # Revoke an access or refresh token. A refresh token ends the whole grant and
    # every token it issued, which is how a machine signs out.
    #
    # @return [nil]
    def revoke(client_id, token, timeout: nil)
      form = { 'token' => token, 'client_id' => client_id }
      Retries.with_retries(@retries) do
        request = @transport.oauth_request(:POST, REVOKE_PATH, form: form, timeout: timeout)
        Transport.oauth_success!(request.run)
      end
      nil
    end

    # Wait for the person to approve a device sign-in, and return its tokens.
    #
    # Waits `device.interval` seconds before EVERY exchange, the first included,
    # and five seconds longer for good each time the server answers `slow_down`,
    # but never past `device.expires_in`: a wait that would end later ends then.
    # Raises {OauthAccessDeniedError} when the person refuses and
    # {OauthExpiredTokenError} when the code expires, including locally, with no
    # status, once `device.expires_in` seconds have passed since this call. Any
    # other failure, a timeout or an outage included, ends the wait unchanged;
    # calling again with the same device is safe until the code expires.
    #
    # There is no way to cancel it from outside: it blocks until one of those
    # outcomes, so run it where blocking is acceptable.
    #
    # @param timeout [Numeric, nil] bounds each exchange, never the whole wait.
    # @return [TokenResponse]
    def poll_device_token(client_id, device, timeout: nil)
      Transport.checked_timeout(timeout) unless timeout.nil?
      interval = device.interval >= 1 ? device.interval : 5
      deadline = @now.call + device.expires_in
      loop do
        # A wait that would end past the deadline waits only the time left, never
        # a negative remainder, and the local expiry below follows with no request.
        left = deadline - @now.call
        @wait.call(interval < left ? interval : [left, 0].max)
        raise OauthExpiredTokenError, 'expired_token' if @now.call >= deadline

        begin
          return exchange_device_code(client_id, device.device_code, timeout: timeout)
        rescue OauthRequestError => e
          case e.error_code
          when 'slow_down' then interval += 5
          when 'authorization_pending' then next
          else raise
          end
        end
      end
    end

    private

    # `sleep` raises RangeError for a Float from about 9.2e18 s and an Integer
    # past 2**63 - 1, and a server's `expires_in` can leave a wait longer than
    # either, so a long one is slept in parts rather than ending the poll.
    def sleep_in_parts(seconds)
      while seconds.positive?
        part = [seconds, LONGEST_SLEEP].min
        sleep(part)
        seconds -= part
      end
    end

    # Every byte of the UTF-8 but A-Z a-z 0-9 - . _ ~ as %XX, so a space is %20
    # and never +.
    def percent_encode(name, value)
      raise ArgumentError, "#{name} is not valid UTF-8" unless value.encode(Encoding::UTF_8).valid_encoding?

      value.encode(Encoding::UTF_8).b.gsub(/[^A-Za-z0-9\-._~]/n) { |byte| format('%%%02X', byte.ord) }
    rescue EncodingError
      raise ArgumentError, "#{name} is not valid UTF-8"
    end

    def exchange(form, timeout)
      decode(TokenResponse, @transport.oauth_request(:POST, TOKEN_PATH, form: form, timeout: timeout).run)
    end

    # Only the members the type declares are read, each checked against the type
    # the spec gives it, so an absent member stays nil and an empty `scope` stays
    # an empty string. A 2xx that is not the type is the server's fault.
    def decode(type, response)
      body = Transport.oauth_object(response)
      type.attribute_map.each do |member, wire|
        value = body[wire.to_s]
        if value.nil?
          next unless REQUIRED.fetch(type).include?(member)

          raise Error.new(:server_error, "the answer carried no #{wire}", status: response.code)
        end
        next if typed?(type.openapi_types.fetch(member), value)

        raise Error.new(:server_error, "the answer's #{wire} is not a #{type.openapi_types[member]}",
                        status: response.code)
      end
      type.build_from_hash(body)
    end

    def typed?(type, value)
      case type
      when :String then value.is_a?(String)
      when :Integer then value.is_a?(Integer)
      when :Boolean then [true, false].include?(value)
      when :'Array<String>' then value.is_a?(Array) && value.all?(String)
      else raise ArgumentError, "no check for a member typed #{type}"
      end
    end
  end
end
