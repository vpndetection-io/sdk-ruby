# frozen_string_literal: true

require 'json'
require 'time'

module VPNDetection
  # Everything this library raises.
  #
  # `:rate_limited` and `:quota_exceeded` both arrive as HTTP 429 and are NOT the
  # same thing. A rate limit is the API protecting itself and carries
  # `Retry-After`; retrying works. A spent quota carries no such header and
  # retrying will not help until the window rolls over or the limit is raised.
  # The header is the only thing that distinguishes them.
  class Error < StandardError
    KINDS = %i[
      bad_request unauthorized forbidden rate_limited quota_exceeded server_error network
    ].freeze

    RETRYABLE = %i[rate_limited server_error network].freeze

    attr_reader :kind, :status, :retry_after_seconds

    def initialize(kind, message, status: nil, retry_after_seconds: nil)
      super(message)
      @kind = kind
      @status = status
      @retry_after_seconds = retry_after_seconds
    end

    # Whether retrying this exact request could succeed.
    def retryable?
      RETRYABLE.include?(@kind)
    end

    # `message:` stands in for the response body, for a response whose body must
    # not be read: an object storage error page has no bounded size, so a refusal
    # from it is classified on the status alone.
    def self.from_status(status, headers, body, message: nil)
      message ||= message_of(body) || "request failed with status #{status}"
      retry_after = parse_retry_after(header(headers, 'retry-after'))

      case status
      when 429
        # Present means transient, absent means an allowance is spent. Nothing
        # else in the response separates the two.
        if retry_after.nil?
          new(:quota_exceeded, message, status: status)
        else
          new(:rate_limited, message, status: status, retry_after_seconds: retry_after)
        end
      when 400 then new(:bad_request, message, status: status)
      when 401 then new(:unauthorized, message, status: status)
      when 403 then new(:forbidden, message, status: status)
      # Every other 4xx is a CLIENT error. Classifying on the RANGE rather than
      # on an enumerated list is what keeps a 404 from a bad dataset id falling
      # through to the retryable server_error default and being retried twice
      # before it fails.
      when 400..499 then new(:bad_request, message, status: status)
      else new(:server_error, message, status: status)
      end
    end

    # A Typhoeus response that never carried an HTTP status: DNS failure,
    # connection refused, TLS failure, or a timeout.
    def self.from_transport(response)
      message = response.return_message || response.return_code&.to_s || 'transport failure'
      new(:network, message)
    end

    # Case-insensitive, and works with a plain Hash as well as with the
    # case-blind header object Typhoeus builds from a live response.
    def self.header(headers, name)
      return nil if headers.nil?

      value = headers[name] || headers[name.split('-').map(&:capitalize).join('-')]
      value = headers.find { |k, _| k.to_s.downcase == name }&.last if value.nil?
      value.is_a?(Array) ? value.last : value
    end

    # The two APIs behind this host answer with different envelopes: the lookup
    # endpoint uses `error`, the database endpoints use `rc`. Both are read here
    # so a caller never has to know which one they hit. An intermediary's HTML
    # error page parses as neither and leaves the status to speak for itself.
    def self.message_of(body)
      parsed = body.is_a?(String) ? (JSON.parse(body) rescue nil) : body
      return nil unless parsed.is_a?(Hash)

      message = parsed['error'] || parsed['rc']
      message.is_a?(String) ? message : nil
    end

    def self.parse_retry_after(value)
      return nil if value.nil? || value.to_s.strip.empty?

      seconds = Float(value, exception: false)
      return seconds if seconds && seconds >= 0

      # The header also permits an HTTP date.
      when_at = Time.httpdate(value) rescue nil
      return nil if when_at.nil?

      [0, (when_at - Time.now).ceil].max
    end

    private_class_method :header, :message_of, :parse_retry_after
  end
end
