# frozen_string_literal: true

module VPNDetection
  # What may be tried again, and how long to wait first.
  #
  # Only a 5xx, a transport failure and a 429 that carried `Retry-After` are
  # worth another attempt. Every other 4xx is a client error and fails on the
  # first try, so a bad dataset id is not asked for three times.
  module Retries
    BACKOFF_SECONDS = 0.25

    # The longest `Retry-After` honored, in seconds: 2**31 - 1 ms, about 24.8
    # days, the same bound as the .NET, erlang, perl and php SDKs'.
    LONGEST_WAIT = 2_147_483.647

    module_function

    # `retry_if`, when given, is asked after each retryable failure, and a false
    # answer ends the attempts there.
    def with_retries(retries, retry_if: nil)
      attempt = 0
      begin
        yield
      rescue Error => e
        raise unless e.retryable? && attempt < retries && (retry_if.nil? || retry_if.call)

        attempt += 1
        sleep(delay_for(e, attempt))
        retry
      end
    end

    # A server-supplied delay wins, including a `Retry-After: 0`, which is the
    # server saying "immediately" rather than saying nothing. One past
    # LONGEST_WAIT is waited out on the backoff instead, still rate_limited:
    # honored, `2147484` held the call for 24.8 days, and `sleep` raised a raw
    # RangeError for `9223372036854775807` and `1e400`.
    def delay_for(error, attempt)
      asked = error.retry_after_seconds
      return asked if asked && asked <= LONGEST_WAIT

      BACKOFF_SECONDS * (2**(attempt - 1))
    end
  end
end
