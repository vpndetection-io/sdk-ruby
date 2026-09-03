# frozen_string_literal: true

module VPNDetection
  # What may be tried again, and how long to wait first.
  #
  # Only a 5xx, a transport failure and a 429 that carried `Retry-After` are
  # worth another attempt. Every other 4xx is a client error and fails on the
  # first try, so a bad dataset id is not asked for three times.
  module Retries
    BACKOFF_SECONDS = 0.25

    module_function

    def with_retries(retries)
      attempt = 0
      begin
        yield
      rescue Error => e
        raise unless e.retryable? && attempt < retries

        attempt += 1
        sleep(delay_for(e, attempt))
        retry
      end
    end

    # A server-supplied delay always wins, including a `Retry-After: 0`, which
    # is the server saying "immediately" rather than saying nothing.
    def delay_for(error, attempt)
      error.retry_after_seconds || BACKOFF_SECONDS * (2**(attempt - 1))
    end
  end
end
