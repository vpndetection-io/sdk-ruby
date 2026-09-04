# frozen_string_literal: true

module VPNDetection
  # The licensed dataset downloads, reached as `client.database`.
  #
  # Access is granted by contract rather than self-serve, so every method here
  # needs a key carrying the `db.download` scope.
  class Database
    def initialize(transport, retries:)
      @api = DatabaseApi.new(transport)
      @retries = retries
    end

    # The dataset FAMILIES your organization is licensed to download.
    #
    # A license is held against the family, while a download names one version,
    # so the ids {#download_url} and {#checksums} take come from each family's
    # `versions`, not from the family itself.
    def list
      call { @api.list_databases.datasets }
    end

    # What is inside one dataset: schema, samples, row count and sizes.
    def metadata(id)
      call { @api.database_metadata(id) }
    end

    # The digests for one dataset file.
    #
    # Returns the whole set rather than one algorithm: which digests a dataset
    # publishes is the API's choice, not ours, and the response nests them one
    # level down under `checksums`.
    def checksums(id, format)
      call { @api.database_checksum(id, format).checksums }
    end

    # Your organization's recent download attempts, newest first.
    def downloads(limit: nil)
      call { @api.list_downloads(limit.nil? ? {} : { limit: limit }).downloads }
    end

    # The time-limited URL for one dataset file.
    #
    # The URL is returned rather than the bytes so the caller decides how to
    # transfer a file that routinely runs to gigabytes; the link authorizes the
    # START of a transfer, so one already running is not interrupted when it
    # lapses.
    def download_url(id, format)
      call { redirect_location(id, format) }
    end

    private

    # The 302 is this operation's SUCCESS case, but the generated client treats
    # every non-2xx as a failure, so it arrives as an ApiError carrying the
    # Location header.
    def redirect_location(id, format)
      @api.download_database(id, format)
      raise Error.new(:server_error, 'expected a redirect to object storage')
    rescue ApiError => e
      raise unless e.code == 302

      location = e.response_headers && e.response_headers['Location']
      raise Error.new(:server_error, 'the redirect carried no Location header', status: 302) if location.nil?

      location.is_a?(Array) ? location.last : location
    end

    def call(&block)
      Retries.with_retries(@retries) do
        block.call
      rescue ApiError => e
        raise error_for(e)
      end
    end

    def error_for(api_error)
      return Error.new(:network, api_error.message) if api_error.code.to_i.zero?

      Error.from_status(api_error.code, api_error.response_headers, api_error.response_body)
    end
  end
end
