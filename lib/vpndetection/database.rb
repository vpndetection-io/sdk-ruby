# frozen_string_literal: true

module VPNDetection
  # The licensed dataset downloads, reached as `client.database`.
  #
  # Access is granted by contract rather than self-serve, so every method here
  # needs a key carrying the `db.download` scope.
  class Database
    def initialize(transport, retries:)
      @transport = transport
      @api = DatabaseApi.new(transport)
      @retries = retries
    end

    # The dataset FAMILIES your organization is licensed to download.
    #
    # A license is held against the family, while a download names one version,
    # so the ids {#download}, {#download_bytes}, {#download_url} and {#checksums}
    # take come from each family's `versions`, not from the family itself.
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

    # Download one dataset file to `path`, and return the bytes written.
    #
    # The bytes land in a neighboring `.part` file that is renamed on completion,
    # so a transfer that dies half way leaves no truncated file that reads as a
    # whole dataset, and a refresh that fails does not destroy the copy already
    # there. Nothing beyond one chunk is ever held in memory, whatever the
    # dataset weighs.
    def download(id, format, path)
      partial = "#{path}.part"
      begin
        url = download_url(id, format)
        written = Retries.with_retries(@retries) do
          # Reopened per attempt, so a retry restarts the file rather than
          # appending a second copy of the body to a half-written one.
          File.open(partial, 'wb') { |file| stream(url) { |chunk| file.write(chunk) } }
        end
        File.rename(partial, path)
      rescue StandardError
        File.delete(partial) if File.exist?(partial)
        raise
      end
      written
    end

    # Download one dataset file and hand back its bytes.
    #
    # **This holds the entire file in memory**, and the catalog spans five orders
    # of magnitude: `cdn_ip_v1` is 10 KB while `resproxy_ip_90d_v1` is 1.79 GB.
    # Reach for it at the small end, where the bytes go straight into a parser,
    # and use {#download} for anything you have not measured.
    def download_bytes(id, format)
      url = download_url(id, format)
      Retries.with_retries(@retries) do
        bytes = String.new(encoding: Encoding::BINARY)
        stream(url) { |chunk| bytes << chunk }
        bytes
      end
    end

    private

    # Runs one transfer of a presigned link, handing each chunk to the block, and
    # returns the bytes that reached it.
    #
    # Typhoeus only streams when a request carries an `on_body` callback: with
    # one set, Ethon's write callback passes the chunk on INSTEAD of appending it
    # to `response.body`, so the ceiling on a transfer of any size is one chunk.
    # The callback must therefore never answer `:unyielded`, which is the value
    # that means "nobody took this" and puts the chunk back in the buffer.
    def stream(url)
      written = 0
      served = nil
      request = @transport.storage_request(url)
      request.on_headers { |response| served = response.code }
      request.on_body do |chunk, _response|
        # An error page has no bounded size, so a refusal is aborted here rather
        # than read and then classified.
        next :abort unless served == 200

        yield chunk
        written += chunk.bytesize
      end

      settle(request.run, written)
    end

    def settle(response, written)
      status = response.code.to_i
      # No status at all means the transfer never reached HTTP: DNS, connect,
      # TLS or a timeout, and curl's own reason is the only thing that says
      # which. It is also what a :partial_file arrives as once a status IS in
      # hand, which is where a transfer that died mid-flight fails rather than
      # leaving a short file that reads as a whole dataset. The declared-length
      # check the other bindings hand-roll is curl's job here.
      raise Error.from_transport(response) if status.zero?

      unless status == 200
        raise Error.from_status(status, response.headers, nil,
                                message: "object storage refused the download link with status #{status}")
      end
      raise Error.from_transport(response) unless response.success?

      written
    end

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
