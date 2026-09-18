# frozen_string_literal: true

module VPNDetection
  # The licensed database downloads, reached as `client.database`.
  #
  # Access is granted by contract rather than self-serve, so every method here
  # needs a key carrying the `db.download` scope.
  #
  # Every JSON call here takes `timeout:`, in seconds, bounding each ATTEMPT of
  # that call alone and overriding the bound the client was built with. The two
  # transfers take none, and are refused it rather than ignoring it: a dataset
  # runs to gigabytes and minutes, so a bound that suits a JSON call would
  # abandon a healthy download.
  class DatabaseApi
    def initialize(transport, retries:)
      @transport = transport
      @api = DatabaseWireApi.new(transport)
      @retries = retries
    end

    # The database FAMILIES your organization is licensed to download.
    #
    # A license is held against the family, while a download names one version,
    # so the ids {#download}, {#download_bytes}, {#download_url} and {#checksums}
    # take come from each family's `versions`, not from the family itself.
    #
    # @param timeout [Numeric, nil] seconds this attempt may take, for THIS call only.
    def list(timeout: nil)
      call { @api.list_databases(timeout: timeout).databases }
    end

    # What is inside one dataset: schema, samples, row count and sizes.
    #
    # @param timeout [Numeric, nil] seconds this attempt may take, for THIS call only.
    def metadata(id, timeout: nil)
      call { @api.database_metadata(id, timeout: timeout) }
    end

    # The digests for one dataset file.
    #
    # Returns the whole set rather than one algorithm: which digests a dataset
    # publishes is the API's choice, not ours, and the response nests them one
    # level down under `checksums`.
    #
    # @param timeout [Numeric, nil] seconds this attempt may take, for THIS call only.
    def checksums(id, format, timeout: nil)
      check_format!(format)
      call { @api.database_checksum(id, format, timeout: timeout).checksums }
    end

    # Your organization's recent download attempts, newest first.
    #
    # @param timeout [Numeric, nil] seconds this attempt may take, for THIS call only.
    def downloads(limit: nil, timeout: nil)
      call { @api.list_downloads(limit: limit, timeout: timeout).downloads }
    end

    # The time-limited URL for one dataset file.
    #
    # The URL is returned rather than the bytes so the caller decides how to
    # transfer a file that routinely runs to gigabytes; the link authorizes the
    # START of a transfer, so one already running is not interrupted when it
    # lapses.
    #
    # @param timeout [Numeric, nil] seconds this attempt may take, for THIS call
    #   only. It bounds the request that MINTS the link, which is an ordinary
    #   JSON call, and says nothing about the transfer you then run with it.
    def download_url(id, format, timeout: nil)
      check_format!(format)
      call { redirect_location(id, format, timeout) }
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
        written = File.open(partial, 'wb') { |file| transfer(url) { |chunk| file.write(chunk) } }
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
      bytes = String.new(encoding: Encoding::BINARY)
      transfer(url) { |chunk| bytes << chunk }
      bytes
    end

    private

    # A format the API does not publish is refused HERE rather than sent.
    #
    # The generator used to emit this check inline in the wire client; naming
    # the enum in the spec made it stop, so an unknown format became a network
    # round trip and a 400. Owning it in this layer keeps the behaviour where a
    # caller can see it and independent of what the generator emits.
    def check_format!(format)
      return if DatabaseFormat.all_vars.include?(format)

      raise ArgumentError,
            "invalid value for \"format\", must be one of #{DatabaseFormat.all_vars}"
    end

    # The transfer of a presigned link, retried only while nothing has reached the
    # block: object storage failing before the body is as transient as any
    # outage, while a body that dies part way is not fetched again, because the
    # bytes already handed over cannot be taken back.
    def transfer(url, &sink)
      delivered = false
      Retries.with_retries(@retries, retry_if: -> { !delivered }) do
        stream(url) do |chunk|
          delivered = true
          sink.call(chunk)
        end
      end
    end

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
    def redirect_location(id, format, timeout)
      @api.download_database(id, format, timeout: timeout)
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
