# frozen_string_literal: true

# The licensed-download half, which only the max key can reach: it is the tier
# holding dataset licences, and db.download is a scope the other three keys do
# not carry.
#
# The transfer is budgeted before it starts. Metadata publishes a size per
# format, and that size is checked against the ceiling below FIRST, so a mistaken
# dataset id can never quietly pull one of the gigabyte datasets through CI.

require 'digest'
require 'fileutils'
require 'tmpdir'

require_relative '../lib/staging'

class DatabaseTest < Minitest::Test
  # The max organization licenses cdn_ip for redistribution, and at ~10 KB it is
  # the only dataset small enough to move in CI.
  DATASET_ID = 'cdn_ip_v1'
  FORMAT = 'csvgz'
  # 8 MiB against a ~10 KB dataset. Three orders of magnitude of headroom, so
  # tripping it means the suite is pointed somewhere unintended, which is exactly
  # when a transfer must not go ahead.
  CEILING = 8 * 1024 * 1024
  # A real catalogue id the max organization holds no licence for.
  UNLICENSED_ID = 'hosting_ip_v1'
  HEX_DIGEST = /\A[0-9a-f]{64}\z/

  class << self
    attr_accessor :transfer, :scratch
  end

  def setup
    skip Tiers.skip_for(Tiers.max) if Tiers.skip_for(Tiers.max)
  end

  def test_the_licensed_catalogue_answers_the_schema_the_client_was_generated_from
    families = max_client.database.list

    refute_empty families, 'the max organization licenses nothing'
    # Named first, and against what the wire actually carried, because every
    # typed assertion below reads as nil when the payload disagrees and a bare
    # "expected a String" costs a whole CI cycle to interpret.
    served = Staging.wire_json('/api/v1/database/list', Tiers.max)['datasets'].flat_map(&:keys).uniq
    assert_includes served, 'base', "the payload carries #{served.sort.join(', ')}"
    assert_includes served, 'versions', "the payload carries #{served.sort.join(', ')}"
    refute_includes served, 'docsGroup',
                    'docsGroup is a docs-site slug and must not be published as API surface'

    ids = families.flat_map do |family|
      refute_nil family.base, 'a licensed family carries no base'
      refute_nil family.name, "#{family.base} carries no name"
      assert_includes %w[expired licensed unlicensed], family.standing,
                      "#{family.base} carries an undocumented standing"
      assert_includes %w[evaluation internal redistribute], family.redistribution,
                      "#{family.base} carries an undocumented right"
      # The point of the family shape: a license covers the family, and these are
      # the ids the download and checksum calls take. Before the spec was
      # corrected this list did not exist, so list() could not tell a caller what
      # to download.
      refute_empty family.versions, "#{family.base} carries no versions"
      family.versions.map do |version|
        refute_nil version.id, "#{family.base} has a version with no id"
        refute_empty version.formats, "#{version.id} carries no formats"
        version.id
      end
    end
    puts "==> licensed: #{ids.join(', ')}"
  end

  def test_a_dataset_the_organization_does_not_license_is_refused_cleanly
    client = max_client(retries: 2)
    before = Staging.facts.length

    error = assert_raises(VPNDetection::Error) { client.database.download_url(UNLICENSED_ID, FORMAT) }

    assert_equal :forbidden, error.kind,
                 "a refusal must be forbidden. If #{UNLICENSED_ID} is now licensed to this " \
                 'organization, point this at one that is not'
    assert_equal 403, error.status
    refute error.retryable?, 'a licence refusal is not worth retrying'
    # The API says which refusal this is (`{"rc":"NOT_LICENSED"}`). Falling back
    # to the status means the client never read the envelope.
    refute_match(/\Arequest failed with status/, error.message,
                 'the client fell back to the status, so the body went unread')
    assert_equal 1, Staging.facts.length - before, 'a 4xx must not be retried'
  end

  def test_download_streams_a_real_dataset_to_disk_intact
    transfer = transferred

    assert_operator transfer[:written], :>, 0, 'nothing was transferred'
    assert_equal transfer[:written], File.size(transfer[:path])
    refute_path_exists "#{transfer[:path]}.part", 'the .part file outlived a successful transfer'
    body = File.binread(transfer[:path])
    assert_equal "\x1f\x8b".b, body[0, 2], 'the payload is not gzip'

    assert_match HEX_DIGEST, transfer[:checksums].sha256,
                 'the checksums did not unwrap past the envelope'
    assert_equal transfer[:checksums].sha256, Digest::SHA256.hexdigest(body),
                 'the bytes do not hash to what the API publishes'

    # The presigned URL authorizes itself, so the request that follows the 302
    # must carry no credential.
    storage = transfer[:facts].reject { |fact| fact.origin == Staging::BASE_URL }
    refute_empty storage, 'nothing was fetched from object storage, so no 302 was followed'
    storage.each do |fact|
      assert_empty fact.tiers, "the API key was sent to object storage at #{fact.origin}"
    end
  end

  def test_download_bytes_agrees_with_the_streamed_copy
    transfer = transferred

    bytes = max_client.database.download_bytes(DATASET_ID, FORMAT)

    assert_equal transfer[:written], bytes.bytesize
    assert_equal File.binread(transfer[:path]), bytes
    assert_equal transfer[:checksums].sha256, Digest::SHA256.hexdigest(bytes)
  end

  private

  # A client of its own per test, so one test's request record cannot be read
  # through another's.
  def max_client(**options)
    Staging.client_for(Tiers.max, **options)
  end

  # Memoized so the two transfer tests share one download rather than pulling the
  # dataset twice each.
  def transferred
    return self.class.transfer if self.class.transfer

    client = max_client
    before = Staging.facts.length
    metadata = client.database.metadata(DATASET_ID)
    assert_equal DATASET_ID, metadata.id, 'metadata answered about the wrong dataset'
    size = metadata.size && metadata.size[FORMAT]
    refute_nil size, "#{DATASET_ID} publishes no #{FORMAT} size to check a transfer against"
    assert_operator size, :<=, CEILING,
                    "#{DATASET_ID} is #{size} bytes, past the #{CEILING} ceiling, so it is not transferred"

    path = File.join(scratch_dir, "#{DATASET_ID}.csv.gz")
    written = client.database.download(DATASET_ID, FORMAT, path)
    # Read after the transfer, so a rebuild between the two calls shows up as a
    # digest mismatch rather than passing against a digest of nothing.
    checksums = client.database.checksums(DATASET_ID, FORMAT)
    puts "==> #{DATASET_ID}.#{FORMAT}: #{written} bytes, metadata says #{size}"

    self.class.transfer = { written: written, path: path, checksums: checksums,
                            facts: Staging.facts[before..] }
  end

  # A directory for the whole class rather than for one test: a per-test one
  # belongs to whichever test asked first and would be gone before the other
  # read what was transferred.
  def scratch_dir
    self.class.scratch ||= Dir.mktmpdir('vpndetection-integration-').tap do |dir|
      Minitest.after_run { FileUtils.remove_entry(dir) }
    end
  end
end
