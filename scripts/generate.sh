#!/bin/bash

# Regenerates the wire layer from the PINNED spec in spec/openapi.yaml.
#
# The generator runs in its official container, so nothing has to be installed
# locally, and it reads the committed spec rather than a URL, so the build is
# reproducible and offline. Refresh the spec with scripts/download-spec.sh, run
# this, and commit both together so a reviewer sees which spec produced which
# client.
#
# The output is COMMITTED. A gem installs from source with no build step, so a
# gitignored client would ship a package that cannot require itself.

set -euo pipefail

cd "$(dirname "$0")/.."

GENERATOR_IMAGE="${GENERATOR_IMAGE:-openapitools/openapi-generator-cli:v7.25.0}"

PROPS="gemName=vpndetection,moduleName=VPNDetection,hideGenerationTimestamp=true"

# The spec's `Error` schema is the database API's `{rc}` envelope. Left alone it
# generates VPNDetection::Error, which is the name Ruby convention reserves for a
# gem's own exception base class, so the two would be the same constant.
MODELS="Error=ErrorEnvelope"

# The four wrapper schemas are inline in the spec, so the generator names them after
# the operation and status code (DatabaseChecksum200ResponseChecksums). One of those
# is public API here. --model-name-mappings does NOT reach an inline schema; only
# --inline-schema-name-mappings does, keyed by the generator's own placeholder name.
NAMES="listDatabases_200_response=DatasetList"
NAMES="${NAMES},listDownloads_200_response=DownloadList"
NAMES="${NAMES},databaseChecksum_200_response=DatasetChecksumsResponse"
NAMES="${NAMES},databaseChecksum_200_response_checksums=DatasetChecksums"

rm -rf .gen
mkdir -p .gen

docker run --rm \
    -v "$PWD/spec:/spec:ro" \
    -v "$PWD/.gen:/out" \
    "$GENERATOR_IMAGE" generate \
    -i /spec/openapi.yaml \
    -g ruby --library typhoeus \
    -o /out \
    --model-name-mappings "$MODELS" \
    --inline-schema-name-mappings "$NAMES" \
    --additional-properties="$PROPS" \
    >/dev/null

# Only the wire layer is taken. The generator also emits lib/vpndetection.rb and
# lib/vpndetection/version.rb, which are OURS, plus a gemspec, Gemfile, Rakefile,
# README, rubocop config, travis and gitlab CI files and an rspec suite - all of
# which would overwrite the repo if the output were unpacked over it.
rm -rf lib/vpndetection/{api,models} lib/vpndetection/{api_client,api_error,api_model_base,configuration}.rb
cp -R .gen/lib/vpndetection/api lib/vpndetection/api
cp -R .gen/lib/vpndetection/models lib/vpndetection/models
for f in api_client api_error api_model_base configuration ; do
    cp ".gen/lib/vpndetection/${f}.rb" "lib/vpndetection/${f}.rb"
done

rm -rf .gen
echo "regenerated the wire layer under lib/vpndetection from spec/openapi.yaml"
grep -m1 '^  version:' spec/openapi.yaml
