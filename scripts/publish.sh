#!/bin/bash

# Publishes the gem to RubyGems from inside the official Ruby image, so a release
# needs nothing installed locally beyond docker and works identically on any
# machine. The release workflow does the same steps on a tag; this is the manual
# path for a first release or when Actions is not an option.
#
#   GEM_HOST_API_KEY=... ./scripts/publish.sh            # publish
#   GEM_HOST_API_KEY=... DRY_RUN=1 ./scripts/publish.sh  # rehearse
#
# The first release has to come through here: RubyGems attaches a trusted
# publisher to an EXISTING gem, so there is nothing to configure until the gem
# exists. The key must be able to push WITHOUT an interactive OTP, so create it
# with MFA not required for that scope.

set -euo pipefail

cd "$(dirname "$0")/.."

RUBY_IMAGE="${RUBY_IMAGE:-ruby:3.4}"
DRY_RUN="${DRY_RUN:-}"

if [ -z "$DRY_RUN" ] ; then
    : "${GEM_HOST_API_KEY:?set GEM_HOST_API_KEY to a key that can push without an OTP}"
fi

push="gem push /tmp/build/pkg/*.gem"
if [ -n "$DRY_RUN" ] ; then
    push="gem spec /tmp/build/pkg/*.gem name version files | head -20"
fi

# The working tree is mounted READ ONLY and copied inside, so bundler cannot
# leave a root-owned Gemfile.lock, .bundle or built .gem behind in it.
docker run --rm \
    -v "$PWD:/src:ro" \
    -e GEM_HOST_API_KEY="${GEM_HOST_API_KEY:-}" \
    "$RUBY_IMAGE" bash -euc "
        cp -R /src /tmp/build
        cd /tmp/build
        rm -rf .bundle vendor Gemfile.lock pkg
        bundle install
        bundle exec rake test
        mkdir -p pkg
        gem build vpndetection.gemspec -o pkg/vpndetection.gem
        ${push}
    "
