#!/bin/bash

# Runs the integration suite against the gem as PUBLISHED on RubyGems, which is
# the one thing the unit suite cannot check: that suite tests this working tree,
# so it stays green through a gemspec whose `files` list forgets half the
# library, a require path a consumer cannot resolve, or a tag that never landed.
#
#   ./scripts/run.sh
#
# Two conditions make the run meaningless rather than failing, and each one skips
# with a reason instead:
#
#   1. Nothing published satisfies the Gemfile's requirement. Before the first
#      release there is no artifact to test.
#   2. A tier's staging key is missing. The unauthenticated tests still run, and
#      each tier without a key skips from inside the suite, so the skip and its
#      reason land in the minitest output rather than in this script's preamble.
#
# A THIRD condition is a failure rather than a skip: a Gemfile pointing at local
# source. A suite run against the working tree passes every test and says
# nothing, so it is refused here and again from inside the suite.

set -euo pipefail

cd "$(dirname "$0")/.."

GEM="vpndetection"

function main() {
    local requirement published matching

    assertNoLocalSource
    requirement="$(requiredVersion)"
    published="$(publishedVersions)"
    matching="$(satisfying "$requirement" "$published")"

    if [ -z "$matching" ] ; then
        skip "no published ${GEM} satisfies '${requirement}', so there is no released artifact to test"
        return 0
    fi
    echo "==> ${GEM} '${requirement}' matches published ${matching}"

    reportTiers

    # Resolved afresh on every run. A kept lock file would pin whatever the first
    # run happened to pick, and the daily run would stop noticing new releases.
    rm -f Gemfile.lock
    bundle install --quiet
    bundle exec rake test
}

# Bundler's own parse of the Gemfile, so the requirement reads exactly as
# `bundle install` will read it, and a source other than RubyGems is caught
# before a single gem is downloaded.
function assertNoLocalSource() {
    ruby -rbundler -e '
        dsl = Bundler::Dsl.new
        dsl.eval_gemfile("Gemfile")
        dep = dsl.dependencies.find { |d| d.name == ARGV[0] } or
            abort("==> FAILED: the Gemfile does not require #{ARGV[0]} at all")
        exit 0 if dep.source.nil?

        abort("==> FAILED: #{ARGV[0]} is required from #{dep.source}, so this would test local source")
    ' "$GEM"
}

function requiredVersion() {
    ruby -rbundler -e '
        dsl = Bundler::Dsl.new
        dsl.eval_gemfile("Gemfile")
        puts dsl.dependencies.find { |d| d.name == ARGV[0] }.requirement.to_s
    ' "$GEM"
}

# Every version RubyGems will serve. This is the index `bundle install` itself
# resolves against, so the answer is exactly what an install would see, and a gem
# that has never been published answers with an empty list rather than an error.
function publishedVersions() {
    gem list --remote --exact --all "$GEM" 2>/dev/null |
        sed -n "s/^${GEM} (\(.*\))\$/\1/p" | tr -d ' '
}

# Gem::Requirement is RubyGems' own matcher, so `~> 1.0` excludes a 2.x and a
# prerelease exactly as an install would.
function satisfying() {
    ruby -e '
        requirement = Gem::Requirement.new(ARGV[0].split(","))
        versions = ARGV[1].split(",").reject(&:empty?).map { |v| Gem::Version.new(v) }
        puts versions.select { |v| requirement.satisfied_by?(v) }.sort.join(", ")
    ' "$1" "$2"
}

function reportTiers() {
    ruby -Ilib -rtiers -e '
        with, without = Tiers::RUNGS.partition { |rung| Tiers.skip_for(rung).nil? }
        puts "==> tiers with a key: #{with.map { |rung| rung[:tier] }.join(", ")}"
        unless without.empty?
            Tiers.notice("no staging key for #{without.map { |rung| rung[:tier] }.join(", ")}:" \
                         " those tiers are skipped")
        end
    '
}

function skip() {
    echo "==> SKIPPED: $1"
    notice "Integration suite skipped: $1"
}

# Surfaced on the workflow run itself, so a skip is visible without opening the
# log and reading to the end of it.
function notice() {
    if [ "${GITHUB_ACTIONS:-}" = "true" ] ; then
        echo "::notice title=Integration::$1"
    fi
}

main "$@"
