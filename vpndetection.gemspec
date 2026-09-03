# frozen_string_literal: true

require_relative 'lib/vpndetection/version'

Gem::Specification.new do |spec|
  spec.name = 'vpndetection'
  spec.version = VPNDetection::VERSION
  spec.authors = ['Mslm Dev']
  spec.email = ['support@vpndetection.io']

  spec.summary = 'Official Ruby client library for the VPNDetection API.'
  spec.description = 'Query the VPNDetection API for anonymity detection including VPNs, ' \
                     'residential proxies, Tor nodes, hosting servers, CDNs and relays.'
  spec.homepage = 'https://vpndetection.io'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.1'

  spec.metadata = {
    'homepage_uri' => spec.homepage,
    'source_code_uri' => 'https://github.com/vpndetection-io/sdk-ruby',
    'bug_tracker_uri' => 'https://github.com/vpndetection-io/sdk-ruby/issues',
    'changelog_uri' => 'https://github.com/vpndetection-io/sdk-ruby/releases',
    'documentation_uri' => 'https://docs.vpndetection.io',
  }

  spec.files = Dir['lib/**/*.rb'] + %w[LICENSE README.md]
  spec.require_paths = ['lib']

  spec.add_dependency 'lru_redux', '~> 1.1'
  spec.add_dependency 'typhoeus', '~> 1.4'
end
