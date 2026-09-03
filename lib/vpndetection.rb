# frozen_string_literal: true

require 'vpndetection/version'

# The wire layer, generated from spec/openapi.yaml by scripts/generate.sh.
# Models are loaded by glob because the set of them is the generator's to
# decide; they subclass ApiModelBase and so must follow it.
require 'vpndetection/api_client'
require 'vpndetection/api_error'
require 'vpndetection/api_model_base'
require 'vpndetection/configuration'
Dir[File.join(__dir__, 'vpndetection', 'models', '*.rb')].sort.each { |model| require model }
Dir[File.join(__dir__, 'vpndetection', 'api', '*.rb')].sort.each { |api| require api }

require 'vpndetection/bogons'
require 'vpndetection/errors'
require 'vpndetection/result'
require 'vpndetection/bogon'
require 'vpndetection/cache'
require 'vpndetection/retries'
require 'vpndetection/transport'
require 'vpndetection/database'
require 'vpndetection/client'

# The official Ruby client library for the VPNDetection API.
#
#   client = VPNDetection::Client.new
#   client.lookup('45.83.91.1').is_vpn   # => true
module VPNDetection
  # Whether an address is a bogon: private, loopback, link-local, documentation,
  # multicast or otherwise not routable on the public internet, including the
  # IPv6 equivalents and the 6to4 and Teredo ranges that wrap them.
  #
  # These can never be VPN or proxy infrastructure, so a client answers them
  # itself and they never cost a request. The same predicate is on the client,
  # which is how the README teaches it.
  def self.bogon?(ip)
    Bogon.bogon?(ip)
  end
end
