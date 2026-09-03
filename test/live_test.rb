# frozen_string_literal: true

# Hits the production API, so it is skipped unless asked for. The keyless daily
# allowance is per source address and CI shares one, which is reason enough not
# to spend it on every push.
#
#   VPNDETECTION_LIVE=1 bundle exec rake test

require_relative 'test_helper'

class LiveTest < Minitest::Test
  def setup
    skip 'set VPNDETECTION_LIVE=1 to run against the production API' unless ENV['VPNDETECTION_LIVE'] == '1'
    @client = VPNDetection::Client.new
  end

  def test_the_free_tier_answers_is_vpn_for_a_known_vpn_address
    result = @client.lookup('45.83.91.1')

    assert_equal true, result.is_vpn
    assert_equal false, result.bogon?
  end

  # The one assertion a stub cannot make honestly: without a key the tier-gated
  # members are ABSENT, and absent must not read as false.
  def test_a_tier_gated_member_is_absent_without_a_key
    result = @client.lookup('1.1.1.1')

    assert_equal false, result.is_vpn
    assert_nil result.is_hosting
    refute result.included?('is_hosting')
    assert_equal false, result.hosting?
  end
end
