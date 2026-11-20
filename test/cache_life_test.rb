# frozen_string_literal: true

# A spent trial's or a reached cap's answer ends with the trial's renewal or a
# raised cap, so it is cached for a minute at most rather than for the client's TTL.

require_relative 'test_helper'

class CacheLifeTest < Minitest::Test
  include TestHelper

  ROUTES = {
    '45.83.91.1' => { body: { 'ip' => '45.83.91.1', 'is_vpn' => false } },
    '45.83.91.2' => { body: { 'ip' => '45.83.91.2', 'is_vpn' => false, 'trial_expired' => false, 'cap_reached' => false } },
    '45.83.91.3' => { body: { 'ip' => '45.83.91.3', 'is_vpn' => false, 'trial_expired' => true } },
    '45.83.91.4' => { body: { 'ip' => '45.83.91.4', 'is_vpn' => false, 'cap_reached' => true } },
  }.freeze

  CASES = [
    ['45.83.91.1', 3600, 3600],
    ['45.83.91.2', 3600, 3600],
    ['45.83.91.3', 3600, 60],
    ['45.83.91.4', 3600, 60],
    ['45.83.91.3', 5, 5],
    ['45.83.91.4', 5, 5],
    ['45.83.91.1', 5, 5],
  ].freeze

  def teardown
    Typhoeus::Expectation.clear
  end

  def test_each_looked_up_answer_is_cached_as_long_as_its_flags_allow
    assert_lives { |client, ip| client.lookup(ip) }
  end

  def test_each_batch_entry_is_cached_as_long_as_its_flags_allow
    assert_lives { |client, ip| client.lookup_batch([ip, '45.83.91.1']) }
  end

  def test_a_reduced_answer_is_still_cached_so_a_repeat_sends_nothing
    calls = stub_lookups(ROUTES)
    client = VPNDetection::Client.new

    client.lookup('45.83.91.3')
    again = client.lookup('45.83.91.3')

    assert_equal true, again.trial_expired
    assert_equal 1, calls.length
  end

  private

  def assert_lives
    stub_lookups(ROUTES)
    CASES.each do |ip, ttl, want|
      client = VPNDetection::Client.new(cache_ttl: ttl)
      before = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      yield client, ip
      after = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      expires = client.instance_variable_get(:@cache).expiry(ip)

      refute_nil expires, "#{ip} under a #{ttl} s TTL was not cached"
      assert_operator expires, :>=, before + want, "#{ip} under a #{ttl} s TTL"
      assert_operator expires, :<=, after + want, "#{ip} under a #{ttl} s TTL"
    end
  end
end
