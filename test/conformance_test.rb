# frozen_string_literal: true

# Asserts the shared conformance corpus that every VPNDetection SDK asserts.
#
# The corpus is generated into testdata/ and is identical across languages, so a
# behaviour that drifts here fails here rather than surfacing as two client
# libraries quietly disagreeing about the same address.

require_relative 'test_helper'

class ConformanceTest < Minitest::Test
  include TestHelper

  def setup
    # Anything not stubbed raises instead of reaching the network, so a test
    # that claims no request was made cannot pass by accident.
    Typhoeus::Config.block_connection = true
  end

  def teardown
    Typhoeus::Config.block_connection = false
    Typhoeus::Expectation.clear
  end

  def test_bogon_matches_the_canonical_ranges
    CORPUS['isBogon'].each do |c|
      assert_equal c['expect'], VPNDetection.bogon?(c['ip']), "#{c['ip']} (#{c['why']})"
    end
  end

  def test_a_bogon_is_answered_locally_in_the_full_max_shape
    calls = stub_lookups({})
    result = VPNDetection::Client.new.lookup('10.0.0.1')

    assert result.bogon?
    assert_equal '10.0.0.1', result.ip
    CORPUS['bogonResponse']['flagsFalse'].each do |flag|
      assert_equal false, result.public_send(flag), "#{flag} must be present and false"
      assert result.included?(flag), "#{flag} must be present"
    end
    CORPUS['bogonResponse']['emptyObjects'].each do |detail|
      assert_equal({}, result.public_send(detail), "#{detail} must be present and empty")
    end
    assert_empty calls, 'a bogon must not reach the network'
  end

  def test_lookup_preserves_absent_versus_false_across_every_plan_shape
    CORPUS['lookup'].each do |c|
      body = c['body']
      stub_lookups(body['ip'] => { status: c['status'], body: body })
      result = VPNDetection::Client.new.lookup(body['ip'])

      assert_equal c['expect']['ip'], result.ip, c['name']
      assert_equal c['expect']['isBogon'], result.bogon?, c['name']

      (c['expect']['present'] || {}).each do |field, value|
        assert_equal value, result.public_send(field), "#{c['name']}: #{field} should be #{value}"
        assert result.included?(field), "#{c['name']}: #{field} should be included"
        assert_equal value, result.public_send(predicate_for(field)), "#{c['name']}: #{field} predicate"
      end
      (c['expect']['absent'] || []).each do |field|
        assert_nil result.public_send(field), "#{c['name']}: #{field} must be ABSENT, not false"
        refute result.included?(field), "#{c['name']}: #{field} must not be reported as included"
        next unless field.start_with?('is_')

        # A predicate coalesces absent to false rather than passing nil on, so
        # `if result.hosting?` is never a three-way question.
        assert_equal false, result.public_send(predicate_for(field)),
                     "#{c['name']}: #{predicate_for(field)} must answer false, never nil"
      end
      (c['expect']['emptyPresent'] || []).each do |field|
        assert_equal({}, result.public_send(field), "#{c['name']}: #{field} must be present and empty")
      end
      %w[vpn hosting dcproxy].each do |detail|
        next if c['expect'][detail].nil?

        assert_equal c['expect'][detail], result.public_send(detail), "#{c['name']}: #{detail}"
      end

      Typhoeus::Expectation.clear
    end
  end

  def predicate_for(field)
    "#{field.delete_prefix('is_')}?"
  end

  def test_errors_are_classified_by_range_and_by_retry_after
    CORPUS['errors'].each do |c|
      stub_lookups('1.1.1.1' => { status: c['status'], body: c['body'], headers: c['headers'] })
      # No retries, so a retryable error still surfaces rather than looping.
      client = VPNDetection::Client.new(retries: 0)

      error = assert_raises(VPNDetection::Error, c['name']) { client.lookup('1.1.1.1') }
      assert_equal c['expect']['kind'], error.kind.to_s, c['name']
      assert_equal c['expect']['retryable'], error.retryable?, "#{c['name']}: retryable"
      assert_equal c['expect']['message'], error.message, "#{c['name']}: message" if c['expect']['message']
      if c['expect']['retryAfterSeconds']
        assert_equal c['expect']['retryAfterSeconds'], error.retry_after_seconds, c['name']
      end

      Typhoeus::Expectation.clear
    end
  end

  def test_batch_dedupes_short_circuits_bogons_and_keys_by_address
    c = corpus_batch('dedup-bogon-and-order-free-keying')
    calls = stub_lookups(
      '1.1.1.1' => { body: { 'ip' => '1.1.1.1', 'is_vpn' => false } },
      '8.8.8.8' => { body: { 'ip' => '8.8.8.8', 'is_vpn' => false } },
    )
    got = VPNDetection::Client.new.lookup_batch(c['input'])

    assert_equal c['expect']['keys'], got.keys
    assert_equal c['expect']['httpRequests'], calls.length
    c['expect']['bogonKeys'].each do |ip|
      assert got[ip].bogon?, "#{ip} should be a local answer"
    end
  end

  def test_one_bad_address_does_not_lose_the_rest_of_the_batch
    c = corpus_batch('partial-failure-does-not-fail-the-batch')
    stub_lookups('1.1.1.1' => { body: { 'ip' => '1.1.1.1', 'is_vpn' => false } })
    got = VPNDetection::Client.new(retries: 0).lookup_batch(c['input'])

    assert_equal c['expect']['keys'], got.keys
    c['expect']['errorKeys'].each do |ip|
      assert_kind_of VPNDetection::Error, got[ip], "#{ip} should carry its error"
    end
    assert_equal false, got['1.1.1.1'].is_vpn, 'the good address still answered'
  end

  def test_a_cache_hit_issues_no_second_request
    c = corpus_batch('cache-hit-issues-no-second-request')
    calls = stub_lookups('1.1.1.1' => { body: { 'ip' => '1.1.1.1', 'is_vpn' => false } })
    client = VPNDetection::Client.new

    c['repeat'].times { client.lookup_batch(c['input']) }

    assert_equal c['expect']['httpRequests'], calls.length
  end

  def test_two_clients_never_share_a_cached_answer
    calls = stub_lookups('1.1.1.1' => { body: { 'ip' => '1.1.1.1', 'is_vpn' => false } })
    VPNDetection::Client.new(api_key: 'key-a').lookup('1.1.1.1')
    VPNDetection::Client.new(api_key: 'key-b').lookup('1.1.1.1')

    # Two keys can be on different plans and so entitled to different fields; a
    # shared cache would serve one of them the other's shape.
    assert_equal 2, calls.length
  end

  def test_caching_can_be_turned_off
    calls = stub_lookups('1.1.1.1' => { body: { 'ip' => '1.1.1.1', 'is_vpn' => false } })
    client = VPNDetection::Client.new(cache: false)
    client.lookup('1.1.1.1')
    client.lookup('1.1.1.1')

    assert_equal 2, calls.length
  end
end
