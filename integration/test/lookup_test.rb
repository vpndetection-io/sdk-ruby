# frozen_string_literal: true

# The published gem looking addresses up against the staging API.
#
# Nothing here pins a field COUNT. The tiers are asserted as a RELATION, each one
# serving a superset of the tier below it, so a pricing change stays a pricing
# change instead of arriving as a red SDK build. What a served answer must
# satisfy on every tier: ip and is_vpn always; a present flag is a real boolean;
# a field a higher tier serves is ABSENT on a lower one rather than false; a
# populated detail object carries its documented keys; an empty one means its
# flag is false.

require_relative '../lib/staging'

class LookupTest < Minitest::Test
  include StagingAssertions

  def test_an_unauthenticated_lookup_answers_ip_and_is_vpn
    fixture = Staging.answer_for(Tiers.unauth)

    assert_equal Staging::PROBE, fixture[:raw]['ip']
    assert_includes [true, false], fixture[:raw]['is_vpn']
    assert_served_by_tier(fixture)
    puts "==> testing against #{Staging::BASE_URL}"
  end

  def test_a_key_reaches_the_wire_and_its_answer_keeps_its_shape
    Tiers::RUNGS.each do |rung|
      next if rung[:secret].nil?

      reason = Tiers.skip_for(rung)
      next Tiers.notice(reason) if reason

      assert_served_by_tier(Staging.answer_for(rung))
    end
  end

  def test_each_tier_serves_a_superset_of_the_tier_below
    skip Tiers.ladder_skip if Tiers.ladder_skip

    below = nil
    Tiers.observable.each do |rung|
      fixture = Staging.answer_for(rung)
      puts "==> #{rung[:tier]}: #{fixture[:raw].length} fields"
      next below = fixture if below.nil?

      (below[:raw].keys - fixture[:raw].keys).each do |field|
        flunk "#{rung[:tier]} drops #{field}, which #{below[:rung][:tier]} serves"
      end
      # Without this a run in which every key resolved to the same plan would
      # pass: identical sets satisfy containment in both directions.
      if rung[:widens]
        assert_operator fixture[:raw].length, :>, below[:raw].length,
                        "#{rung[:tier]} is no wider than #{below[:rung][:tier]}"
      end
      below = fixture
    end
  end

  # The one that matters most in Ruby, where nil and false are both falsy: a
  # field a higher tier serves must read as nil on a lower one, never false, or
  # "not in your plan" and "checked, and no" become the same answer.
  def test_a_field_a_higher_tier_serves_is_absent_on_a_lower_one_never_false
    skip Tiers.ladder_skip if Tiers.ladder_skip

    fixtures = Tiers.observable.map { |rung| Staging.answer_for(rung) }
    fixtures.each_with_index do |lower, index|
      higher = fixtures[(index + 1)..].flat_map { |f| f[:raw].keys }.uniq
      (higher - lower[:raw].keys).each do |field|
        next unless VPNDetection::Result::FLAGS.include?(field)

        tier = lower[:rung][:tier]
        assert_nil lower[:result].public_send(field), "#{field} is not in the #{tier} plan"
        refute lower[:result].included?(field), "#{tier} must not claim #{field} is included"
        assert_equal false, lower[:result].public_send("#{field.delete_prefix('is_')}?"),
                     "the #{tier} predicate for #{field} must answer false, never nil"
      end
      # The positive half: a field the wire carried must have reached the result,
      # which is what makes a served `false` survive.
      lower[:raw].keys.each do |field|
        next unless VPNDetection::Result::FLAGS.include?(field)

        refute_nil lower[:result].public_send(field),
                   "#{lower[:rung][:tier]} serves #{field} and the client dropped it"
      end
    end
  end

  def test_a_bogon_is_answered_without_touching_the_network
    client = Staging.client_for(Tiers.unauth)
    before = Staging.facts.length

    result = client.lookup('10.0.0.1')

    assert result.bogon?, 'a private address must be answered locally'
    refute result.is_vpn, 'a private address cannot be VPN infrastructure'
    assert VPNDetection.bogon?('10.0.0.1'), 'the module function must agree with the client'
    assert_equal before, Staging.facts.length, 'the bogon path reached the network'
    # Computed rather than served, so it carries every field whatever the plan.
    VPNDetection::Result::FLAGS.each do |flag|
      assert_equal false, result.public_send(flag), "#{flag} must be present and false on a bogon"
    end
    VPNDetection::Result::DETAILS.each do |name|
      assert_empty result.public_send(name), "#{name} must be present and EMPTY on a bogon"
    end
  end

  def test_a_batch_collapses_duplicates_and_keeps_bogons_off_the_wire
    client = Staging.client_for(Tiers.unauth, cache: false)
    before = Staging.facts.length

    results = client.lookup_batch([Staging::PROBE, '8.8.8.8', Staging::PROBE, '10.0.0.1', '8.8.8.8'])

    assert_equal [Staging::PROBE, '8.8.8.8', '10.0.0.1'], results.keys
    # Distinct paths rather than a call count, so a retry against a wobbling
    # staging cannot read as a failure to deduplicate.
    asked = Staging.facts[before..].map(&:path).uniq.sort
    assert_equal ["/#{Staging::PROBE}", '/8.8.8.8'].sort, asked
    assert results['10.0.0.1'].bogon?, '10.0.0.1 was not answered locally'
    [Staging::PROBE, '8.8.8.8'].each do |ip|
      refute_kind_of VPNDetection::Error, results[ip], "#{ip} failed"
    end
  end
end
