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

  def test_a_lookup_without_a_key_answers_ip_and_is_vpn_at_the_least
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
      fields = tier_fields(fixture)
      puts "==> #{rung[:tier]}: #{fields.length} fields"
      next below = fixture if below.nil?

      (tier_fields(below) - fields).each do |field|
        flunk "#{rung[:tier]} drops #{field}, which #{below[:rung][:tier]} serves"
      end
      # Without this a run in which every key resolved to the same plan would
      # pass: identical sets satisfy containment in both directions.
      if rung[:widens]
        assert_operator fields.length, :>, tier_fields(below).length,
                        "#{rung[:tier]} is no wider than #{below[:rung][:tier]}"
      end
      below = fixture unless rung[:tier] == 'trial'
    end
  end

  # The fields a tier serves: trial_expired marks a free-plan key's answers, and
  # no other, so it is not one.
  def tier_fields(fixture)
    fixture[:raw].keys - ['trial_expired']
  end

  def test_a_free_plan_keys_answer_is_a_paid_one_or_unlimiteds_and_says_which
    reason = Tiers.skip_for(Tiers.trial)
    skip reason if reason
    raw = Staging.answer_for(Tiers.trial)[:raw]

    assert_includes [true, false], raw['trial_expired'], 'a free-plan key answers trial_expired'
    # The organization's first 100 lookups of the UTC day are answered in full,
    # and the rest as Unlimited's: which half a run sees depends on the day.
    assert_equal !raw['trial_expired'], raw.key?('is_hosting')
  end

  def test_a_free_plan_keys_batch_of_two_is_refused_as_a_bad_request_once
    reason = Tiers.skip_for(Tiers.trial)
    skip reason if reason
    client = Staging.client_for(Tiers.trial, cache: false)
    before = Staging.facts.length

    results = client.lookup_batch([Staging::PROBE, '8.8.8.8'])

    [Staging::PROBE, '8.8.8.8'].each do |ip|
      refused = results[ip]
      assert_kind_of VPNDetection::Error, refused, "#{ip}: a free-plan key's batch of two must fail"
      assert_equal [:bad_request, 402, false], [refused.kind, refused.status, refused.retryable?]
    end
    assert_equal ['/batch'], Staging.facts[before..].map(&:path), 'one request, never retried'
  end

  def test_a_free_plan_keys_batch_of_one_is_answered
    reason = Tiers.skip_for(Tiers.trial)
    skip reason if reason
    client = Staging.client_for(Tiers.trial, cache: false)

    answer = client.lookup_batch([Staging::PROBE])[Staging::PROBE]

    refute_kind_of VPNDetection::Error, answer, "a free-plan key's batch of one failed"
    assert_includes [true, false], answer.to_h['trial_expired'], 'the answer carries trial_expired'
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

  def test_a_batch_without_a_key_is_refused_once_and_its_bogon_still_answered
    client = Staging.client_for(Tiers.unauth, cache: false)
    before = Staging.facts.length

    results = client.lookup_batch([Staging::PROBE, '10.0.0.1'])

    assert results['10.0.0.1'].bogon?, '10.0.0.1 was not answered locally'
    refused = results[Staging::PROBE]
    assert_kind_of VPNDetection::Error, refused, 'a batch without a key must fail'
    assert_equal [:unauthorized, 401, false], [refused.kind, refused.status, refused.retryable?]
    assert_equal ['/batch'], Staging.facts[before..].map(&:path), 'one request, never retried'
  end

  def test_a_batch_collapses_duplicates_and_keeps_bogons_off_the_wire
    # A batch needs a paid plan, and starter is the cheapest.
    reason = Tiers.skip_for(Tiers.paid)
    skip reason if reason
    client = Staging.client_for(Tiers.paid, cache: false)
    before = Staging.facts.length

    results = client.lookup_batch([Staging::PROBE, '8.8.8.8', Staging::PROBE, '10.0.0.1', '8.8.8.8'])

    assert_equal [Staging::PROBE, '8.8.8.8', '10.0.0.1'], results.keys
    # Distinct paths and addresses rather than a call count, so a retry against a
    # wobbling staging cannot read as a failure to deduplicate.
    sent = Staging.facts[before..]
    assert_equal ['/batch'], sent.map(&:path).uniq
    assert(sent.all? { |fact| fact.tiers.include?('starter') }, 'the paid key never reached the wire')
    assert_equal [Staging::PROBE, '8.8.8.8'].sort, sent.flat_map(&:ips).uniq.sort
    assert results['10.0.0.1'].bogon?, '10.0.0.1 was not answered locally'
    [Staging::PROBE, '8.8.8.8'].each do |ip|
      refute_kind_of VPNDetection::Error, results[ip], "#{ip} failed"
    end
  end
end
