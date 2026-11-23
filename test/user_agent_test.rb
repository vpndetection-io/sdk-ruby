# frozen_string_literal: true

require_relative 'test_helper'

# The user agent a lookup, `my_ip` or a batch entry sends, and what it does to
# the cache: an answer with one carries a verdict the plain answer does not, so
# it is cached and shared on the pair of address and agent.
class UserAgentTest < Minitest::Test
  include TestHelper

  GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
  CHROME = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36'

  # Answers every lookup with the agent it was sent, and a batch with each
  # entry's, so a test reads what reached the origin from the answer too.
  class Origin
    attr_reader :requests

    def initialize(delay: 0)
      @requests = []
      @lock = Mutex.new
      @server = TestServer.new(delay: delay) { |target, body| answer(target, body) }
    end

    def base_url
      @server.base_url
    end

    def stop
      @server.stop
    end

    # The batch bodies the origin was sent, parsed.
    def batches
      @requests.filter_map { |r| r[:body] if r[:path] == '/batch' }
    end

    # The single lookups, as [path, query].
    def lookups
      @requests.reject { |r| r[:path] == '/batch' }.map { |r| [r[:path], r[:query]] }
    end

    private

    def answer(target, body)
      path, query = target.split('?', 2)
      query = URI.decode_www_form(query.to_s).to_h
      if path == '/batch'
        sent = JSON.parse(body)
        record(path: path, body: sent)
        agents = sent['user_agents'] || {}
        results = sent['ips'].to_h { |ip| [ip, entry(ip, agents[ip])] }
        return [200, JSON.generate({ 'results' => results, 'errors' => {} })]
      end
      record(path: path, query: query)
      ip = path == '/myip' ? '8.8.8.8' : path[1..]
      [200, JSON.generate(entry(ip, query['user_agent']))]
    end

    def record(request)
      @lock.synchronize { @requests << request }
    end

    def entry(ip, agent)
      body = { 'ip' => ip, 'is_vpn' => false }
      body['user_agent'] = { 'agent' => agent[0, 40], 'kind' => 'bot', 'verdict' => 'verified' } unless agent.nil?
      body
    end
  end

  def setup
    @origin = Origin.new
  end

  def teardown
    @origin.stop
  end

  def client(**options)
    VPNDetection::Client.new(base_url: @origin.base_url, retries: 0, **options)
  end

  def test_a_lookup_sends_its_user_agent_as_the_query_parameter
    result = client.lookup('8.8.8.8', user_agent: GOOGLEBOT)

    assert_equal [['/8.8.8.8', { 'user_agent' => GOOGLEBOT }]], @origin.lookups
    assert_equal 'verified', result.user_agent['verdict']
    assert result.included?(:user_agent)
  end

  def test_my_ip_sends_its_user_agent_and_stays_uncached
    c = client
    result = c.my_ip(user_agent: GOOGLEBOT)
    c.my_ip(user_agent: GOOGLEBOT)
    c.my_ip

    assert_equal [['/myip', { 'user_agent' => GOOGLEBOT }], ['/myip', { 'user_agent' => GOOGLEBOT }], ['/myip', {}]],
                 @origin.lookups
    assert_equal 'verified', result.user_agent['verdict']
  end

  def test_an_empty_user_agent_is_none_and_a_long_one_is_sent_whole
    plain = client.lookup('8.8.8.8', user_agent: '')
    long = "#{GOOGLEBOT} #{'x' * 1100}"
    client.lookup('8.8.4.4', user_agent: long)

    assert_nil plain.user_agent
    refute plain.included?(:user_agent)
    assert_equal [['/8.8.8.8', {}], ['/8.8.4.4', { 'user_agent' => long }]], @origin.lookups
    assert_operator long.length, :>, 1024
  end

  def test_a_user_agent_that_is_not_a_string_is_refused_before_any_request
    c = client
    assert_raises(ArgumentError) { c.lookup('8.8.8.8', user_agent: 42) }
    assert_raises(ArgumentError) { c.my_ip(user_agent: :googlebot) }
    assert_raises(ArgumentError) { c.lookup_batch(['8.8.8.8'], user_agents: { '8.8.8.8' => 1 }) }
    assert_raises(ArgumentError) { c.lookup_batch(['8.8.8.8'], user_agents: [['8.8.8.8', GOOGLEBOT]]) }
    assert_empty @origin.requests
  end

  def test_a_bogon_carries_no_user_agent_and_makes_no_request
    result = client.lookup('10.0.0.1', user_agent: GOOGLEBOT)
    batch = client.lookup_batch(['10.0.0.2'], user_agents: { '10.0.0.2' => GOOGLEBOT })

    assert result.bogon?
    assert_nil result.user_agent
    refute result.included?(:user_agent)
    assert_nil batch['10.0.0.2'].user_agent
    assert_empty @origin.requests
  end

  # The address's plain answer, one agent's and another's are three entries:
  # only the same pair is a hit.
  def test_the_cache_hits_only_on_the_same_address_and_agent
    c = client
    plain = c.lookup('8.8.8.8')
    googlebot = c.lookup('8.8.8.8', user_agent: GOOGLEBOT)
    again = c.lookup('8.8.8.8', user_agent: GOOGLEBOT)
    chrome = c.lookup('8.8.8.8', user_agent: CHROME)
    plain_again = c.lookup('8.8.8.8')

    assert_equal [['/8.8.8.8', {}], ['/8.8.8.8', { 'user_agent' => GOOGLEBOT }],
                  ['/8.8.8.8', { 'user_agent' => CHROME }]], @origin.lookups
    assert_same googlebot, again
    assert_same plain, plain_again
    assert_nil plain.user_agent
    refute_equal googlebot.user_agent, chrome.user_agent
  end

  # N callers for each of three pairs on one address, against an origin that
  # holds every answer, so the calls genuinely overlap: one request per pair.
  def test_concurrent_misses_share_one_request_only_for_the_same_pair
    @origin.stop
    @origin = Origin.new(delay: 0.3)
    c = client
    agents = [nil, GOOGLEBOT, CHROME]
    threads = agents.flat_map do |agent|
      Array.new(8) { Thread.new { [agent, c.lookup('9.9.9.1', user_agent: agent)] } }
    end
    answers = threads.map(&:value)

    assert_equal 3, @origin.lookups.length, "one request per pair: #{@origin.lookups.inspect}"
    assert_equal [{}, { 'user_agent' => GOOGLEBOT }, { 'user_agent' => CHROME }].sort_by(&:to_s),
                 @origin.lookups.map(&:last).sort_by(&:to_s)
    answers.each do |agent, result|
      next assert_nil(result.user_agent, 'a plain caller gets the plain answer') if agent.nil?

      assert_equal agent[0, 40], result.user_agent['agent'], 'each caller gets its own pair'
    end
  end

  def test_a_batch_sends_user_agents_keyed_as_sent_and_only_where_an_entry_has_one
    plain = client.lookup_batch(['8.8.8.8', '1.1.1.1'])
    partial = client.lookup_batch(['8.8.4.4', '1.0.0.1', '9.9.9.9'],
                                  user_agents: { '8.8.4.4' => GOOGLEBOT, '1.0.0.1' => '' })

    refute @origin.batches[0].key?('user_agents'), 'no entry carries an agent, so no user_agents at all'
    assert_equal({ '8.8.4.4' => GOOGLEBOT }, @origin.batches[1]['user_agents'], 'only the entries carrying one')
    assert_nil plain['8.8.8.8'].user_agent
    assert_equal 'verified', partial['8.8.4.4'].user_agent['verdict']
    assert_nil partial['1.0.0.1'].user_agent
  end

  # The address is sent as the IPv4 it carries, so its agent is keyed by that.
  def test_a_batch_keys_a_mapped_addresss_agent_by_the_address_it_sends
    answers = client.lookup_batch(['::ffff:8.8.8.8', '2001:4860:4801:10::1'],
                                  user_agents: { '::ffff:8.8.8.8' => GOOGLEBOT, '2001:4860:4801:10::1' => CHROME })

    sent = @origin.batches.first
    assert_equal ['8.8.8.8', '2001:4860:4801:10::1'], sent['ips']
    assert_equal({ '8.8.8.8' => GOOGLEBOT, '2001:4860:4801:10::1' => CHROME }, sent['user_agents'])
    assert_equal 'verified', answers['::ffff:8.8.8.8'].user_agent['verdict']
  end

  # Each chunk carries its own entries' agents, and none where none of its
  # entries has one.
  def test_a_batch_sends_user_agents_per_chunk
    ips = Array.new(1001) { |i| "11.0.#{i / 256}.#{i % 256}" }
    client.lookup_batch(ips, user_agents: { ips.last => GOOGLEBOT }, concurrency: 1)

    first, second = @origin.batches
    assert_equal 1000, first['ips'].length
    refute first.key?('user_agents'), 'the first chunk carries no agent'
    assert_equal [ips.last], second['ips']
    assert_equal({ ips.last => GOOGLEBOT }, second['user_agents'])
  end

  def test_a_batchs_answers_are_cached_on_the_pair
    c = client
    c.lookup_batch(['8.8.8.8', '1.1.1.1'], user_agents: { '8.8.8.8' => GOOGLEBOT })
    c.lookup('8.8.8.8', user_agent: GOOGLEBOT)
    c.lookup('1.1.1.1')
    c.lookup('8.8.8.8')
    c.lookup_batch(['8.8.8.8', '1.1.1.1'], user_agents: { '1.1.1.1' => CHROME })

    assert_equal [['/8.8.8.8', {}]], @origin.lookups, 'only the plain 8.8.8.8 missed'
    assert_equal 2, @origin.batches.length
    assert_equal({ 'ips' => ['1.1.1.1'], 'user_agents' => { '1.1.1.1' => CHROME } }, @origin.batches.last)
  end

  # A batch boards the in-flight registry on the pair: it awaits a lookup of
  # the same address and agent, and sends an address another agent is fetching.
  def test_a_batch_shares_a_lookup_in_flight_only_for_the_same_pair
    @origin.stop
    @origin = Origin.new(delay: 0.3)
    c = client
    googlebot = Thread.new { c.lookup('9.9.9.2', user_agent: GOOGLEBOT) }
    sleep 0.1
    answers = c.lookup_batch(['9.9.9.2', '9.9.9.3'], user_agents: { '9.9.9.2' => GOOGLEBOT, '9.9.9.3' => GOOGLEBOT })

    assert_equal [['9.9.9.3']], @origin.batches.map { |b| b['ips'] }, 'the same pair in flight is not sent again'
    assert_same googlebot.value, answers['9.9.9.2']

    chrome = Thread.new { c.lookup('9.9.9.4', user_agent: CHROME) }
    sleep 0.1
    c.lookup_batch(['9.9.9.4'], user_agents: { '9.9.9.4' => GOOGLEBOT })
    chrome.join

    assert_equal({ 'ips' => ['9.9.9.4'], 'user_agents' => { '9.9.9.4' => GOOGLEBOT } }, @origin.batches.last,
                 'another agent in flight is no answer for this one')
  end

  # The generated request model, which the batch does not build its body with,
  # leaves out a map it was never given rather than serializing it as {}.
  def test_the_generated_batch_request_leaves_out_unset_user_agents
    refute VPNDetection::BatchLookupRequest.new(ips: ['8.8.8.8']).to_hash.key?(:user_agents)
  end
end
