# frozen_string_literal: true

require_relative 'test_helper'
require 'minitest/mock'
require 'vpndetection/middleware'

# `allow_bots`: a crawler's User-Agent goes with its lookup, at most four an
# address, and a crawler whose operator vouches for the address is never refused.
# Every request comes from a public peer, since a bogon is answered locally with
# nothing sent.
class AllowBotsTest < Minitest::Test
  include TestHelper

  PEER = '66.249.66.1'
  GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
  CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' \
           'Chrome/151.0.0.0 Safari/537.36'
  CRAWLER_AGENTS = TestHelper::CORPUS.fetch('crawlerAgents')

  Req = Struct.new(:headers, :ip) do
    def initialize(headers = {}, ip = PEER)
      super(headers.transform_keys { |k| k.to_s.downcase }, ip)
    end
  end

  SELECTORS = VPNDetection::Middleware::Selectors.new do |request|
    VPNDetection::Middleware::RequestView.new(
      header: ->(name) { request.headers[name.downcase] },
      framework_ip: -> { request.ip }
    )
  end

  # Answers every lookup as a hosting bot address, with the verdict this test set
  # for the agent it was sent, or none, and the `bot` detail it set; and records
  # the query each one carried.
  def setup
    @verdict = 'verified'
    @bot = nil
    @queries = []
    @server = TestServer.new(delay: 0) do |target, _body|
      path, query = target.split('?', 2)
      query = URI.decode_www_form(query.to_s).to_h
      @queries << query
      body = { 'ip' => path[1..], 'is_vpn' => false, 'is_hosting' => true, 'is_bot' => true }
      body['bot'] = @bot if @bot
      agent = query['user_agent']
      body['user_agent'] = { 'agent' => 'Googlebot', 'kind' => 'bot', 'verdict' => @verdict } if agent && @verdict
      [200, JSON.generate(body)]
    end
  end

  def teardown
    @server.stop
  end

  def core(**options)
    client = VPNDetection::Client.new(base_url: @server.base_url, cache: false, retries: 0)
    VPNDetection::Middleware::Core.new(SELECTORS.default, SELECTORS.user_agent, client: client, **options)
  end

  def crawler
    Req.new({ 'User-Agent' => GOOGLEBOT })
  end

  def examplebot(number, ip = PEER)
    Req.new({ 'User-Agent' => "Mozilla/5.0 (compatible; Examplebot/#{number}.0)" }, ip)
  end

  def agent_sent(number)
    "Mozilla/5.0 (compatible; Examplebot/#{number}.0)"
  end

  def agents_sent
    @queries.map { |query| query['user_agent'] }
  end

  def test_the_requests_own_user_agent_reaches_the_origin
    lookup = core(allow_bots: true).evaluate(crawler)

    assert_equal [{ 'user_agent' => GOOGLEBOT }], @queries
    assert_equal 'verified', lookup.result.user_agent['verdict']
  end

  def test_off_by_default_sends_no_user_agent_and_lets_nothing_through
    @verdict = 'verified'
    lookup = core(block_condition: { is_hosting: true }).evaluate(crawler)

    assert_equal [{}], @queries
    assert lookup.blocked?
  end

  def test_an_absent_or_empty_header_sends_none
    subject = core(allow_bots: true)
    subject.evaluate(Req.new)
    subject.evaluate(Req.new({ 'User-Agent' => '' }))

    assert_equal [{}, {}], @queries
  end

  def test_a_verified_crawler_passes_a_condition_it_otherwise_meets
    lookup = core(allow_bots: true, block_condition: { is_hosting: true }).evaluate(crawler)

    refute lookup.blocked?, 'a verified crawler is never refused'
    assert_equal true, lookup.result.is_hosting, 'and its answer is still attached'
    assert_equal 'verified', lookup.result.user_agent['verdict']
  end

  def test_a_spoofed_or_not_bot_answer_is_refused
    %w[spoofed not_bot unverifiable].each do |verdict|
      @verdict = verdict
      lookup = core(allow_bots: true, block_condition: { is_hosting: true }).evaluate(crawler)

      assert lookup.blocked?, "#{verdict} is refused by the condition it meets"
      assert_equal verdict, lookup.result.user_agent['verdict']
    end
  end

  # `{ user_agent: { verdict: 'spoofed' } }` refuses a forged crawler and lets
  # a verified one and a browser through, with no warning of a missing member.
  def test_a_condition_naming_user_agent_works_with_it_on
    warnings = []
    subject = core(allow_bots: true, block_condition: { user_agent: { verdict: 'spoofed' } },
                   on_warn: ->(m) { warnings << m })
    @verdict = 'spoofed'
    assert subject.evaluate(crawler).blocked?
    @verdict = 'verified'
    refute subject.evaluate(crawler).blocked?

    assert_empty warnings
  end

  # A keyless client, or a free key past its trial, is never answered a
  # verdict: once per process, not once per request.
  def test_a_served_answer_without_a_verdict_warns_once_under_on_missing_field
    @verdict = nil
    warnings = []
    warned = core(allow_bots: true, block_condition: { is_hosting: true }, on_warn: ->(m) { warnings << m })
    2.times { assert warned.evaluate(crawler).blocked? }

    assert_equal 1, warnings.length
    assert_match(/no user_agent verdict/, warnings.first)

    quiet = []
    core(allow_bots: true, on_missing_field: :ignore, on_warn: ->(m) { quiet << m }).evaluate(crawler)
    assert_empty quiet

    strict = core(allow_bots: true, on_missing_field: :raise)
    assert_raises(ArgumentError) { strict.evaluate(crawler) }

    nothing_sent = []
    core(allow_bots: true, on_warn: ->(m) { nothing_sent << m }).evaluate(Req.new)
    assert_empty nothing_sent, 'no agent sent, so no verdict expected'
  end

  # Answered locally with no verdict: nothing is sent, nothing let through,
  # and only the bogon's own warning is given.
  def test_a_bogon_peer_sends_nothing_and_is_not_let_through
    warnings = []
    lookup = core(allow_bots: true, block_condition: [{ is_hosting: true }, { user_agent: { verdict: 'spoofed' } }],
                  on_warn: ->(m) { warnings << m }).evaluate(Req.new({ 'User-Agent' => GOOGLEBOT }, '10.0.0.1'))

    assert_empty @queries
    refute lookup.blocked?
    assert_nil lookup.result.user_agent
    assert_equal 1, warnings.length
    assert_match(/not a public address/, warnings.first)
  end

  def test_the_default_reader_takes_a_rack_style_requests_user_agent
    request = Struct.new(:user_agent, :ip).new(GOOGLEBOT, PEER)
    client = VPNDetection::Client.new(base_url: @server.base_url, cache: false, retries: 0)
    VPNDetection::Middleware::Core.new(->(r) { r.ip }, client: client, allow_bots: true).evaluate(request)

    assert_equal [{ 'user_agent' => GOOGLEBOT }], @queries
  end

  def test_only_an_agent_naming_a_crawler_is_sent_as_the_corpus_says
    refute_empty CRAWLER_AGENTS['crawlers']
    refute_empty CRAWLER_AGENTS['others']
    CRAWLER_AGENTS['crawlers'].each { |agent| assert VPNDetection::Middleware.names_crawler?(agent), agent }
    CRAWLER_AGENTS['others'].each { |agent| refute VPNDetection::Middleware.names_crawler?(agent), agent }
    CRAWLER_AGENTS['terms'].each do |term|
      assert VPNDetection::Middleware.names_crawler?("x #{term.upcase} y"), term
    end

    subject = core(allow_bots: true, block_condition: { is_bot: true })
    lookup = subject.evaluate(Req.new({ 'User-Agent' => CHROME }))

    assert_equal [nil], agents_sent, "a browser's agent stays off the lookup"
    assert lookup.blocked?
  end

  def test_one_address_is_looked_up_with_at_most_four_crawler_agents_and_none_passes_past_them
    assert_equal 4, VPNDetection::Middleware::MAX_AGENTS_PER_ADDRESS
    subject = core(allow_bots: true, block_condition: { is_bot: true })
    (1..4).each { |n| refute subject.evaluate(examplebot(n)).blocked?, "agent #{n}" }

    past = subject.evaluate(examplebot(5))
    assert past.blocked?, 'an agent past the bound is never let through as verified'
    assert_nil past.result.user_agent
    refute subject.evaluate(examplebot(1)).blocked?, 'a known agent is still sent'
    assert_equal [1, 2, 3, 4, nil, 1].map { |n| n && agent_sent(n) }, agents_sent

    other = subject.evaluate(examplebot(5, '66.249.66.2'))
    refute other.blocked?, 'each address has its own bound'
    assert_equal agent_sent(5), agents_sent.last
  end

  def test_past_the_bound_an_address_its_operator_vouches_for_still_passes
    @bot = { 'verified' => true }
    subject = core(allow_bots: true, block_condition: { is_bot: true })
    (1..5).each { |n| refute subject.evaluate(examplebot(n)).blocked?, "agent #{n}" }

    assert_nil agents_sent.last
    browser = subject.evaluate(Req.new({ 'User-Agent' => CHROME }))
    assert browser.blocked?, 'a browser on that address is judged as the condition says'
  end

  # A request that sent no agent has no verdict to lack, so a condition naming
  # `user_agent` is no plan gap for it, and `on_missing_field: :raise` does not
  # fail every browser. With it off the condition can never match, and says so.
  def test_a_condition_on_the_verdict_is_no_plan_gap_for_a_request_that_sent_no_agent
    @verdict = 'spoofed'
    forged = { user_agent: { verdict: 'spoofed' } }
    [{ 'User-Agent' => CHROME }, {}].each do |headers|
      @queries.clear
      warnings = []
      subject = core(allow_bots: true, block_condition: forged, on_missing_field: :raise,
                     on_warn: ->(m) { warnings << m })

      refute subject.evaluate(Req.new(headers)).blocked?, headers.inspect
      assert_equal [nil], agents_sent
      assert_empty warnings
    end

    @queries.clear
    subject = core(allow_bots: true, block_condition: forged, on_missing_field: :raise)
    (1..4).each { |n| subject.evaluate(examplebot(n)) }
    refute subject.evaluate(examplebot(5)).blocked?, 'past the bound, no gap either'
    assert_nil agents_sent.last

    warned = []
    core(block_condition: forged, on_warn: ->(m) { warned << m }).evaluate(Req.new)
    assert_equal 1, warned.length, 'off, a condition on the verdict can never match, and says so'
  end

  # The hour runs from an address's first agent: a fourth one, added late, does
  # not restart it.
  def test_an_address_forgets_its_agents_an_hour_after_its_first
    subject = core(allow_bots: true, block_condition: { is_bot: true })
    start = Time.now
    at = ->(seconds, &block) { Time.stub(:now, start + seconds, &block) }
    at.call(0) { (1..3).each { |n| subject.evaluate(examplebot(n)) } }
    at.call(3000) { subject.evaluate(examplebot(4)) }

    at.call(3599) { assert subject.evaluate(examplebot(5)).blocked?, 'still inside the first one\'s hour' }
    at.call(3601) { refute subject.evaluate(examplebot(5)).blocked?, 'forgotten, so a new agent is sent' }
  end
end
