# frozen_string_literal: true

require_relative 'test_helper'

# The first and last day on the bot, ssh, smtp, web, dns_resolver and
# bittorrent details are `format: date` from spec 2026.11.23, so each is read
# as the others' days are: RFC 3339's full-date on a day that exists, kept as
# the string served. Through 5.20.0 each came back as served, "x" included.
class DayMembersTest < Minitest::Test
  include TestHelper

  # A web row carries every member the spec requires of one.
  WEB_ROW = {
    'port' => 443, 'tls_ok' => true, 'session_ok' => true, 'status_code' => 200, 'server' => 'nginx',
    'location' => '', 'title' => 'Welcome', 'cert_subject_cn' => 'example.com', 'cert_subject_o' => '',
    'cert_issuer_dn' => 'CN=R11, O=Let\'s Encrypt, C=US', 'cert_browser_trusted' => true,
    'tls_version' => 'TLS 1.3', 'first_seen' => '2026-08-04', 'last_seen' => '2026-11-15'
  }.freeze

  DAYS = { 'first_seen' => '2026-08-04', 'last_seen' => '2026-11-15' }.freeze

  # The answer every case below is cut from, each detail as the API serves it.
  WELL_FORMED = {
    'ip' => '1.1.1.1', 'is_vpn' => false,
    'is_bot' => true, 'bot' => { 'provider' => 'googlebot', 'verified' => true }.merge(DAYS),
    'is_ssh' => true, 'ssh' => { 'port' => 22, 'session_ok' => true }.merge(DAYS),
    'is_smtp' => true, 'smtp' => { 'port' => 25, 'session_ok' => true }.merge(DAYS),
    'is_web' => true, 'web' => [WEB_ROW],
    'is_dns_resolver' => true, 'dns_resolver' => { 'port' => 53, 'answer_correct' => true }.merge(DAYS),
    'is_bittorrent' => true,
    'bittorrent' => { 'verified' => true, 'last_reachable' => '', 'days_seen' => 3 }.merge(DAYS),
  }.freeze

  # RFC 3339's full-date is all a `date` member may hold.
  PROBE = [
    'x', 'tomorrow', 'monday', '2026-02-30', '2026-11-15T24:00:00Z', '2026-11-15T10:00:00Z', '2026-11-15+05',
    "2026-11-15\n", "٢٠٢٦-11-15"
  ].freeze

  def teardown
    Typhoeus::Expectation.clear
  end

  def test_bot_last_seen_takes_the_date_probe
    assert_equal '2026-11-15', answer_with('bot', 'last_seen', '2026-11-15').bot['last_seen']
    PROBE.each { |value| assert_refused('bot', 'last_seen', value) }
  end

  def test_each_day_member_refuses_a_malformed_value
    result = answer_with('bot', 'first_seen', '2026-08-04')
    %w[bot ssh smtp dns_resolver bittorrent].each do |detail|
      assert_equal DAYS, result.public_send(detail).slice(*DAYS.keys), detail
    end
    assert_equal DAYS, result.web.first.slice(*DAYS.keys)

    %w[bot ssh smtp web dns_resolver bittorrent].product(DAYS.keys).each do |detail, member|
      assert_refused(detail, member, 'x')
    end
  end

  private

  # The well-formed answer with one day member replaced, read by a client that
  # retries once.
  def answer_with(detail, member, value)
    stub_answer(body_with(detail, member, value))
    VPNDetection::Client.new(cache: false, retries: 1).lookup('1.1.1.1')
  end

  def assert_refused(detail, member, value)
    name = "#{detail}.#{member} of #{value.inspect}"
    sent = stub_answer(body_with(detail, member, value))
    error = assert_raises(VPNDetection::Error, name) do
      VPNDetection::Client.new(cache: false, retries: 1).lookup('1.1.1.1')
    end

    assert_equal :server_error, error.kind, "#{name}: #{error.message}"
    assert_equal 200, error.status, name
    assert_equal 2, sent.size, "#{name}: retried"
  ensure
    Typhoeus::Expectation.clear
  end

  def body_with(detail, member, value)
    body = JSON.parse(JSON.generate(WELL_FORMED))
    target = detail == 'web' ? body['web'].first : body[detail]
    target[member] = value
    body
  end

  def stub_answer(body)
    Typhoeus::Expectation.clear
    stub_lookups('1.1.1.1' => { body: body })
  end
end
