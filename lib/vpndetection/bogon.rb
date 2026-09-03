# frozen_string_literal: true

require 'ipaddr'

module VPNDetection
  # Addresses that can never be VPN or proxy infrastructure, answered here
  # rather than on the network.
  module Bogon
    module_function

    # Whether an address is a bogon: private, loopback, link-local,
    # documentation, multicast or otherwise not routable on the public internet,
    # including the IPv6 equivalents and the 6to4 and Teredo ranges that wrap
    # them.
    def bogon?(ip)
      addr = parse(ip)
      return false if addr.nil?

      # An IPv4-mapped address stays in the v6 table, which is where the
      # canonical ranges put ::ffff:0:0/96. Unmapping it first would match it
      # against the v4 table and disagree with every other SDK.
      (addr.ipv4? ? v4 : v6).any? { |range| range.include?(addr) }
    end

    # The answer a bogon gets, in the full shape the API serves at its widest
    # plan: every flag present and false, every detail object present and empty.
    #
    # `is_bogon` marks it as computed rather than served. Note this is
    # deliberately the WIDEST shape regardless of your plan, so do not infer
    # which fields your plan includes from a bogon answer.
    def result(ip)
      raw = { 'ip' => ip, 'is_bogon' => true }
      Result::FLAGS.each { |flag| raw[flag] = false }
      Result::DETAILS.each { |detail| raw[detail] = {} }
      Result.new(raw, bogon: true)
    end

    # Parsed on first use rather than at load: a consumer that never looks an
    # address up should not pay for the table.
    def v4
      @v4 ||= Bogons::V4.map { |cidr| IPAddr.new(cidr) }.freeze
    end

    def v6
      @v6 ||= Bogons::V6.map { |cidr| IPAddr.new(cidr) }.freeze
    end

    def parse(ip)
      text = ip.to_s
      # IPAddr accepts a prefix, and "10.0.0.0/8" is not an address.
      return nil if text.include?('/')

      IPAddr.new(text)
    rescue IPAddr::Error
      nil
    end

    private_class_method :v4, :v6, :parse
  end
end
