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

      addr = addr.native if addr.ipv4_mapped?
      (addr.ipv4? ? v4 : v6).any? { |range| range.include?(addr) }
    end

    # The IPv4 address an IPv4-mapped IPv6 address (::ffff:a.b.c.d, in any
    # spelling) carries, dotted, and any other address as given. A server
    # listening on :: sees every IPv4 visitor in that form, which read whole is
    # inside ::ffff:0:0/96, so judging it whole would answer every such visitor
    # locally as a bogon. ::a.b.c.d is IPv4-compatible rather than mapped, and
    # stays IPv6: IPAddr#native alone would unwrap that too.
    def unmapped(ip)
      addr = ip.to_s.include?(':') ? parse(ip) : nil
      addr&.ipv4_mapped? ? addr.native.to_s : ip
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
