# [<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" width="24"/>](https://vpndetection.io/) VPNDetection Ruby Client Library

[![gem](https://img.shields.io/gem/v/vpndetection.svg)](https://rubygems.org/gems/vpndetection)
[![license](https://img.shields.io/github/license/vpndetection-io/sdk-ruby.svg)](LICENSE)

The official Ruby client library for the [VPNDetection](https://vpndetection.io) API.

The library helps you query VPNDetection's APIs for anonymity detection including VPNs, residential proxies, Tor nodes, hosting servers, CDNs, relays and more.

## Getting Started

```bash
gem install vpndetection
```

Or add it to your Gemfile:

```ruby
gem 'vpndetection'
```

Requires Ruby 3.1 or newer.

## Usage

**No API key needed to start.** The free tier answers `ip` and `is_vpn`, and allows 1000 requests per day per source address.

```ruby
require 'vpndetection'

client = VPNDetection::Client.new

result = client.lookup('45.83.91.1')
result.is_vpn   # => true
```

### With an API key

An API key raises your quota, and raises your features on a paid plan. Create one in the [console](https://app.vpndetection.io), then pass it in:

```ruby
client = VPNDetection::Client.new(api_key: ENV['VPNDETECTION_API_KEY'])

result = client.lookup('45.83.91.1')
result.is_vpn               # => true
result.vpn['provider']      # => "mullvad"
result.is_hosting           # => true
result.hosting['provider']  # => "M247"
```

### Batch lookup

You can do batch lookups with a list, which parallelizes requests for you efficiently:

```ruby
results = client.lookup_batch(['45.83.91.1', '8.8.8.8', '1.1.1.1'])

results.each do |ip, result|
  if result.is_a?(VPNDetection::Error)
    warn "#{ip}: #{result.message}"
    next
  end
  puts "#{ip}: #{result.is_vpn}"
end
```

Results are keyed by address, so duplicates in your list collapse into a single request and one address failing never loses the rest.

Concurrency and other variables are configurable per-call:

```ruby
results = client.lookup_batch(many_ips, concurrency: 32, retries: 4)
```

### Caching

Answers are cached by default, so repeat lookups of the same address are free:

```ruby
client = VPNDetection::Client.new

result = client.lookup('45.83.91.1')
result.is_vpn    # => true, API request

result2 = client.lookup('45.83.91.1')
result2.is_vpn   # => true, no API request, result was cached
```

You can change the default cache variables (max size, TTL in seconds) on initialization, or even disable it:

```ruby
client = VPNDetection::Client.new(cache_max_size: 50_000, cache_ttl: 6 * 60 * 60)
client_no_cache = VPNDetection::Client.new(cache: false)
```

### Private and reserved addresses

Private, loopback, link-local, documentation and multicast addresses (and their IPv6 equivalents, including the 6to4 and Teredo ranges) can never be VPN or proxy infrastructure. The library answers them locally, so they cost no request and no quota:

```ruby
result = client.lookup('192.168.1.1')
result.bogon?    # => true, this answer was computed rather than served
result.is_vpn    # => false
```

The check is available on the client, which is handy when your inputs are addresses anyway:

```ruby
client.bogon?('10.0.0.1')   # => true
client.bogon?('8.8.8.8')    # => false
```

It is also on the module itself, if you want it without a client:

```ruby
VPNDetection.bogon?('10.0.0.1')   # => true
```

### Errors

Failures raise a `VPNDetection::Error` carrying a `kind` and a `retryable?` flag:

```ruby
begin
  client.lookup('1.1.1.1')
rescue VPNDetection::Error => e
  warn "#{e.kind} #{e.retryable?}: #{e.message}"
end
```

`kind` is one of `:bad_request`, `:unauthorized`, `:forbidden`, `:rate_limited`, `:quota_exceeded`, `:server_error` or `:network`.

Note that `:rate_limited` and `:quota_exceeded` both arrive as HTTP 429 and are not the same thing. A rate limit is when the API faces extreme traffic bursts and so retrying later works; but a spent quota needs your allowance raised or the window to roll over. The library retries rate limits for you, but not if your quota is exceeded.

### Database downloads

If your key carries the `db.download` scope, the licensed datasets are available through `client.database`:

```ruby
datasets = client.database.list
url = client.database.download_url('vpn_ip_extended_v1', 'mmdb')
```

`download_url` returns a time-limited link rather than the bytes, so you choose how to transfer a file that can run to gigabytes.

### Absent is not false

Every field beyond `ip` and `is_vpn` is present when your plan includes it and `nil` when it does not. `nil` means "not in your plan"; `false` means "we checked, and no".

```ruby
result.hosting?                 # false when absent, for when you only want the flag
result.included?(:is_hosting)   # whether your plan carries the field at all
```

## Other Libraries

There are official VPNDetection client libraries available for many languages including PHP, Python, Go, Java, Ruby, and many popular frameworks such as Django, Rails, and Laravel. See our GitHub at https://github.com/vpndetection-io for more.

## About VPNDetection

VPN Detection API: Accurate anonymity detection identifying VPNs, residential proxies, hosting servers, Tor nodes, CDNs, relays and more.

[<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" width="96"/>](https://vpndetection.io/)

## License

This project is licensed under the [MIT License](LICENSE).
