# [<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="28"/>](https://vpndetection.io/) VPNDetection Ruby Client Library

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

Requires Ruby 3.3 or newer.

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

### Your own address

```ruby
result = client.my_ip
result.ip   # => the address we saw this call come from
```

Same answer `lookup` would give for that address, and the same cost against your allowance. It is deliberately not cached: which address you are is the whole question, and a machine that moves between networks would otherwise be told where it used to be.

### Your plan and usage

```ruby
acct = client.my_entitlement
acct.plan.key          # => "max"
acct.usage.requests    # => 580
acct.usage.window_end  # => when the allowance resets
```

Usage counts against the anniversary of your subscription, not the calendar month and not the billing period, and it is the same number a lookup is gated on. `hard_limit` is `nil` on an uncapped plan, which is not the same as zero.

### Batch lookup

Look up as many addresses as you like at once. Bogons and cached answers are handled locally, and everything else goes to the batch endpoint in chunks of up to 1000 addresses, in parallel:

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

Results are keyed by address, in the order you first listed each one, so duplicates in your list collapse into a single entry and one address failing never loses the rest: it carries its error as its value, with the status the API would have given that address on its own.

How many chunks are in flight at once, how many times a failed chunk is retried, and how long each chunk's request may take are configurable per call:

```ruby
results = client.lookup_batch(many_ips, concurrency: 4, retries: 4, timeout: 5)
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

Note that `:rate_limited` and `:quota_exceeded` both arrive as HTTP 429 and are not the same thing. A rate limit is when the API faces extreme traffic bursts and so retrying later works; but a spent quota needs your allowance raised or the window to roll over. The library retries rate limits for you, but not if your quota is exceeded. It waits the `Retry-After` the API sent, or its own backoff from 250 ms when that's past about 24.8 days.

### Timeouts and retries

```ruby
client = VPNDetection::Client.new(timeout: 10, retries: 4)

result = client.lookup('45.83.91.1', timeout: 2, retries: 0)
```

`timeout` is in seconds and bounds each attempt, body included, so a call that is retried can take longer in total. It defaults to 30 seconds, and 0 means no bound; before 5.2.0 the default was 10, so pass `timeout: 10` to keep that bound. The client's values are defaults: `lookup`, `lookup_batch`, `my_ip` and `my_entitlement` each take `timeout:` and `retries:` for that call alone, and every `client.oauth` method and every `client.database` call that is not a transfer takes `timeout:` (from 5.3.0). A database download bounds only its connection with it, because a whole transfer can take minutes. A negative value, anything that isn't a number, and anything past 2147483.647 seconds (the longest curl holds) raise `ArgumentError` where you pass them, before any request.

### Database downloads

If your key carries the `db.download` scope, the licensed databases are available through `client.database`. A license covers a database FAMILY and a download names one of its versions, so the id comes from `versions`:

```ruby
family = client.database.list.first
id = family.versions.last.id

written = client.database.download(id, 'mmdb', './vpn_ip_extended_v1.mmdb')
url = client.database.download_url(id, 'mmdb')
bytes = client.database.download_bytes('cdn_ip_v1', 'csvgz')
```

`download` streams straight to disk, so nothing bigger than a chunk is ever held in memory whatever the database weighs, and it writes through a neighboring `.part` file so a transfer that dies half way leaves no truncated copy behind. `download_url` hands back the time-limited link and follows nothing, for when you want to run the transfer yourself. `download_bytes` holds the whole file in memory, and the catalog runs from `cdn_ip_v1` at 10 KB to `resproxy_ip_90d_v1` at 1.79 GB, so reach for `download` for anything you have not measured.

From 5.3.0, `list`, `metadata`, `checksums`, `downloads` and `download_url` each take `timeout:` in seconds for that call alone, overriding the client's for one attempt of it:

```ruby
catalog = client.database.list(timeout: 5)
sums = client.database.checksums(id, 'mmdb', timeout: 5)
```

`download` and `download_bytes` deliberately take no `timeout:` and raise `ArgumentError` if handed one, rather than accepting it and quietly doing nothing: a transfer runs to gigabytes and minutes, so any bound that suits a JSON call would abandon a healthy download. `download_url` does take one, because minting the link is an ordinary API request - it bounds that request, not whatever you do with the link afterwards.

### Sign in with OAuth (device flow)

A program running on a person's own machine can let them sign in with their browser and pick one of their API keys, instead of asking them to paste one.

```ruby
client = VPNDetection::Client.new
device = client.oauth.device_authorization('your-client-id', scope: 'account.read apikeys.read apikeys.reveal')
puts "Open #{device.verification_uri} and enter #{device.user_code}"

token = client.oauth.poll_device_token('your-client-id', device)
raise 'no API key was picked' if token.apikey.nil?

keyed = VPNDetection::Client.new(api_key: token.apikey)
```

`poll_device_token` raises `VPNDetection::OauthAccessDeniedError` when the person refuses and `VPNDetection::OauthExpiredTokenError` when the code expires first. Client IDs are issued on request from support@vpndetection.io, and `client.oauth.revoke('your-client-id', token.refresh_token)` signs the machine out.

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

[<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="64"/>](https://vpndetection.io/)

## License

This project is licensed under the [MIT License](LICENSE).
