# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 5.4.2 are described by their release commits.

## 5.5.2 - 2026-10-04

### Fixes

- Re-pin the spec to 2026.10.03: metadata needs no license ([`3abb622`](https://github.com/vpndetection-io/sdk-ruby/commit/3abb622bcf88bfa4f9b4baa2096e0a08a80f958b))

## 5.5.1 - 2026-09-29

### Fixes

- Judge an IPv4-mapped address as the IPv4 address it carries ([`7b4582d`](https://github.com/vpndetection-io/sdk-ruby/commit/7b4582d520904c38897c401e1bcba73b2817159f))
- Recognize 26 more reserved ranges as bogons, as the API does ([`1cb81f0`](https://github.com/vpndetection-io/sdk-ruby/commit/1cb81f00ecccfd96fb5085b6ab984a2c10db6342))

## 5.5.0 - 2026-09-27

### Features

- Re-pin the spec to 2026.09.26, adding client_id_metadata_document_supported ([`4d89157`](https://github.com/vpndetection-io/sdk-ruby/commit/4d89157da0770f8d1c4cca571c3309e247147e5e))

## 5.4.3 - 2026-09-26

### Fixes

- Share one request per address between concurrent misses ([`b2722c6`](https://github.com/vpndetection-io/sdk-ruby/commit/b2722c6c3cccb5d283295ddac1e22c663375dc72))

## 5.4.2 - 2026-09-24

### Fixes

- Refuse a timeout curl cannot hold, and cap every wait a server sets ([`8788688`](https://github.com/vpndetection-io/sdk-ruby/commit/87886880f25915e410fb16e32c7ee78c49708e2f))
