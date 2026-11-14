# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 5.4.2 are described by their release commits.

## 5.15.0 - 2026-11-14

### Features

- Re-pin the spec to 2026.11.14: is_bogon on every answer, and provider_name beside each provider ([`2e70f5d`](https://github.com/vpndetection-io/sdk-ruby/commit/2e70f5d987131359d4b7737f98c00eb0737c980b))

## 5.14.2 - 2026-11-13

### Fixes

- End a device poll at its deadline with no request past it ([`1a00833`](https://github.com/vpndetection-io/sdk-ruby/commit/1a00833d2f3aa2665f6ed56cecaa71c8111f8f34))
- Re-pin the spec to 2026.11.12: plainer words on the 401 and the batch rate limit ([`e92f4e8`](https://github.com/vpndetection-io/sdk-ruby/commit/e92f4e8fa1ce6f10a945c6d14faef76924daea8f))
- Say that a batch request of one address is answered as its lookup ([`e396dc8`](https://github.com/vpndetection-io/sdk-ruby/commit/e396dc8180087b3db85e6e9cea912088fd1ea6ff))

## 5.14.1 - 2026-11-11

### Fixes

- Say the free plan's daily trial and Unlimited, the free plan, and re-pin the spec ([`9d8c0d0`](https://github.com/vpndetection-io/sdk-ruby/commit/9d8c0d0c933d382a84d3c7cc3843d77015b1466f))

## 5.14.0 - 2026-11-11

### Features

- Add trial_expired for a trial key's answers, and re-pin the spec ([`fb94fc0`](https://github.com/vpndetection-io/sdk-ruby/commit/fb94fc005d3d35a553582ac166ae4752d1b0e872))

## 5.13.2 - 2026-11-11

### Fixes

- Name the Unlimited tier and its terms, and re-pin the spec ([`0569a0b`](https://github.com/vpndetection-io/sdk-ruby/commit/0569a0bb2c8c13125ef7c61e1cccec20e2b37a61))

## 5.13.1 - 2026-11-11

### Fixes

- Re-pin the spec's 2026.11.11 rebuild: plainer words on lookups without a key ([`fb6654a`](https://github.com/vpndetection-io/sdk-ruby/commit/fb6654a2aceb1f71e60b844004ff06b46e91c663))

## 5.13.0 - 2026-11-11

### Features

- Re-pin the spec to 2026.11.11: a lookup without a key answers more ([`e1437ab`](https://github.com/vpndetection-io/sdk-ruby/commit/e1437abc527d672038245e930892b595b16aa44e))

## 5.12.0 - 2026-11-07

### Features

- Download the build a database.updated webhook names ([`c780d94`](https://github.com/vpndetection-io/sdk-ruby/commit/c780d94da3c6f6b607c99e43e3f202f37e0df4e3))

### Fixes

- Re-pin the spec to 2026.11.05: the download's build parameter ([`12d4559`](https://github.com/vpndetection-io/sdk-ruby/commit/12d45595c9d6e8d558ce281c10a35939b66b9661))
- Re-pin the spec to 2026.11.03: a proxy flag keeps its last values ([`2e1a26e`](https://github.com/vpndetection-io/sdk-ruby/commit/2e1a26ee648531766640982da609cdf2150a3754))

## 5.11.4 - 2026-11-03

### Fixes

- Refuse a concurrency that is not an Integer from 1, where it is set ([`27155a9`](https://github.com/vpndetection-io/sdk-ruby/commit/27155a9b3e4e7384203d676629d41dc9c782e1f5))

## 5.11.3 - 2026-10-31

### Fixes

- Refuse a retries that is not an Integer from 0, where it is set ([`9237c04`](https://github.com/vpndetection-io/sdk-ruby/commit/9237c046770a68c8b2a04abea5b5399e774f5af6))
- Read a database sample row only as an object ([`60e23a9`](https://github.com/vpndetection-io/sdk-ruby/commit/60e23a93327d6c0440b53e192cfbd90f4470233f))

## 5.11.2 - 2026-10-30

### Fixes

- Read a lowercase t or z in a date-time ([`08ac73d`](https://github.com/vpndetection-io/sdk-ruby/commit/08ac73d5d2475cba851d96e5604a72b3e51d53be))

## 5.11.1 - 2026-10-26

### Fixes

- Re-pin the spec to 2026.10.25: Retry-After on myip's 429 ([`a6a6933`](https://github.com/vpndetection-io/sdk-ruby/commit/a6a69335a8091ce386cf1a5d11961006351f8c36))

## 5.11.0 - 2026-10-22

### Features

- Add oauth.register, for RFC 7591 dynamic client registration ([`49ddcd4`](https://github.com/vpndetection-io/sdk-ruby/commit/49ddcd4923cfda3d7d4fcfe2df147016324dddbf))

### Fixes

- Send a key without the blanks around it, and refuse a control character ([`3411f58`](https://github.com/vpndetection-io/sdk-ruby/commit/3411f588343df3c624cc6d3fc52e5369b4429483))

## 5.10.1 - 2026-10-21

### Fixes

- Read a date only in its RFC 3339 form, on a real day ([`e71071e`](https://github.com/vpndetection-io/sdk-ruby/commit/e71071edddf97bcd879605a6ac0240d56b861b15))

## 5.10.0 - 2026-10-20

### Features

- Re-pin the spec to 2026.10.20: open on databases and downloads ([`fe61573`](https://github.com/vpndetection-io/sdk-ruby/commit/fe615737d18152a3456f4f101518b9a28dd3d430))
- Add location and asn to lookup results, a bogon's included ([`704d53c`](https://github.com/vpndetection-io/sdk-ruby/commit/704d53c101821c624381772887cb81ee5cfd633b))

## 5.9.1 - 2026-10-20

### Fixes

- Refuse a member of the wrong type, or a null the spec does not allow ([`a1fdbc8`](https://github.com/vpndetection-io/sdk-ruby/commit/a1fdbc8d39a9ed8b3b07b9876df1d8bf5a9f2dc3))

## 5.9.0 - 2026-10-19

### Features

- Re-pin the spec to 2026.10.19: num_ports and num_proxies in the pubproxy detail ([`fa10460`](https://github.com/vpndetection-io/sdk-ruby/commit/fa10460114f48c1e263b7b03df0bd3d78be2c4fa))

### Fixes

- Read a Retry-After date only when it names a real day ([`2c66615`](https://github.com/vpndetection-io/sdk-ruby/commit/2c666151b7d820d9ec86e03dfce385d21f2e9f64))

## 5.8.0 - 2026-10-18

### Features

- Re-pin the spec to 2026.10.18: is_pubproxy and the pubproxy detail ([`8e72755`](https://github.com/vpndetection-io/sdk-ruby/commit/8e72755c3d2e168f2a3cd721ec347539afd6bebb))

## 5.7.0 - 2026-10-17

### Features

- Re-pin the spec to 2026.10.16: dynamic client registration ([`96b4309`](https://github.com/vpndetection-io/sdk-ruby/commit/96b43097f1c85f69d0c048397397bf65ab5a71ab))

### Fixes

- Say the three proxy flags are Scale and above ([`3661797`](https://github.com/vpndetection-io/sdk-ruby/commit/3661797fc09c9b8678727784e966e1354c72fbde))

## 5.6.4 - 2026-10-16

### Fixes

- Re-pin the spec to 2026.10.15: descriptions in US spelling ([`e119c00`](https://github.com/vpndetection-io/sdk-ruby/commit/e119c005a5368d1efb71e51bec34db1530d8f7bc))

## 5.6.3 - 2026-10-10

### Fixes

- Re-pin the spec to 2026.10.09: rotating a key needs apikeys.reveal ([`5cbbe6e`](https://github.com/vpndetection-io/sdk-ruby/commit/5cbbe6ea1de8007f04944c92d203ea175845a3ad))

## 5.6.2 - 2026-10-08

### Fixes

- Retry a lookup, my_ip, my_entitlement or batch answer a call cannot read ([`043a0e4`](https://github.com/vpndetection-io/sdk-ruby/commit/043a0e4bd2688c06dfd607d0402ad99931291b7e))
- Carry the status when the download link answers 2xx, not its redirect ([`2d191d4`](https://github.com/vpndetection-io/sdk-ruby/commit/2d191d4ea51600ff0893c735491f03be802bcd3b))
- Read a Retry-After as digits or an HTTP date, and nothing else ([`1670ab8`](https://github.com/vpndetection-io/sdk-ruby/commit/1670ab84c3c49370eadafec439a976e2bab6239c))

## 5.6.1 - 2026-10-06

### Fixes

- Raise a 2xx that is not its answer as a retried server_error ([`431e0df`](https://github.com/vpndetection-io/sdk-ruby/commit/431e0df37f9c2b1ab738905fe6406072f73784b1))

## 5.6.0 - 2026-10-05

### Features

- Add the authorization code sign-in, with PKCE ([`669f9a3`](https://github.com/vpndetection-io/sdk-ruby/commit/669f9a3a8cb4f00644816091ac715928d9b1d8e5))

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
