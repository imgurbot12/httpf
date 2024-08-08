httpf
-----

Dead Simple HTTP Reverse Proxy Firewall.

<!--
  DONE: implement expiration into cli and active db entry
  TODO: close connection if keep-alive is not specified? 
  TODO: document fail2ban implementation
  TODO: implement memory cache for sqlite entries?
  TODO: implement connection pooling for client address?
-->

### Features:
  - Blazingly Fast 🔥
  - Simple and Easy Reverse Proxy
  - Stupid Easy IP Whitelist/Blacklist
  - Simple Fail2Ban Integration

### Install

```bash
$ cargo install --path .
```

### Quick Start

1. Configure `httpf.toml` to specify your listener, protected resolution,
and firewall options.

```toml
[listen]
host = '127.0.0.1' # httpf listener host
port = 8001        # httpf listener port

[resolve]
host = 'example.com' # protected resource that valid requests resolve to
port = 80            # port of host to connect to

[firewall]
trust_proxy_headers = false # useful if httpf is behind another proxy
trusted_headers = ['cf-connecting-ip', 'x-real-ip'] # only allow headers u trust

# permanant and cached blacklist/whitelist entries
blacklist = []
whitelist = ['127.0.0.1']
```

2. Run httpf:

```bash
$ httpf --config ./config.toml
```
