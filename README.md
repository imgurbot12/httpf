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

# useful if httpf is behind another proxy (only allow headers u trust)
[proxy]
trust_proxy_headers = false
trusted_headers = ['cf-connecting-ip', 'x-real-ip']

# permanant and cached blacklist/whitelist entries
[firewall]
blacklist = []
whitelist = ['127.0.0.1']
database  = 'httpf.db'

# nginx style matchers for denying/allowing access per ip
# https://www.digitalocean.com/community/tutorials/nginx-location-directive
[[controls]]
path  = '/example'
allow = ['127.0.0.1']
deny  = ['all']

```

2. Run httpf:

```bash
$ httpf
```

### Fail2Ban Setup

Declare a new Fail2ban Action via `/etc/fail2ban/action.d/httpf.conf`

```
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = httpf blacklist add <ip>
actionunban = httpf blacklist remove <ip>
```

Configure your jail of choice in `/etc/fail2ban/jail.d/`
and include: `action = httpf`
