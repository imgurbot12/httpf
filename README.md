httpf
-----

Dead Simple HTTP Reverse Proxy Firewall.

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

1. Configure `httpf.yaml` to specify your listener, protected resolution,
and firewall options.

```yaml
---
listen:
  host: '127.0.0.1' # httpf listener host
  port: 8001        # httpf listener port

# protected resources that valid requests resolve to
resolve:
  - https://example.com

# useful if httpf is behind another proxy (only allow headers you trust)
proxy:
  trust_headers:   false
  trusted_headers: ['cf-connecting-ip']

# permanent and cached blacklist/whitelist entries
firewall:
  database:  'httpf.db'
  blacklist: []
  whitelist: ['127.0.0.1']

# block & ratelimit access rules
controls:

  - path: '/'
    match: ['1.2.3.4', '1.2.4.0/24']
    action:
      type: 'block'

  # javascript challenge to filter bots
  - path: '/'
    skip:  ['/robots.txt', '/api/']
    match: ['all']
    action:
      type: 'challenge'

  # nginx style matchers for denying/allowing access per ip
  # https://www.digitalocean.com/community/tutorials/nginx-location-directive
  - path: '= /limit'
    match: ['all']
    action:
      type:  'ratelimit'
      limit: 30 # requests/second
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
