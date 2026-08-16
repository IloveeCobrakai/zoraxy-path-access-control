# Path Access Control

[![Test and release](https://github.com/IloveeCobrakai/zoraxy-path-access-control/actions/workflows/release.yaml/badge.svg)](https://github.com/IloveeCobrakai/zoraxy-path-access-control/actions/workflows/release.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Path Access Control is a Zoraxy router plugin that applies an existing Zoraxy
IP/CIDR access rule to selected URL paths. It keeps a host public while
protecting sensitive areas such as `https://example.com/admin/*`.

![Path Access Control icon](icon.png)

## Features

- Selects existing HTTP proxy hosts and Zoraxy access rules in the plugin UI.
- Supports exact paths and Go-style glob patterns such as `/admin/*`.
- Treats `/admin/*` as the whole subtree, including `/admin` and nested paths.
- Evaluates rules from top to bottom; the first host/path match wins.
- Reuses enabled IPv4/IPv6, CIDR and IPv4 wildcard blacklist/whitelist entries.
- Optionally permits loopback and private addresses when the selected Zoraxy
  whitelist enables that setting.
- Automatically creates the `path-access-control` plugin routing group and adds
  the tag to hosts used by a saved rule.
- Fails closed with HTTP 503 when access-rule data or a configured rule is
  unavailable, and with HTTP 403 when access is denied.

## Requirements

- A Zoraxy version with router plugins, dynamic capture and the plugin API.
- Go 1.25 or newer to build from source (as declared in `go.mod`).
- At least one HTTP proxy host and one Zoraxy access rule.

## Install

Download the binary for your platform from the
[latest release](https://github.com/kianby/zoraxy-path-access-control/releases/latest)
and rename it to `path-access-control` (`path-access-control.exe` on Windows).
Place the binary and `icon.png` together in a directory scanned by Zoraxy's
plugin manager.

## Build from source

From this directory:

```sh
go test ./...
go build -trimpath -ldflags="-s -w" -o path-access-control .
```

Place the following files in a directory scanned by Zoraxy's plugin manager:

```text
path-access-control
icon.png
```

Enable **Path Access Control** in Zoraxy. Open its UI, select an HTTP proxy host,
enter a path pattern, select an access rule and choose **Add Rule**. Saving the
first rule for a host assigns the required routing tag automatically.

The plugin stores configuration in `path_access_rules.json` in its working
directory. The file is written atomically with owner-only permissions. Back it
up before moving or replacing the plugin directory.

## Path matching

Patterns use Go's slash-aware `path.Match` syntax:

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `/admin` | `/admin` | `/admin/` |
| `/admin/*` | `/admin`, `/admin/users`, `/admin/a/b` | `/administrator` |
| `/users/?` | `/users/a` | `/users/alice` |

Matching ignores a host's case, port and final DNS dot. Query strings are not
part of matching. Both the decoded URL path and its dot-segment-cleaned form are
checked to prevent paths such as `/public/../admin` from bypassing protection.

## Access-rule behavior and limitations

The plugin reads access rules through Zoraxy's authenticated, explicitly
permitted plugin API. A background worker refreshes them every 20 seconds.
Previously loaded data remains usable briefly during an outage, but data older
than 60 seconds fails closed. Allowed traffic stays in Zoraxy's normal proxy
pipeline; only denied or fail-closed requests are captured.

Country rules cannot currently be evaluated because the public plugin API does
not expose Zoraxy's GeoIP resolver. A selected rule with an enabled, non-empty
country blacklist or whitelist therefore denies matching paths instead of
silently exposing them.

`TrustProxyHeadersOnly` also cannot be reproduced safely because the public API
does not expose Zoraxy's trusted-proxy list. The plugin consequently evaluates
the direct peer address from Zoraxy's sniff payload and never trusts forwarded
IP headers. If Zoraxy is behind another reverse proxy, verify this behavior in
your deployment before relying on an IP whitelist.

Removing all rules does not remove the routing tag already assigned to a host;
the plugin simply skips all requests. Remove the `path-access-control` tag in
Zoraxy manually if it is no longer needed.

## Security notes

- The HTTP server listens only on `127.0.0.1`.
- Rule payloads and Zoraxy API responses are size-limited.
- Configuration writes are atomic and use mode `0600`.
- The short-lived handoff cache is bounded to prevent unbounded memory growth.
- The forbidden page has no third-party assets, tracking or network requests.
- Invalid/missing rules and temporary API failures fail closed.

## Performance design

The request path does not perform file or Zoraxy API I/O. Rules are compiled
into immutable, host-indexed snapshots and published atomically, so concurrent
requests read them without a mutex. IP addresses, CIDRs and IPv4 wildcards are
also parsed once during refresh instead of once per request. The short-lived
sniff-to-capture store is split into 64 independently locked shards and bounded
to 4,096 entries.

HTTP connections to Zoraxy's local plugin API are pooled, refresh attempts are
coalesced, and retry throttling prevents an API outage from creating a request
storm. The plugin HTTP server has explicit header, read, write and idle
timeouts.

Keep Zoraxy's management interface private and protect the plugin directory and
API key with the same care as the main Zoraxy installation.

## Troubleshooting

- **A path is still public:** confirm the plugin is enabled and the proxy host
  has the `path-access-control` tag. Check host spelling and rule order.
- **HTTP 503:** the selected rule may have been removed, or Zoraxy's plugin API
  may be unavailable. Reopen the UI and save a valid rule.
- **All requests receive HTTP 403:** the selected access rule may contain a
  country entry, which intentionally fails closed as described above.
- **Changes appear delayed:** access-rule changes can take up to 20 seconds to
  leave the plugin cache.

## Releases

The GitHub Actions workflow runs formatting checks, `go vet`, tests and the Go
race detector for pushes and pull requests. Tags matching `v*` additionally
produce stripped Linux and Windows binaries plus `SHA256SUMS`, then publish a
GitHub release. For example:

```sh
git tag v1.0.0
git push origin v1.0.0
```

## License

Licensed under the [MIT License](LICENSE).
