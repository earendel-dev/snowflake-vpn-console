# Snowflake VPN Console

A small Windows automation tool for running Snowflake through a system VPN tunnel, with connection monitoring and automatic recovery. This is an independent project based on Tor Project Snowflake, not an official Tor Project application.

## Features

- Live connected-user count, relayed traffic and channel speed checks.
- Configurable capacity from 1 to 1000, starting at 10.
- Automatic discovery of supported active VPN tunnel adapters.
- IPv4 sockets pinned to the selected tunnel; IPv6 TCP and UDP blocked.
- Snowflake WebRTC/DTLS connectivity probes and periodic exit-country checks.
- Automatic recovery after VPN loss, with fresh connectivity checks before serving users.
- Red warnings for detected egress IP/country matches or unexpected WebRTC paths.
- In-memory operation: no application logs, statistics or VPN configuration files.

## Build and run

Requires Windows amd64 and Go 1.26.10 or newer.

```powershell
go build -o Snowflake-Console.exe ./console
.\Snowflake-Console.exe
```

Press **L** to change capacity, **Enter** to apply, **Esc** to cancel, or **Q** to stop and quit. Changing capacity restarts connections. Keep the console open for automatic recovery; no Windows startup entry is installed.

Channel checks run at random intervals of 40–60 seconds and transfer up to about 5 MB each, approximately 300–450 MB per hour. They use Google and Cloudflare. Exit checks use ipwho.is and Cloudflare, plus DNS and UDP/STUN probes. Small direct HTTPS geolocation requests are intentional diagnostic exceptions; Snowflake user traffic remains tunnel-bound.

## VPN and privacy limitations

**Enable your VPN client's kill switch.** This application is not a replacement for an operating-system firewall or the VPN's kill switch. A VPN client can apply DIRECT exceptions internally even while its tunnel stays up. Periodic IP-country checks cannot guarantee detection of every short-lived routing change. Geolocation can be inaccurate, unavailable or rate-limited; matching countries alone do not prove a leak. No warning is not proof that all checks succeeded.

Unsupported adapters and browser-only proxy modes are rejected. Missing NAT connectivity blocks worker startup. Unavailable external geolocation services do not block ordinary startup, but recovery from a detected country/IP violation requires a successful recheck. IPv6 is blocked, not tested as an active VPN transport. Tests do not disconnect the user's live VPN.

## Validation

```powershell
go test ./console
```

Tests cover tunnel selection, socket pinning, IPv6 blocking, traffic accounting, warnings and recovery decisions. They do not constitute a comprehensive security audit.

## Upstream and license

Includes modified Snowflake components from [Tor Project Snowflake](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake), based on commit `195cdf3d`. Original copyright notices and licensing are retained in [LICENSE](LICENSE). Changes include the console interface, raw traffic events, selected ICE path events, interface-pinned networking and recovery controls.
