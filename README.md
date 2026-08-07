# Ligolo-MP : pivoting like a VPN, now with friends!

![Ligolo-MP Logo](doc/logo.png)

[![Release](https://github.com/ttpreport/ligolo-mp/actions/workflows/release.yml/badge.svg)](https://github.com/ttpreport/ligolo-mp/actions/workflows/release.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/ttpreport/ligolo-mp/v2)](https://goreportcard.com/report/github.com/ttpreport/ligolo-mp/v2) [![GPLv3](https://img.shields.io/badge/License-GPLv3-brightgreen.svg)](https://www.gnu.org/licenses/gpl-3.0)

**Ligolo-MP** is an advanced version of Ligolo-ng, with client-server architecture, enabling pentesters to play with multiple concurrent tunnels collaboratively. It manages all your TUNs automatically, while also providing a clean GUI to track everything.

![Ligolo-MP Dashboard](doc/dashboard-1.png)

## Features

- Multiplayer
- Automatic TUN management
- Auto-restoring routing
- Unlimited concurrent relays
- SOCKS and HTTP proxy support (including SSPI/SPNEGO authentication)
- Cross-platform agent compatible with Linux/FreeBSD/MacOS/Windows 7+
- Routing to the loopback of target machine (no more port forwarding)
- Listeners are independent redirectors
- Dynamic mTLS-enabled agent binaries generation with obfuscation option
- Simplified certificate management
- Friendly terminal-based GUI
- Bind agent mode — agent listens, server connects (reverse TCP direction)
- PKI rotation — regenerate all certificates with a single flag

## Server Usage

```
ligolo-mp [options]

  -agent-addr string
        listening address (default "0.0.0.0:11601")
  -daemon
        enable daemon mode
  -insecure-agents
        Disable certificate verification for agents (insecure!)
  -max-connection int
        per tunnel connection pool size (default 1024)
  -max-inflight int
        max inflight TCP connections (default 4096)
  -operator-addr string
        Address for operators connections (default "0.0.0.0:58008")
  -v    enable verbose mode
  -version
        print version
```

## Client Usage

```
ligolo-mp-client [options]

  -version
        Print version 
  -v    Enable verbose logging
```

## Agent Binary Usage

```
agent [options]

  -bind string
        Listen for server connections on this address (bind mode)
        Example: -bind 0.0.0.0:4444
  -server string
        Override the embedded server address
        Example: -server 1.2.3.4:11601
  -insecure
        Disable TLS certificate verification
```
### PowerShell Agent Usage

1. **Export certs** (run on the Ligolo-MP server):

```bash
bash artifacts/ps_agent/export-agent-certs.sh ./certs
```

2. **Copy to the Windows target**: `ca.pem` and `agent.pfx` from the `certs/` directory.

3. **Run the agent**:

```powershell
# Reverse Connection (agent connects to server)
.\agent.ps1 -Server 10.0.0.5:11601 -CACertFile ca.pem -PfxFile agent.pfx

# Bind Connection (agent listens, server connects via "Connect Bind Agent")
.\agent.ps1 -Bind 0.0.0.0:4444 -CACertFile ca.pem -PfxFile agent.pfx
```

## Bind Agent Mode

In standard mode the agent dials the server. In bind mode the roles are reversed — the agent listens and the server connects to it. This is useful when the target cannot reach the server directly.

**On the target machine:**
```
./agent -bind 192.168.1.10:4444
```

**From the server TUI (admin only):**

Press `Ctrl+B` in the dashboard, enter the agent's address (`192.168.1.10:4444`), and connect.


## Documentation

Please visit the [Wiki](https://github.com/ttpreport/ligolo-mp/wiki) for up-to-date information
