<div align="center">

<img src="docs/images/drm-logo.png" alt="Docker Router Manager logo" width="110">

# Docker Router Manager

### Docker networking, routing, firewall and WireGuard management from one web interface

**Version 0.9.9**

![Version](https://img.shields.io/badge/version-0.9.9-2f80ff)
![Docker](https://img.shields.io/badge/Docker-supported-2496ED?logo=docker&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-host-FCC624?logo=linux&logoColor=black)
![WireGuard](https://img.shields.io/badge/WireGuard-supported-88171A?logo=wireguard&logoColor=white)
![License](https://img.shields.io/badge/license-GPL--3.0-blue)

</div>

---

## Overview

**Docker Router Manager (DRM)** is a web-based network management interface for Docker hosts. It combines Docker network visibility with host-level routing, firewall policy management, interactive topology visualization and native WireGuard configuration.

DRM is designed for environments where Docker is more than an application runtime and the Linux host also acts as a network gateway between containers, VPN clients, LANs and other routed networks.

<img src="docs/images/dashboard.png" alt="Docker Router Manager dashboard">

## Highlights

- **Live Docker overview** — networks, containers, endpoints and published ports.
- **Real-time container traffic** — RX/TX rates and cumulative traffic counters.
- **Interactive topology** — Docker networks, containers, published ports and external paths in one diagram.
- **Firewall Engine** — host-level Docker traffic policy using `iptables` and the `DOCKER-USER` path.
- **Published-port filtering** — control access to exposed Docker services by source CIDR.
- **Dual-stack Routing Engine** — view IPv4/IPv6 routing tables, manage static routes and IPv4/IPv6 forwarding.
- **Native dual-stack WireGuard management** — IPv4/IPv6 interfaces, peers, access policies, routes, DNS, client configuration and QR codes.
- **Authentication and RBAC** — Administrator, Operator and Viewer roles.
- **Dark and light themes** — dark mode is enabled by default.
- **Docker-native deployment** — frontend and backend run as containers while the backend manages the host network namespace.

---

## Visual Network Topology

DRM builds a live topology from Docker networks, containers, published ports and firewall paths.

<img src="docs/images/topology.png" alt="Docker Router Manager topology">

The topology can represent the path from **External / Internet → published host port → container** and the relationships between containers and Docker networks. Firewall state can be reflected directly in the visual path, making network policy easier to understand than from rule tables alone.

---

## Firewall Engine

The Firewall module manages traffic at the Docker host level and integrates with Docker's forwarding path.

<img src="docs/images/firewall.png" alt="Docker Router Manager firewall">

### Published ports

Create source-based policies for ports published by Docker, for example:

```text
0.0.0.0:9443/tcp → portainer:9443

Source: 192.168.100.0/24
Action: DROP
```

DRM can also terminate matching existing conntrack sessions when a published-port block is applied, so a new policy does not affect only future connections.

### Network policies

Policies can be defined between Docker networks with protocol and destination-port matching.

Firewall changes use an **Apply / Rollback** workflow and the Firewall Engine can be enabled or disabled from the GUI.

> **Important:** Firewall and routing changes affect the Docker host. Always keep an alternative management path available when testing remote firewall rules.

---

## Routing Engine

DRM exposes the Linux host routing table and provides controls for host forwarding and DRM-managed static routes.

<img src="docs/images/routing.png" alt="Docker Router Manager routing">

Features include:

- IPv4 forwarding ON/OFF
- IPv6 forwarding ON/OFF
- current IPv4 and IPv6 Linux routing tables
- connected Docker routes
- WireGuard routes
- IPv4 and IPv6 static destination routes
- create, edit and delete DRM-managed static routes
- gateway selection
- outgoing interface
- route metric
- persistence of DRM-managed routes

Example:

```text
Family:      IPv6
Destination: 2001:db8:100::/64
Gateway:     fd42:8::2
Interface:   wg0
Metric:      100
```

This makes it possible to use the Docker host as a router between Docker networks, VPN networks, LAN segments and other reachable networks.

---

## WireGuard

WireGuard is managed as a native Linux interface in the host network namespace.

<img src="docs/images/wireguard.png" alt="Docker Router Manager WireGuard">

DRM can:

- create WireGuard interfaces
- generate private/public keys
- configure IPv4/IPv6 interface addresses and listen port
- enable IPv6 with automatically suggested gateway/client addresses
- add and remove peers
- configure IPv4 and IPv6 peer tunnel addresses
- separate endpoint address and endpoint port
- configure server-side `AllowedIPs`
- configure client routes
- add DNS servers to generated client configurations
- configure Persistent Keepalive
- generate client `.conf` configurations
- download WireGuard configuration files
- generate QR codes for mobile WireGuard clients

Client-route presets include Docker networks and dual-stack full-tunnel operation. Routing & Access Policy can allow WireGuard clients to selected IPv4 and IPv6 Docker networks, LAN/custom CIDRs and the Internet. IPv4 Internet access can use MASQUERADE; IPv6 Internet access supports routed IPv6 or optional NAT66.

### Example generated client configuration

```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.8.0.2/32, fd42:8::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 172.20.0.0/16, fd20:20::/64, 192.168.150.0/24
PersistentKeepalive = 25
```

Private keys and generated client configurations must be treated as sensitive data.

---

## Dual-stack Docker & WireGuard networking

Version 0.9.3 extends DRM to IPv6 across Docker visibility, routing and WireGuard access policies.

- Container views can display both IPv4 and IPv6 addresses when the Docker network is dual-stack.
- Docker network subnets and gateways are discovered for both address families.
- WireGuard interfaces can operate IPv4-only or dual-stack.
- Enabling IPv6 can automatically suggest a ULA gateway such as `fd42:8::1/64` and peer addresses such as `fd42:8::2/128`.
- WireGuard → Docker access policies are generated for selected IPv4 and IPv6 Docker subnets.
- DRM manages separate IPv6 firewall paths (`DRM-WG6-RAW`, `DRM-WG6-FORWARD`, and optional `DRM-WG6-NAT`).
- IPv6 forwarding state is exposed in Routing and can be enabled by DRM.

For a dual-stack full-tunnel client, the generated route set can include:

```ini
AllowedIPs = 0.0.0.0/0, ::/0
```

For direct access to a dual-stack Docker network, NAT is not required between the WireGuard and Docker IPv6 prefixes; normal routed IPv6 is used. NAT66 remains optional for IPv6 Internet access when a ULA WireGuard prefix does not have an upstream route.

---

## Authentication & Management

DRM includes built-in authentication and role-based access control.

### Roles

| Role | Access |
|---|---|
| **Administrator** | Full system and user management |
| **Operator** | Network, Firewall, Routing and WireGuard management |
| **Viewer** | Read-only access |

The initial bootstrap credentials are:

```text
Username: admin
Password: admin
```

**A password change is mandatory after the first login.** New passwords must contain at least 8 characters.

The Management section supports:

- adding users
- changing roles
- resetting passwords
- changing your own password
- deleting users
- protection of the built-in `admin` account

Authentication uses server-side sessions, HttpOnly cookies, CSRF protection and login rate limiting. Passwords are stored as Argon2id hashes.

> **Security:** Change the bootstrap password immediately and expose DRM only over a trusted management network or HTTPS reverse proxy.

---

## Architecture

```text
                         ┌───────────────────────┐
                         │        Browser        │
                         └───────────┬───────────┘
                                     │
                                HTTP / HTTPS
                                     │
                         ┌───────────▼───────────┐
                         │     DRM Frontend      │
                         │    React + Nginx      │
                         └───────────┬───────────┘
                                     │
                               Management API
                                     │
                         ┌───────────▼───────────┐
                         │      DRM Backend      │
                         │   host network mode   │
                         └───────────┬───────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
       Docker Engine            Linux Network          WireGuard
       Docker socket         iptables / routes       wg interfaces
              │                      │                      │
       ┌──────┴──────┐        ┌──────┴──────┐        ┌─────┴─────┐
       │ Containers  │        │ LAN / VLAN  │        │ VPN peers │
       │  Networks   │        │ Forwarding  │        │  Routes   │
       └─────────────┘        └─────────────┘        └───────────┘
```

The backend intentionally uses the **host network namespace** because DRM must manage the host routing table, WireGuard interfaces and Docker forwarding firewall.

---

## Installation

### Requirements

- Linux Docker host
- Docker Engine
- Docker Compose plugin
- permission to mount the Docker socket
- `NET_ADMIN` capability for host networking operations

Clone the repository:

```bash
git clone https://github.com/RyVolodya/docker-router-manager.git /opt/drm
cd /opt/drm
```

Build and start:

```bash
docker compose build --no-cache
docker compose up -d
```
or:

``` bash
docker compose up -d --build
```

Check container status:

```bash
docker compose ps
```

Open DRM in your browser:

```text
http://DOCKER-HOST:8080
```

Then sign in with the bootstrap account and immediately change its password.

---

## Updating

Pull the latest source:

```bash
git pull
```

Rebuild:

```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

Before upgrading a production installation, back up DRM persistent data and review the release notes.

---

## Rollback

Because releases are tagged, you can return to an earlier DRM version.

Example:

``` bash
cd /opt/drm
sudo docker compose down
sudo git checkout v0.9.9
sudo docker compose build --no-cache
sudo docker compose up -d
```

Before rolling back across versions that change persistent configuration
formats, make a backup of important DRM data.

---

## Security Considerations

DRM is a **privileged network-management application**. The backend can modify host firewall rules, routes and WireGuard interfaces.

Recommended deployment practices:

1. Never expose the backend management API directly to the public Internet.
2. Restrict GUI access to a management LAN or VPN.
3. Use HTTPS for remote administration.
4. Set secure session cookies when DRM is deployed behind HTTPS.
5. Never commit `.env`, private keys, WireGuard client configurations or DRM runtime data to Git.
6. Protect access to the Docker socket.
7. Keep an out-of-band or alternative SSH management path while testing firewall/routing policies.

---

## Project Structure

```text
docker-router-manager/
├── backend/              # Management API and host network engine
├── frontend/             # React web interface
├── docker-compose.yml
├── README.md
└── docs/
    └── images/
        ├── drm-logo.svg
        ├── dashboard.png
        ├── topology.png
        ├── firewall.png
        ├── routing.png
        └── wireguard.png
```

---

## Version 0.9.3

### Changes since v0.8.5

**Firewall & host INPUT**

- Added host `INPUT` firewall management in addition to Docker published-port rules.
- Host interfaces and listening TCP/UDP ports can be discovered and selected from the GUI.
- Added source CIDR, protocol, port and `ACCEPT` / `DROP` / `REJECT` policies for host services.

**WireGuard routing & Docker access**

- Added per-interface **Routing & Access Policy**.
- WireGuard networks can be granted access to selected Docker networks and custom LAN CIDRs.
- Added IPv4 Internet forwarding with optional MASQUERADE.
- Added a managed raw-table exception before Docker direct-container-address DROP rules, allowing explicitly selected WireGuard → Docker network traffic.
- Added peer runtime information, endpoint visibility and interface deletion support.

**WireGuard IPv6 / dual stack**

- Added IPv6 support for WireGuard interfaces and peers.
- Added **Enable IPv6** workflow with automatic gateway and peer-address suggestions.
- Added IPv6 `AllowedIPs`, client routes and DNS support.
- Added IPv6 Internet forwarding and optional NAT66.
- Added IPv6 WireGuard → Docker IPv6 network access using dedicated managed chains.
- DRM now exposes and manages host IPv6 forwarding state.

**Containers & Routing**

- Container network information can display IPv6 addresses alongside IPv4.
- Routing now displays both IPv4 and IPv6 routes.
- Added IPv6 static route creation.
- Added editing and deletion of DRM-managed static routes.
- Added support for IPv6 destinations, gateways, interfaces, metrics and `::/0`.

**Compatibility**

- Existing v0.9.x state remains compatible; new dual-stack fields use defaults when absent.
- Kernel/Docker/WireGuard connected routes remain read-only; only DRM-managed static routes are editable.

---

## Roadmap

Potential future development areas:

- VLAN interface management
- Docker `macvlan` / `ipvlan` management
- policy-based routing (`ip rule` / multiple routing tables)
- OpenVPN integration
- enhanced WireGuard site-to-site workflows
- firewall logging and traffic counters
- richer topology interaction
- configuration backup/restore
- audit log
- HTTPS deployment workflow
- monitoring and historical traffic graphs

---

## Contributing

Issues, bug reports and pull requests are welcome.

When reporting a networking issue, include relevant Docker network information and DRM version, but **remove passwords, private keys, public IP addresses and other sensitive information** before posting logs or screenshots.

---

## License

Docker Router Manager is intended to be distributed under the **GNU General Public License v3.0 (GPL-3.0)**.

See the `LICENSE` file for the complete license text.

---

<div align="center">

**Docker Router Manager · v0.9.3**

*Docker networking with routing, firewall and VPN management in one interface.*

</div>
