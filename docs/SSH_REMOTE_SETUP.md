# Remote Capture & SSH Configuration Guide

NetOrchestra captures network packets remotely over SSH using an isolated Go worker. Traffic is captured passively on the remote server using **tcpdump** (default) or **NETOU** (automatic AF_PACKET fallback) and streamed directly to NetOrchestra over an encrypted SSH connection.

This guide details:
1. Generating SSH keypairs on the NetOrchestra SOC server.
2. Setting up the dedicated, unprivileged capture user on the remote host.
3. Granting minimum packet capture capabilities (`CAP_NET_RAW`) without `sudo` or `root`.
4. Storing keys, configuring `known_hosts`, and setting permissions.

---

## Architecture & Security Model

```
NetOrchestra Server (Local)                          Remote Linux Server (Target)
┌─────────────────────────────────────────┐          ┌────────────────────────────────────────┐
│ secrets/ssh/<credential_ref> (chmod 600)│  SSH     │ ~/.ssh/authorized_keys (chmod 600)     │
│ secrets/known_hosts (chmod 644)         ├─────────►│ neto-capture user (UID non-zero)       │
│                                         │          │ ├── tcpdump (cap_net_raw)              │
│ Worker passes key as credential_ref     │          │ └── netou fallback (cap_net_raw)       │
└─────────────────────────────────────────┘          └────────────────────────────────────────┘
```

* **No root required:** The capture account runs under a dedicated, low-privilege user account.
* **No `sudo` used:** Tools use Linux file capabilities (`CAP_NET_RAW`), eliminating sudo escalation risks.
* **Strict host verification:** `known_hosts` checking is strictly enforced; modified or unknown host keys abort the connection immediately.
* **Memory-only:** Private key material is read by the worker and never stored in the database, audit logs, or web events.

---

## Step 1: Generate SSH Keypair on the SOC Server (Local)

Run these commands inside your NetOrchestra project root (or inside the mounted `secrets/` directory):

```bash
# 1. Create secrets directories with strict permissions
mkdir -p secrets/ssh secrets/known_hosts

# 2. Generate an unencrypted Ed25519 key (recommended) or RSA key
# Replace "sensor-node-01" with a descriptive credential reference name
ssh-keygen -t ed25519 -f secrets/ssh/sensor-node-01 -N "" -C "netorchestra@soc"

# 3. Secure the local file permissions (MANDATORY)
chmod 700 secrets/ssh
chmod 600 secrets/ssh/*
```

* **Private Key:** `secrets/ssh/sensor-node-01` (This filename, e.g. `sensor-node-01`, is your `credential_ref` when starting a capture).
* **Public Key:** `secrets/ssh/sensor-node-01.pub` (To be installed on the remote host).

---

## Step 2: Configure the Remote Host (Target Server)

Log into the remote server where traffic will be captured and run the following setup steps.

### 2.1 Create a Dedicated Capture User
Create a system user named `neto-capture` with no interactive login password:

```bash
# Ubuntu / Debian
sudo useradd -r -m -s /bin/bash neto-capture

# RHEL / CentOS / Rocky / AlmaLinux
sudo useradd -r -m -s /bin/bash neto-capture
```

### 2.2 Install the Public Key
Install the public key generated in Step 1 into `neto-capture`'s `authorized_keys` file:

```bash
# 1. Switch to user directory
sudo mkdir -p /home/neto-capture/.ssh
sudo chmod 700 /home/neto-capture/.ssh

# 2. Add public key with optional source IP restriction (recommended)
# Replace <SOC_SERVER_IP> with the IP address of your NetOrchestra server:
echo 'from="<SOC_SERVER_IP>" <PASTE_CONTENTS_OF_sensor-node-01.pub>' | sudo tee -a /home/neto-capture/.ssh/authorized_keys

# (If no source IP restriction is needed):
# cat sensor-node-01.pub | sudo tee -a /home/neto-capture/.ssh/authorized_keys

# 3. Lock down permissions
sudo chmod 600 /home/neto-capture/.ssh/authorized_keys
sudo chown -R neto-capture:neto-capture /home/neto-capture/.ssh
```

### 2.3 Grant Packet Capture Capabilities (`CAP_NET_RAW`)

To capture packets passively without granting full `root` access or `sudo`:

#### Option A: Provisioning `tcpdump` (Primary Engine)
```bash
# Verify tcpdump is installed
command -v tcpdump

# Grant CAP_NET_RAW to tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip $(command -v tcpdump)
```

#### Option B: Provisioning `netou` (AF_PACKET Fallback Engine)
If `tcpdump` is not installed or cannot be modified, copy the pre-built `netou` binary (from `worker/bin/netou`) to the remote host:

```bash
# 1. Install binary
sudo install -o root -g root -m 0755 netou /usr/local/bin/netou

# 2. Grant CAP_NET_RAW
sudo setcap cap_net_raw+ep /usr/local/bin/netou

# 3. Test operational readiness as neto-capture user
su - neto-capture -c "netou -check"
# Output should display: "netou operational (CAP_NET_RAW verified)"
```

---

## Step 3: Configure Host Key Verification (`known_hosts`)

To prevent man-in-the-middle attacks, NetOrchestra requires remote host keys in `known_hosts`.

On your **NetOrchestra SOC server**:

```bash
# Scan and record the remote host public key (e.g. 192.168.1.50)
ssh-keyscan -H 192.168.1.50 >> secrets/known_hosts

# Ensure read permissions for the container/process
chmod 644 secrets/known_hosts
```

> **Security Verification:** Validate that the printed host fingerprint matches the target server's real fingerprint (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the remote host).

---

## Step 4: Authorize Target in NetOrchestra Configuration

For security, NetOrchestra blocks SSH connections to arbitrary hosts unless explicitly listed in `.env`:

Edit your `.env` file on the SOC server:
```bash
# CIDR blocks or IPs authorized for capture
NETO_ALLOWED_TARGETS=192.168.1.0/24,10.0.0.50

# Worker binaries and paths
NETO_WORKER_BIN=/usr/local/bin/netorchestra-worker
NETO_WORKER_KEYS_DIR=/run/secrets/ssh          # or ./secrets/ssh for local dev
NETO_WORKER_KNOWN_HOSTS=/etc/netorchestra/known_hosts # or ./secrets/known_hosts
```

---

## Step 5: Start a Remote Capture from the Dashboard

1. Open the NetOrchestra Dashboard in your browser (`http://localhost:8080`).
2. Navigate to **Capture Controls** -> **Live Stream**.
3. Fill in the parameters:
   * **Target Host:** `192.168.1.50`
   * **SSH Port:** `22`
   * **SSH Username:** `neto-capture`
   * **Authentication:** Select **Key file** and choose `sensor-node-01` from the dropdown.
   * **Interface:** `eth0` (or `any`)
   * **Duration:** `60` seconds (or custom)
   * **Detection Profile:** e.g. `DNS Tunneling` or `Cleartext HTTP`
4. Click **Start Capture**.
5. The **Live Activity** ribbon will show:
   * `CAPTURE PROGRESS · [tcpdump] ...` OR
   * `CAPTURE PROGRESS · [NETOU (AF_PACKET)] ...` (if `tcpdump` was absent or unprivileged).
6. Packets and detected threats appear instantly in the **Packet Inspector** and **Threat Grid**.
