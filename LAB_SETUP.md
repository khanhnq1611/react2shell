# Lab Setup Guide: 3-VM Architecture

This guide explains how to set up the lab environment with 3 distinct Virtual Machines (VMs) as described:

1.  **Victim Machine**: Runs the vulnerable React application.
2.  **IDS Machine**: Acts as a gateway/monitor to detect attacks.
3.  **Attacker Machine**: Runs Kali Linux to exploit the victim.

## Architecture: Reverse Proxy Method

The easiest way to force traffic through an IDS in a lab is to use the **Reverse Proxy** method. The IDS machine sits "in front" of the victim.

```mermaid
graph LR
    A[Attacker (Kali)] -- HTTP Request to 192.168.56.20 --> B[IDS Machine (Nginx + Suricata)]
    B -- Forwards Request to 192.168.56.10 --> C[Victim Machine (React App)]
    
    style A fill:#f9f,stroke:#333
    style B fill:#bbf,stroke:#333
    style C fill:#bfb,stroke:#333
```

- **Attacker Target**: `http://<IDS_IP>` (e.g., 192.168.56.20)
- **IDS Role**: Logs the request, analyzes it, and forwards it to the Victim.
- **Victim Role**: Processes the request (and potentially gets exploited).

---

## Step 1: Network Configuration

Create a **Host-Only Network** (e.g., `vboxnet0` in VirtualBox) so all VMs can talk to each other but are isolated from the internet (optional, but safer).

**Example IPs:**
- **Victim**: `192.168.56.10`
- **IDS**: `192.168.56.20`
- **Attacker**: `192.168.56.30`

---

## Step 2: Configure the VMs

### 1. Victim Machine (Windows/Linux)
- **Install**: Node.js 18+.
- **Copy Code**: Moving the `react2shell` code to this machine.
- **Run App**:
  ```bash
  npm install --legacy-peer-deps
  npm run dev
  ```
- **Firewall**: Ensure port `3000` is open to the IDS machine.

### 2. IDS Machine (Ubuntu/Debian)
This machine needs **Nginx** (to handle traffic) and **Suricata/Snort** (to inspect it).

**A. Install Nginx (Reverse Proxy):**
```bash
sudo apt update && sudo apt install nginx -y
```

**B. Configure Nginx to Forward Traffic:**
Edit `/etc/nginx/sites-available/default`:
```nginx
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://192.168.56.10:3000; # Forward to Victim IP
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```
Restart Nginx: `sudo systemctl restart nginx`

**C. Install & Configure IDS (Snort):**
```bash
sudo apt install snort -y
# When asked for CIDR, use your VM subnet (e.g., 192.168.56.0/24)
```

For detailed rule analysis, see **[SNORT_RULES.md](SNORT_RULES.md)**.

**Optimized Rule** (copy to `/etc/snort/rules/local.rules`):
```
alert tcp any any -> any any (msg:"EXPLOIT CVE-2025-55182 React RCE"; flow:to_server,established; content:"POST"; content:"__proto__"; content:"constructor"; content:"child_process"; content:"execSync"; classtype:web-application-attack; sid:1000001; rev:2;)
```

**Run Snort**:
```bash
sudo snort -T -c /etc/snort/snort.conf   # Test
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0  # Live alerts
```
*(Replace `eth0` with your actual network interface)*


### 3. Attacker Machine (Kali Linux)
- **Connect**: Ensure you can ping the IDS IP (`192.168.56.20`).
- **Attack**:
  Modify `confirm_rce.js` to point to the **IDS IP** instead of localhost.
  ```javascript
  const options = {
    hostname: '192.168.56.20', // Target the IDS, which forwards to Victim
    port: 80,                  // Nginx listens on port 80
    // ...
  };
  ```
  Run the attack: `node confirm_rce.js`

---

## Expected Outcome

1.  **Attacker**: Sees the "Success" message (RCE confirmed).
2.  **Victim**: Executes the command (e.g., prints to console).
3.  **IDS (Snort)**: Displays the alert in the console or logs to `/var/log/snort/alert`.
    ```
    [**] [1:1000001:1] EXPLOIT React Server Components RCE Detected [**]
    ```
