# React-to-Shell Vulnerable Lab (CVE-2025-66478)

⚠️ **WARNING: This application contains a real command injection vulnerability. Use ONLY in isolated lab environments for educational purposes.**

## Overview

This lab demonstrates the React Server Components command injection vulnerability (CVE-2025-66478) found in:
- `react-server-dom-webpack` versions 19.0.0, 19.1.0-19.1.1, 19.2.0
- Next.js with App Router (versions 15.0.0-15.0.4, 15.1.0-15.1.8, etc.)

The vulnerable endpoint accepts user input and executes it directly as shell commands without sanitization.

## Setup Instructions

1. **Install dependencies:**
   ```bash
   npm install --legacy-peer-deps
   ```

2. **Run the vulnerable application:**
   ```bash
   npm run dev
   ```

3. **Access the lab:**
   Open your browser to `http://localhost:3000`

## Testing the Vulnerability

### Safe Test Commands:
- `whoami` - Display current user
- `pwd` - Show current directory  
- `ls -la` - List all files
- `echo "test"` - Echo text
- `id` - Display user ID
- `uname -a` - Show system info

### Example Attack Patterns (for IDS testing):
- Command chaining: `whoami; ls -la`
- Piping: `ls | grep txt`
- Background execution: `sleep 5 &`
- File operations: `cat /etc/passwd`

## For IDS/ZAAK Testing

All requests are logged to `logs/requests.log` with timestamps and IP addresses.

### Detection Patterns:
- Shell metacharacters: `;`, `|`, `&`, `$`, backticks
- Dangerous commands: `nc`, `bash`, `sh`, `curl`, `wget`, `python`, `perl`
- File access attempts: `/etc/passwd`, `/etc/shadow`
- Network commands: `netcat`, `ncat`, `socat`

### Log Format:
```
[2025-12-27T10:30:00.000Z] IP=::1 input=whoami
[2025-12-27T10:30:00.001Z] EXECUTED IP=::1 input=whoami
```

## Files Structure

- `app/page.js` - Vulnerable React frontend with input form
- `app/api/exec-vuln/route.js` - Vulnerable API endpoint (ACTUAL COMMAND EXECUTION)
- `logs/requests.log` - Request and execution logs for IDS analysis
- `next.config.js` - Next.js configuration
- `package.json` - Vulnerable dependencies

## Security Notes

**DO NOT deploy this application on the internet or any production environment.**

This lab is designed exclusively for:
- Training security teams
- Testing IDS/IPS systems (ZAAK, Suricata, Snort, etc.)
- Educating developers about command injection vulnerabilities
- Demonstrating secure coding practices by showing what NOT to do

## Mitigation (for learning purposes)

The proper fix involves:
1. Never execute user input directly
2. Use allowlists for permitted commands
3. Implement strict input validation
4. Use parameterized APIs instead of shell execution
5. Apply principle of least privilege
6. Upgrade to patched versions (React 19.0.1+, Next.js 15.0.5+, etc.)

## License

Educational use only. Use at your own risk.

**Reality vs Simulation**

- **Reality:** The real vulnerability arises from the React Server Components Flight deserializer allowing prototype-paths such as `$1:__proto__:then` or `$1:constructor:constructor`. These prototype paths can be abused to reach the `Function` constructor inside the server runtime, which effectively lets an attacker run arbitrary server-side code. A full exploit chain traverses Flight frames, pollutes prototypes, reaches `Function`/`constructor`, and evaluates attacker-controlled source in the server process.

- **Simulation (this lab):** For safety and usability, the HTTP handler in this lab detects the Flight/prototype-pollution markers (`$1:__proto__:then`, `$1:constructor:constructor`, `$1:__proto__`) and then looks for an `execSync('...')` snippet in the raw body to show the exploit outcome (RCE + exfil via `X-Action-Redirect`). This reproduces the practical impact (remote command execution and exfiltration) without modeling the full exploitation stack.

- **Why this simplification is acceptable for a lab:** The goal is to teach detection, logging, and response to the RCE outcome rather than to provide a weaponized exploit. The simplified handler makes the lab deterministic and easier to test with `test-vuln.sh` while still demonstrating the exact post‑exploit effects defenders should detect.

- **Default mode (safe):** The server defaults to `VULN_MODE=simulated`. In simulated mode the code does not execute arbitrary shell commands; instead it returns realistic, precomputed outputs for common PoC commands (e.g., `echo $((11111*1))`, `id`).

- **Real mode (dangerous — use only in isolated VMs):** To reproduce actual command execution, set `VULN_MODE=real` when starting the server. Example (only in an isolated lab):

```bash
cd ~/Desktop/react2shell
VULN_MODE=real npm run dev
# then from another terminal:
./test-vuln.sh http://localhost:3000
```

- **Safety checklist before enabling `VULN_MODE=real`:**
   - Run inside an isolated VM or disposable container (no sensitive data or network access).
   - Ensure host firewall prevents outgoing connections you don't intend.
   - Avoid running as root.
   - Inspect `test-vuln.sh` before use.

- **Where the lab differs from a full exploit:** This lab does not implement the Flight deserialization steps or prototype pollution mechanics in the engine itself — instead it detects the Flight markers and models the attacker-controlled `Function` evaluation's effect by running (or simulating) `execSync(...)`. That makes the lab functionally equivalent from a detection/logging/testing POV while reducing accidental risk.
