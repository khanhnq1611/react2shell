# React-to-Shell Vulnerable Lab (CVE-2025-55182)

⚠️ **WARNING: This application contains a REAL command injection vulnerability. Use ONLY in isolated lab environments for educational purposes.**

## Overview

This lab demonstrates the **React Server Components Remote Code Execution (RCE)** vulnerability (CVE-2025-55182).

- **Vulnerability**: Prototype pollution in the React Flight protocol deserializer allows attackers to execute arbitrary code on the server.
- **Affected Versions**: Next.js 15.0.0-15.0.4.

Unlike previous simulations, this lab runs the **actual vulnerable versions** of Next.js and React.

## Setup Instructions

1.  **Install dependencies:**
    ```bash
    npm install --legacy-peer-deps
    ```

2.  **Run the vulnerable application:**
    ```bash
    npm run dev
    ```
    The server will start on `http://localhost:3000`.

## Testing the Vulnerability

We have provided a Proof-of-Concept script (`confirm_rce.js`) to demonstrate the RCE.

1.  Ensure the server is running (`npm run dev`).
2.  Open a new terminal.
3.  Run the exploit script:
    ```bash
    node confirm_rce.js
    ```

**Expected Output:**
You should see a success message indicating that the server executed the command (by default `whoami`) and returned the result in the `X-Action-Redirect` header.

## Detailed Guide

For a step-by-step explanation of how the exploit works, read the [Vulnerability Guide](VULNERABILITY_GUIDE.md).

## File Structure

- `app/page.js`: The vulnerable Next.js page (note: the vulnerability is in the framework, not this file's code).
- `confirm_rce.js`: Node.js script that sends the malicious payload.
- `VULNERABILITY_GUIDE.md`: Educational guide explaining the root cause.

## Mitigation

To fix this vulnerability in a real application:
- Upgrade to **Next.js 15.0.5+** and **React 19.0.1+**.

## License

Educational use only. Use at your own risk. Do not deploy to production.
