# Snort Rules for CVE-2025-55182 (React-to-Shell)

This document provides a detailed analysis of the attack payload and explains how to write Snort rules to detect it.

---

## Part 1: Payload Analysis

Let's break down the malicious payload sent by `confirm_rce.js`.

### The HTTP Request Structure

The attack sends a **POST request** with these key characteristics:

| Element | Value | Why It Matters |
|---------|-------|----------------|
| **Method** | `POST` | The attack modifies server state. |
| **Header** | `Next-Action: x` | This header triggers the React Server Components Flight handler. Without it, the request is ignored. |
| **Content-Type** | `multipart/form-data` | Standard for form submissions. The attack hides its payload inside a form field. |
| **Body** | JSON payload (see below) | Contains the actual exploit code. |

### The JSON Payload (Field "0")

```json
{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var res=process.mainModule.require('child_process').execSync('whoami')...",
    "_chunks": "$Q2",
    "_formData": { "get": "$1:constructor:constructor" }
  }
}
```

**Key Malicious Indicators:**

1.  **`$1:__proto__:then`**: This is the **prototype pollution trigger**. It tells the deserializer to modify the `__proto__` property, which is the key to breaking out of the sandbox.

2.  **`$1:constructor:constructor`**: This accesses the global `Function` constructor, which allows arbitrary code to be created from a string.

3.  **`process.mainModule.require('child_process')`**: This is how Node.js loads the module that can run shell commands.

4.  **`execSync('...')`**: The actual dangerous function that executes a command on the system.

---

## Part 2: Optimized Single Snort Rule

To avoid false positives, we combine **all** attack indicators into a single rule. The rule will only trigger when **every** condition is met:

1. `__proto__` (prototype pollution marker)
2. `constructor` (Function access)
3. `execSync` (command execution function)
4. `child_process` (Node.js shell module)

### The Optimized Rule

```
alert tcp any any -> any any (
    msg:"EXPLOIT CVE-2025-55182 React Server Components RCE";
    flow:to_server,established;
    content:"POST";
    content:"__proto__";
    content:"constructor";
    content:"child_process";
    content:"execSync";
    classtype:web-application-attack;
    sid:1000001;
    rev:2;
)
```

### Line-by-Line Explanation

| Part | Meaning |
|------|---------|
| `alert` | Generate an alert (don't block). |
| `tcp any any -> any any` | Match TCP traffic on any port. |
| `msg:"..."` | Alert message shown in logs. |
| `flow:to_server,established` | Only match packets going TO the server on an active connection. |
| `content:"POST"` | Require HTTP POST method (the attack uses POST). |
| `content:"__proto__"` | Require prototype pollution marker. |
| `content:"constructor"` | Require Function constructor access. |
| `content:"child_process"` | Require Node.js shell module reference. |
| `content:"execSync"` | Require the dangerous execution function. |
| `classtype:web-application-attack` | Categorize as web attack. |
| `sid:1000001; rev:2` | Unique rule ID, revision 2. |

### Why This Reduces False Positives

- A legitimate request would **never** contain all four patterns (`__proto__`, `constructor`, `child_process`, `execSync`) together.
- By requiring all of them, we ensure only the actual exploit triggers the alert.

---

## Part 3: Complete local.rules File

Copy this single rule into `/etc/snort/rules/local.rules`:

```
# CVE-2025-55182 React Server Components RCE - Optimized Detection
alert tcp any any -> any any (msg:"EXPLOIT CVE-2025-55182 React Server Components RCE"; flow:to_server,established; content:"POST"; content:"__proto__"; content:"constructor"; content:"child_process"; content:"execSync"; classtype:web-application-attack; sid:1000001; rev:2;)
```

---

## Part 4: Testing

1.  **Update rules**: Save the file to `/etc/snort/rules/local.rules`.
2.  **Test configuration**:
    ```bash
    sudo snort -T -c /etc/snort/snort.conf
    ```
3.  **Run Snort**:
    ```bash
    sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
    ```
4.  **Execute the attack** from Kali:
    ```bash
    node confirm_rce.js
    ```
5.  **Expected output**:
    ```
    [**] [1:1000001:2] EXPLOIT CVE-2025-55182 React Server Components RCE [**]
    ```

