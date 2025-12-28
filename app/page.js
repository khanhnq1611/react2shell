import { submitForm } from './actions';

export default function Page() {
  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', maxWidth: '800px', margin: '50px auto', padding: '40px', textAlign: 'center' }}>
      <h1 style={{ color: '#d32f2f' }}>🔓 VULNERABLE LAB</h1>
      <h2 style={{ color: '#555' }}>CVE-2025-55182</h2>

      <div style={{ background: '#fff0f0', padding: '30px', borderRadius: '12px', border: '1px solid #ffcdd2', marginTop: '30px' }}>
        <p style={{ fontSize: '1.2em', margin: 0 }}>
          This application is running a vulnerable version of <strong>Next.js (15.0.0)</strong>.
        </p>
        <p style={{ marginTop: '15px' }}>
          It is vulnerable to <strong>Remote Code Execution (RCE)</strong> via the React Server Components (Flight) protocol.
        </p>
      </div>

      <p style={{ marginTop: '40px', color: '#666' }}>
        See <code>VULNERABILITY_GUIDE.md</code> for a detailed explanation of how this exploit works.
      </p>

      <div style={{ marginTop: '40px', padding: '20px', background: '#f5f5f5', borderRadius: '8px', textAlign: 'left' }}>
        <strong>To test the vulnerability:</strong>
        <pre style={{ margin: '10px 0 0 0', background: '#333', color: '#fff', padding: '15px', borderRadius: '6px' }}>
          node confirm_rce.js
        </pre>
      </div>
    </div>
  );
}