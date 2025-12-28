import { submitForm } from './actions';

export default function Page() {
  return (
    <div
      style={{
        fontFamily: 'system-ui, sans-serif',
        maxWidth: '900px',
        margin: '50px auto',
        padding: '40px',
        textAlign: 'center'
      }}
    >
      <h1 style={{ color: '#1976d2' }}>🛡️ Network Security Awareness</h1>
      <h2 style={{ color: '#555' }}>The Importance of IDS / IPS Systems</h2>

      <div
        style={{
          background: '#e3f2fd',
          padding: '30px',
          borderRadius: '12px',
          border: '1px solid #bbdefb',
          marginTop: '30px'
        }}
      >
        <p style={{ fontSize: '1.2em', margin: 0 }}>
          <strong>IDS (Intrusion Detection System)</strong> and{' '}
          <strong>IPS (Intrusion Prevention System)</strong> are critical
          components in modern cybersecurity architectures.
        </p>

        <p style={{ marginTop: '15px' }}>
          They help organizations <strong>detect, analyze, and prevent</strong>{' '}
          malicious activities targeting networks, servers, and applications.
        </p>
      </div>

      <div
        style={{
          marginTop: '40px',
          textAlign: 'left',
          lineHeight: 1.7
        }}
      >
        <h3 style={{ color: '#1976d2' }}>Why IDS / IPS are important</h3>
        <ul>
          <li>
            🚨 <strong>Early attack detection:</strong> Identify suspicious
            behavior such as brute-force attacks, malware traffic, or exploits.
          </li>
          <li>
            🔍 <strong>Traffic monitoring:</strong> Analyze network packets in
            real time to detect anomalies.
          </li>
          <li>
            ⛔ <strong>Attack prevention (IPS):</strong> Automatically block or
            drop malicious traffic before damage occurs.
          </li>
          <li>
            📊 <strong>Security visibility:</strong> Provide logs and alerts for
            incident response and forensic analysis.
          </li>
          <li>
            🧩 <strong>Defense in depth:</strong> Strengthen security when used
            alongside firewalls, SIEM, and endpoint protection.
          </li>
        </ul>
      </div>

      <div
        style={{
          marginTop: '40px',
          padding: '25px',
          background: '#f5f5f5',
          borderRadius: '8px',
          textAlign: 'left'
        }}
      >
        <strong>Typical deployment environments:</strong>
        <ul style={{ marginTop: '10px' }}>
          <li>Enterprise networks</li>
          <li>Data centers and cloud infrastructure</li>
          <li>Web application servers</li>
          <li>Critical systems requiring high availability</li>
        </ul>
      </div>

      <p style={{ marginTop: '40px', color: '#666' }}>
        A well-configured IDS/IPS system plays a vital role in protecting
        organizations from evolving cyber threats.
      </p>
    </div>
  );
}
