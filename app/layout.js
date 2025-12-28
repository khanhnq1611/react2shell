export const metadata = {
  title: 'CVE-2025-55182 - React Server Components RCE Lab',
  description: 'Vulnerable Next.js 15.0.0 + React 19.0.0 for security research',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, padding: 0 }}>{children}</body>
    </html>
  )
}
