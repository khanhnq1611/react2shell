'use server';

// Simple server action - the vulnerability is in the RSC deserialization,
// not in this code. Any server action makes the app exploitable.
export async function submitForm(formData) {
  const name = formData.get('name') || 'Guest';
  return { message: `Hello, ${name}!`, timestamp: new Date().toISOString() };
}

export async function getServerTime() {
  return { time: new Date().toISOString() };
}
