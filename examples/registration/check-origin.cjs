function exactOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin !== value) throw new Error('Supply exact HTTPS origins');
  return url.origin;
}
async function main() {
  const [one, app] = process.argv.slice(2).map(exactOrigin);
  if (!one || !app) throw new Error('Usage: check-origin.cjs ONE_ORIGIN APPLICATION_ORIGIN');
  const response = await fetch(one + '/api/v1/delegations/frame-origins', {
    redirect: 'error', signal: AbortSignal.timeout(5000), cache: 'no-store',
  });
  if (!response.ok) throw new Error('One frame-origin registry returned HTTP ' + response.status);
  const { origins } = await response.json();
  if (!Array.isArray(origins) || origins.some(value => typeof value !== 'string' || exactOrigin(value) !== value)) {
    throw new Error('Unexpected frame-origin registry response');
  }
  const originRegistered = origins.includes(app);
  console.log(JSON.stringify({ originRegistered }));
  if (!originRegistered) process.exitCode = 1;
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
