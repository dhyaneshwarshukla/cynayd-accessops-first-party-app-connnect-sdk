const sdk = require('..');
const { mockServices } = require('./mock-services.cjs');

async function main() {
  const { client, session, expected, operations } = mockServices(sdk);
  // Host adapter atomically consumes callback state and checks the current session revision.
  let pending = { sessionId: 'connect-session', revision: '1', expected };
  let stored;
  const states = { async consume(value) {
    if (value !== 'fixture-state') return;
    const state = pending;
    pending = undefined;
    return state;
  } };
  const store = {
    async load() { return stored; },
    async replaceIfCurrent(sessionId, revision, credentials) {
      if (sessionId !== 'connect-session' || revision !== '1' || stored) return false;
      stored = { revision: '2', credentials };
      return true;
    },
    async removeIfCurrent(sessionId, revision) {
      if (sessionId !== 'connect-session' || stored?.revision !== revision) return false;
      stored = undefined;
      return true;
    },
  };
  await session.completeCodeLaunch({ code: 'one-code', state: 'fixture-state' }, states, store);
  const binding = (await store.load()).credentials;
  for (const [name, path] of [['drive', '/files'], ['calendar', '/events']]) {
    const operation = operations[name];
    const result = await client.call(binding, operation, operation.origin + path, {
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'Fixture' }),
    });
    if (!result.ok) throw new Error(name + ' failed with HTTP ' + result.status);
    console.log(name + ' HTTP ' + result.status);
  }
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
