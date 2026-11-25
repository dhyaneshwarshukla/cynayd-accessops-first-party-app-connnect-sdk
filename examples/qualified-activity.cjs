// The host authenticates its own session and loads a server-held One binding.
async function runInteractiveSend({ client, binding, withCentralSession, authorizeAndSend, reportFailure, operationId }) {
  const result = await withCentralSession(client, binding, authorizeAndSend);
  try {
    await client.reportActivity(binding, 'message.send', operationId);
  } catch (error) {
    // A reporting failure does not invalidate a send that already succeeded.
    reportFailure({ code: error.code ?? 'ACTIVITY_REPORT_FAILED', requestId: error.requestId });
  }
  return result;
}

module.exports = { runInteractiveSend };
