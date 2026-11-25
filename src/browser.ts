/** Same-origin sync hints only. Fetch authoritative state through the application backend. */
export function observeSessionChanges(onChange: () => void, channelName = 'cynayd-session-v1') {
  const channel = typeof BroadcastChannel === 'undefined' ? undefined : new BroadcastChannel(channelName);
  const onMessage = (event: MessageEvent) => { if (event.data === 'session-changed') onChange(); };
  const onVisible = () => { if (document.visibilityState === 'visible') onChange(); };
  channel?.addEventListener('message', onMessage);
  window.addEventListener('online', onVisible);
  document.addEventListener('visibilitychange', onVisible);
  return {
    invalidate() { channel?.postMessage('session-changed'); onChange(); },
    close() {
      channel?.close();
      window.removeEventListener('online', onVisible);
      document.removeEventListener('visibilitychange', onVisible);
    },
  };
}

/** Listen on the product's authenticated SSE relay. Data is an invalidation hint only. */
export function observeSessionEventStream(path: string, onChange: () => void): () => void {
  const url = new URL(path, window.location.origin);
  if (url.origin !== window.location.origin || url.username || url.password || url.search || url.hash) {
    throw new Error('Use the configured same-origin session event relay');
  }
  const stream = new EventSource(url.href);
  stream.addEventListener('session', onChange);
  stream.addEventListener('open', onChange);
  return () => stream.close();
}
