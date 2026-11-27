// Server-side examples. Verify source resource permissions before resolving every file/folder ID.
const audience = 'cynayd-drive';
const validId = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,160}$/.test(value)) throw new Error('Invalid Drive object ID');
  return value;
};

function driveOperations({ host, delegation, driveOrigin }) {
  const origin = new URL(driveOrigin);
  if (origin.protocol !== 'https:' || origin.origin !== driveOrigin) throw new Error('Configure the approved Drive origin');
  async function call(cookies, pathname, query, method, scope, init) {
    const binding = await host.authenticate(cookies);
    const url = new URL(pathname + query, origin);
    return delegation.call(binding, {
      audience, scopes: [scope], method, origin: driveOrigin,
      allowsUrl: target => target.pathname === pathname && target.search === query,
    }, url.href, init);
  }

  return {
    // Docs creates a new stored document. Mail can reuse the same upload for a permitted attachment.
    upload(cookies, { folderId, bytes, filename, mimeType }) {
      folderId = validId(folderId);
      const body = new FormData();
      body.append('file', new Blob([new Uint8Array(bytes)], { type: mimeType }), filename);
      body.append('folderId', folderId);
      body.append('userVisible', 'true');
      return call(cookies, '/api/interapp/files/upload', '?' + new URLSearchParams({ folderId, userVisible: 'true' }),
        'POST', 'drive:write', { body, headers: { 'X-Cynayd-User-Visible': 'true' } });
    },
    // Docs replaces content using the previously observed content hash. Reconcile conflicts and uncertain writes.
    save(cookies, { fileId, bytes, filename, mimeType, contentHash }) {
      if (typeof contentHash !== 'string' || !contentHash.trim()) throw new Error('A previous Drive revision is required');
      const body = new FormData();
      body.append('file', new Blob([new Uint8Array(bytes)], { type: mimeType }), filename);
      return call(cookies, '/api/interapp/files/' + validId(fileId) + '/content', '', 'PUT', 'drive:write',
        { body, headers: { 'If-Match': contentHash } });
    },
    // Mail can fetch bytes for a permitted draft. The app still enforces draft and send permissions.
    download(cookies, { fileId }) {
      return call(cookies, '/api/interapp/files/' + validId(fileId) + '/download', '', 'GET', 'drive:read');
    },
  };
}

module.exports = { driveOperations };
