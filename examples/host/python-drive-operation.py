"""Use after the application authorizes a user-initiated operation on an existing Drive file."""

import re

from cynayd_first_party.client import RegisteredOperation


async def download_drive_file(host, request, delegation, approved_origin, authorized_file_id):
    # The product supplies the file ID after checking its own operation and resource permissions.
    credentials, _ = await host.authenticate(request)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", authorized_file_id):
        raise ValueError("Invalid authorized Drive file ID")
    path = f"/api/interapp/files/{authorized_file_id}/download"
    operation = RegisteredOperation(
        audience="cynayd-drive", scopes=("drive:read",), method="GET", origin=approved_origin,
        allows_url=lambda url: url.path == path and not url.query,
    )
    return await delegation.call(credentials.subject, credentials.identity, operation, approved_origin + path)
