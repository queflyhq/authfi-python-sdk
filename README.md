# AuthFI Python SDK

Official Python SDK for [AuthFI](https://authfi.app) — the identity control plane.

## Install

```bash
pip install authfi
```

For RS256 signature verification (recommended for production):
```bash
pip install authfi PyJWT[crypto]
```

## Quick Start (Flask)

```python
from authfi import AuthFI

auth = AuthFI(tenant='acme', api_key='sk_live_...')

@app.route('/api/users')
@auth.require('read:users')
def get_users():
    user = auth.current_user()
    return jsonify(users)

# On startup
auth.sync()
```

## Quick Start (FastAPI)

```python
from authfi import AuthFI
from fastapi import Depends

auth = AuthFI(tenant='acme', api_key='sk_live_...')

@app.get('/api/users')
async def get_users(user=Depends(auth.require('read:users'))):
    return users
```

## Features

- JWKS + RS256 verification (via PyJWT when installed)
- `@auth.require("read:users")` — decorator for Flask/FastAPI
- `@auth.require_role("admin")` — role-based access
- Permission auto-sync on `sync()`
- Cloud credentials (GCP/AWS/Azure/OCI)
- Cloud token exchange
- Works with Flask, FastAPI, Django, any WSGI/ASGI framework

## Cloud Credentials (AuthFI Connect)

```python
creds = auth.cloud_credentials(user_token, 'aws', role_arn='arn:aws:iam::123:role/deploy')
```

## Running Tests

```bash
python -m unittest test_authfi -v
```

16 unit tests — all passing.

## License

MIT
