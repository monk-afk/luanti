# async_auth_test

Minimal async authentication handler for testing external validation.

This mod uses the new async auth hooks:
- `begin_auth(name, ip)`
- `poll_auth(name, handle)`

and uses Luanti HTTP async fetch to avoid blocking login in `TOSERVER_INIT`.

## 1) Enable the mod

Add it to your world and enable it (depends on how you manage mods).

## 2) Allow HTTP for this mod

In `minetest.conf` or world config:

```conf
secure.http_mods = async_auth_test
```

## 3) Start the local http auth service

```bash
./util/local_auth_test_server.py --host 127.0.0.1 --port 8085 --delay 1.5
```

Known test users:
- `alice` / `alicepass` (normal privs)
- `admin` / `adminpass` (admin-like privs)
- `denied` (always denied)
- `slow` (forced delay > 30s to test timeout behavior)

## 4) Optional mod settings

```conf
async_auth_test.url = http://127.0.0.1:8085/auth
async_auth_test.timeout = 10
async_auth_test.use_remote_privileges = false
async_auth_test.log_pending_polls = false
```

By default (`use_remote_privileges = false`) the mod ignores privileges returned by
the local http auth service and uses server-local privileges from Luanti auth storage.
This models shared credentials + per-server authorization.

### Logging

The mod logs major auth steps by default (begin, success, deny/failure, local fallback).

If you also want a log line for every pending poll cycle, enable:

```conf
async_auth_test.log_pending_polls = true
```

Note: this can get very noisy under load.

## 5) Quick tests

1. Login as `alice` with password `alicepass` => should authenticate.
2. Login as `denied` with any password => should be denied.
3. Login as `slow` => should hit async auth timeout on the server side.

## Notes

- This is a test harness, not production auth service.
- The local http service returns plaintext test passwords; the mod converts them to SRP verifier format using `core.get_password_hash(name, password)`.
- For real auth, your service should return material that maps to the SRP verifier expected by Luanti's auth flow.
