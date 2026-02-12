**AI Disclaimer**

The changes made in this branch (auth-async) were written by Agentic AI (Codex)

**Engine Changes**

1. Added async auth lookup API to server Lua bridge:
- `AuthLookupStatus`, `beginAuthLookup(...)`, `pollAuthLookup(...)` in `luanti/src/script/cpp_api/s_server.h:14`
- Implementation of `begin_auth`/`poll_auth` calls and result parsing in `luanti/src/script/cpp_api/s_server.cpp:74`
- Shared auth table parser for both sync and async paths in `luanti/src/script/cpp_api/s_server.cpp:12`

2. Added client auth-pending state machine support:
- New `CS_AuthPending` and `CSE_AuthStart` in `luanti/src/server/clientiface.h:162`
- State transitions in `luanti/src/server/clientiface.cpp:461`
- Extended linger timeout for pending async auth (`ASYNC_AUTH_LINGER_TIMEOUT = 60`) in `luanti/src/server/clientiface.h:533` and `luanti/src/server/clientiface.cpp:733`
- Added `getPendingSerializationVersion()` accessor used for delayed `TOCLIENT_HELLO` in `luanti/src/server/clientiface.h:309`

3. Added server-side async auth queue and poll loop:
- Pending lookup data model and storage in `luanti/src/server.h:520` and `luanti/src/server.h:791`
- Centralized auth mechanism response builder `sendAuthMethods(...)` in `luanti/src/server.cpp:2946`
- Periodic async poller `stepPendingAuthLookups()` in `luanti/src/server.cpp:3005`
- Poll step wired into server frame loop in `luanti/src/server.cpp:674`
- Pending-auth cleanup on disconnect in `luanti/src/server.cpp:3201`

4. Updated login init flow to support non-blocking auth start:
- `handleCommand_Init` now attempts `beginAuthLookup(...)`, stores pending handles, and transitions to `CS_AuthPending` when needed in `luanti/src/network/serverpackethandler.cpp:205`
- Sync fallback remains in place when async hooks are unsupported in `luanti/src/network/serverpackethandler.cpp:240`

5. Added builtin compatibility hook:
- Builtin auth handler now exposes immediate `begin_auth(...)` pass-through in `luanti/builtin/game/auth.lua:45`

**Test Utilities Added**
1. Mock OAuth service:
- `luanti/util/mock_oauth_server.py`
- Provides predictable allow/deny and delayed responses for timeout and concurrency testing.

2. Async auth test handler mod (under `util/`):
- `luanti/util/oauth_async_auth_test/init.lua`
- `luanti/util/oauth_async_auth_test/mod.conf`
- `luanti/util/oauth_async_auth_test/README.md`
- Includes structured logging (`log_pending_polls`), async HTTP lookup, caching, and optional remote privilege usage.

**Behavior Notes**
1. Existing authentication handlers without async methods still work through the synchronous `get_auth` path.
2. Handlers implementing both `begin_auth` and `poll_auth` avoid blocking auth work inside `TOSERVER_INIT`.
3. Async auth requests are timeout-limited (30s server-side poll window) and cleaned up on disconnect.
4. If `begin_auth` exists but `poll_auth` is missing, server logs a warning and falls back to synchronous lookup.
5. No database schema changes are included in this change set.
