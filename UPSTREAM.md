# Issues to report upstream

Bugs found while using this fork, kept for reporting later. Not reported yet.
"Fork" = this repo's `std-tls` branch; "upstream" = karlseguin/pg.zig.

## pg.zig

### 1. Read buffer freed or grown by the wrong allocator

- **Where:** `src/reader.zig`, `src/conn.zig` (`exec`).
- **What:** a read buffer grown past the static one belongs to the allocator current when it
  grew. The reader tracked only the current allocator, so the next flow's arena grew or freed
  a buffer it did not own: ArenaAllocator abort, leak, or use after free. `exec` read its reply
  after `endFlow` (no values) or after `result.deinit` (values); with `release_conn` it read
  from a connection already back in the pool.
- **Trigger:** a row over 4 KiB through `exec`, then any statement with an arena allocator.
- **Status:** fixed in fork, 955d78b. Upstream: affected as of the 2f8d67b sync.

### 2. Pool quirks (fork pool features, commit 410f227)

These live in fork-only code (connect deadline, max lifetime); report only if upstreamed.

- The dial deadline is not bounded by the caller's acquire timeout: acquire can wait longer
  than asked.
- `max_lifetime` is enforced only on release; an idle connection past its lifetime is handed
  out once more.
- `Pool.init`: a connect failure part way through leaks the connections already opened.
  (Check whether upstream's init has the same path.)

## Zig std (0.17.1)

### 3. Restarted blocking connect panics with ISCONN

- **Where:** `lib/std/Io/Threaded.zig` `posixConnect` (12346) and `posixConnectUnix` (12384).
- **What:** on EINTR with no cancel pending, std calls `connect()` again. An interrupted
  connect keeps going in the kernel; the retry gets EALREADY (`error.ConnectionPending`) or,
  once done, EISCONN. std maps EISCONN to `errnoBug`: panic in Debug, `error.Unexpected` in
  release. Linux answers the
  retry with success, so it shows on macOS.
- **Repro:** one thread connects to a local listener in a loop while another sends it SIGIO
  (`pthread_kill`). Panics within seconds, 3 of 3 runs.
- **Seen as:** ledger live test "parallel postings" crashed once with
  `panic: programmer bug caused syscall error: ISCONN`.
- **Fork workaround:** `src/dial.zig` connects non-blocking and waits in `poll`, which is safe
  to repeat. Remove it when std fixes `posixConnect`.
- **Related std doc bug:** `HostName.lookup` says it never blocks with a 16+ slot queue, but
  `netLookupFallible` does one `putOne` per result with no cap (`Threaded.zig` ~14240), so a
  name with more results than slots blocks unless the queue is drained concurrently.

### 4. Cancel signal can land on the next task

- **Where:** `lib/std/Io/Threaded.zig` `signalCanceledSyscall` (~1312).
- **What:** it loads the thread's status, then `pthread_kill(SIGIO)`; the two are not atomic,
  and the signal is resent with backoff. A thread that finished the canceled task and started
  another can get the signal inside an unrelated syscall. Harmless where EINTR is retried
  safely; with issue 3 it is a crash.
- **Evidence:** the window is in the code; that it caused the ledger crash is inferred, not
  measured.
- **Sources in this code:** `HostName.connect` races all resolved addresses and cancels the
  losers; the pool's `dialWithin` / `checkWithin` cancel the loser of each race.
