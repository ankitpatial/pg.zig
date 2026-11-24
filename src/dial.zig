//! Opens TCP and Unix socket connections on POSIX without std's blocking connect.
//!
//! Why: std 0.17.1 `Io.Threaded.posixConnect` / `posixConnectUnix` call a blocking connect()
//! again after EINTR. The interrupted connect keeps going in the kernel, so the retry gets
//! EALREADY or, once done, EISCONN: a panic in Debug, error.Unexpected in release. std sends
//! SIGIO to cancel tasks, so any signal landing mid-connect can trigger it.
//! Remove this file when std fixes `posixConnect`.
//!
//! How: connect without blocking, then wait in poll(), which is safe to repeat.
//!
//!   socket ─ connect (non-blocking) ─┬─ done ──────────────────────────┐
//!                                    └─ in progress ─ poll ─ SO_ERROR ─┴─ blocking ─ Stream
//!
//! Several addresses for one host race: all start at once, the first to connect wins.
//!
//! Assumes `Io.Threaded`: the raw poll() blocks the OS thread, and the socket handle must be a
//! POSIX fd. The std path worked with any `Io`.

const std = @import("std");
const builtin = @import("builtin");

const Io = std.Io;
const posix = std.posix;
const Threaded = Io.Threaded;
const IpAddress = Io.net.IpAddress;
const HostName = Io.net.HostName;

/// Addresses tried per host; the rest of the lookup is ignored.
const max_addresses = 8;

/// How often the wait wakes to check for cancelation. std signals only its own syscalls, so
/// a raw poll() never gets the cancel signal; this tick bounds the delay before cancel is seen.
const tick_ms = 50;

/// Give up on a connect after this long. 75 s is the macOS kernel's own connect timeout.
/// Linux waits ~127 s, so this cuts a Linux connect short.
const connect_timeout_s = 75;

pub const TcpError = HostName.ValidateError || HostName.LookupError || SocketError || error{
    ConnectionRefused,
    ConnectionResetByPeer,
    Timeout,
    NetworkUnreachable,
    HostUnreachable,
    AddressUnavailable,
    AccessDenied,
};

pub const UnixError = SocketError || error{
    NameTooLong,
    FileNotFound,
    NotDir,
    SymLinkLoop,
    ReadOnlyFileSystem,
    PermissionDenied,
    AccessDenied,
    ConnectionRefused,
    WouldBlock,
    Timeout,
};

const SocketError = error{
    AddressFamilyUnsupported,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    Canceled,
    Unexpected,
};

/// Connects to `host` (name or IP) on `port`. The caller closes the stream with `io`.
pub fn tcp(io: Io, host: []const u8, port: u16) TcpError!Io.net.Stream {
    var addresses: [max_addresses]IpAddress = undefined;
    const count = try lookup(io, host, port, &addresses);
    const deadline = Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(connect_timeout_s));

    // Sockets still connecting; whatever is left when we return lost the race.
    var set: Set = .{};
    defer set.closeAll();

    // The last failure in time; passed to `wait`, it is the error if no later one comes.
    var last: posix.E = .SUCCESS;
    for (addresses[0..count]) |*address| {
        var storage: Threaded.PosixAddress = undefined;
        const len = Threaded.addressToPosix(address, &storage);

        const fd = openSocket(Threaded.posixAddressFamily(address)) catch |err| switch (err) {
            // e.g. IPv6 on a host without it: try the next address.
            error.AddressFamilyUnsupported => {
                last = .AFNOSUPPORT;
                continue;
            },
            else => |e| return e,
        };

        switch (start(fd, &storage.any, len)) {
            .connected => return finishTcp(fd),
            .pending => set.add(fd),
            .failed => |e| {
                closeFd(fd);
                last = e;
            },
        }
    }

    if (set.len == 0) return mapTcp(last);

    return switch (try wait(io, &set, deadline, last)) {
        .connected => |fd| finishTcp(fd),
        .failed => |e| mapTcp(e),
    };
}

/// Connects to the Unix socket at `path`. The caller closes the stream with `io`.
pub fn unix(io: Io, path: []const u8) UnixError!Io.net.Stream {
    var storage: UnixStorage = .{ .un = .{ .path = undefined } };

    // Room for the path and its terminating zero.
    if (path.len < storage.un.path.len) {
        @memcpy(storage.un.path[0..path.len], path);
        storage.un.path[path.len] = 0;
    } else {
        return error.NameTooLong;
    }
    const len: posix.socklen_t = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + 1);

    const deadline = Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(connect_timeout_s));
    const fd = try openSocket(posix.AF.UNIX);
    var set: Set = .{};
    defer set.closeAll();

    const started = startUnix(io, fd, &storage.any, len, deadline) catch |err| {
        closeFd(fd);
        return err;
    };
    const fd_ready = switch (started) {
        .connected => fd,
        .pending => blk: {
            set.add(fd);
            break :blk switch (try wait(io, &set, deadline, .SUCCESS)) {
                .connected => |ready| ready,
                .failed => |e| return mapUnix(e),
            };
        },
        .failed => |e| {
            closeFd(fd);
            return mapUnix(e);
        },
    };
    errdefer closeFd(fd_ready);

    try setNonblocking(fd_ready, false);

    // std's placeholder for a Unix socket's address (Io.net.UnixAddress.connect).
    return .{ .socket = .{ .handle = fd_ready, .address = .{ .ip4 = .loopback(0) } } };
}

const UnixStorage = extern union {
    any: posix.sockaddr,
    un: posix.sockaddr.un,
};

/// Resolves `host` into `out`, in lookup order. Returns how many addresses were filled.
fn lookup(io: Io, host: []const u8, port: u16, out: *[max_addresses]IpAddress) TcpError!usize {
    const host_name: HostName = try .init(host);

    // The lookup runs as a task and we drain its queue meanwhile, as std's HostName.connect
    // does: std puts one entry per result with no cap, so a full queue would block it. Where
    // `io.async` runs inline (no threads), a name with more than 32 results still blocks, as
    // it does in std. Lookup syscalls are safe to restart, so its cancel signal is harmless.
    var buffer: [32]HostName.LookupResult = undefined;
    var queue: Io.Queue(HostName.LookupResult) = .init(&buffer);
    var future = io.async(HostName.lookup, .{ host_name, io, &queue, .{ .port = port } });

    // Bounded by the lookup's results; it closes the queue when done. Beyond `out.len`,
    // addresses are drained and dropped.
    var count: usize = 0;
    while (queue.getOne(io)) |result| switch (result) {
        .address => |address| {
            if (count < out.len) {
                out[count] = address;
                count += 1;
            }
        },
        .canonical_name => continue,
    } else |err| switch (err) {
        error.Closed => {},
        error.Canceled => {
            // We return Canceled either way; the lookup's own result no longer matters.
            future.cancel(io) catch {};
            return error.Canceled;
        },
    }

    const lookup_result = future.await(io);
    if (count > 0) return count;
    try lookup_result;
    return error.UnknownHostName;
}

/// Sockets with a connect in flight, in the form poll() takes.
const Set = struct {
    fds: [max_addresses]posix.pollfd = undefined,
    len: usize = 0,

    fn add(set: *Set, fd: posix.fd_t) void {
        set.fds[set.len] = .{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 };
        set.len += 1;
    }

    /// Takes the socket at `i` out of the set; the caller now owns it.
    fn remove(set: *Set, i: usize) posix.fd_t {
        const fd = set.fds[i].fd;
        set.len -= 1;
        set.fds[i] = set.fds[set.len];
        return fd;
    }

    fn closeAll(set: *Set) void {
        for (set.fds[0..set.len]) |pfd| closeFd(pfd.fd);
        set.len = 0;
    }
};

/// What became of a connect: done, still going, or refused with an errno.
const Outcome = union(enum) {
    connected: posix.fd_t,
    failed: posix.E,
};

const Start = union(enum) {
    connected,
    pending,
    failed: posix.E,
};

/// Starts a non-blocking connect on `fd`.
fn start(fd: posix.fd_t, addr: *const posix.sockaddr, len: posix.socklen_t) Start {
    return switch (posix.errno(posix.system.connect(fd, addr, len))) {
        .SUCCESS => .connected,
        // EINTR: the connect goes on in the kernel, exactly as EINPROGRESS.
        .INPROGRESS, .INTR => .pending,
        else => |e| .{ .failed = e },
    };
}

/// Starts a Unix connect. A full backlog (EAGAIN, Linux) is tried again each tick until
/// `deadline`, as a blocking connect would wait for room.
fn startUnix(
    io: Io,
    fd: posix.fd_t,
    addr: *const posix.sockaddr,
    len: posix.socklen_t,
    deadline: Io.Timestamp,
) error{ Timeout, Canceled }!Start {
    // Bounded by the deadline.
    while (true) {
        const started = start(fd, addr, len);
        if (started != .failed) return started;
        if (started.failed != .AGAIN) return started;

        if (Io.Timestamp.now(io, .awake).compare(.gte, deadline)) return error.Timeout;
        try io.sleep(.fromMilliseconds(tick_ms), .awake);
        try io.checkCancel();
    }
}

/// Waits until one socket in `set` connects or all fail, or `deadline` passes. The winner
/// leaves the set; losers stay for the caller to close. `failed` carries the errno of the
/// last failure in time: the last socket here to fail, else `fallback` (an earlier failure
/// the caller saw while starting connects).
fn wait(
    io: Io,
    set: *Set,
    deadline: Io.Timestamp,
    fallback: posix.E,
) error{ Timeout, SystemResources, Canceled, Unexpected }!Outcome {
    var last = fallback;

    // Bounded by the deadline, not a tick count: signals can wake poll() early, many times.
    while (true) {
        for (set.fds[0..set.len]) |*pfd| pfd.revents = 0;

        switch (posix.errno(posix.system.poll(&set.fds, @intCast(set.len), tick_ms))) {
            .SUCCESS, .INTR => {},
            .NOMEM => return error.SystemResources,
            else => |e| return posix.unexpectedErrno(e),
        }

        // The only place cancelation is seen; see tick_ms.
        try io.checkCancel();

        // Backwards, so `remove` only moves sockets already looked at.
        var i = set.len;
        while (i > 0) {
            i -= 1;
            if (set.fds[i].revents == 0) continue;

            // Readiness alone does not say success; SO_ERROR does.
            const fd = set.remove(i);
            const e = socketError(fd) catch |err| {
                closeFd(fd);
                return err;
            };
            if (e == .SUCCESS) return .{ .connected = fd };

            closeFd(fd);
            last = e;
        }

        if (set.len == 0) return .{ .failed = last };

        if (Io.Timestamp.now(io, .awake).compare(.gte, deadline)) return error.Timeout;
    }
}

/// The connect's result on a socket poll() reported ready.
fn socketError(fd: posix.fd_t) error{Unexpected}!posix.E {
    var value: i32 = 0;
    var len: posix.socklen_t = @sizeOf(i32);
    const rc = posix.system.getsockopt(
        fd,
        posix.SOL.SOCKET,
        posix.SO.ERROR,
        std.mem.asBytes(&value),
        &len,
    );
    switch (posix.errno(rc)) {
        .SUCCESS => return @fromBackingInt(@intCast(value)),
        else => |e| return posix.unexpectedErrno(e),
    }
}

/// Opens a close-on-exec, non-blocking stream socket.
fn openSocket(family: posix.sa_family_t) SocketError!posix.fd_t {
    // macOS has no SOCK_CLOEXEC; set it with fcntl below.
    const cloexec = if (Threaded.socket_flags_unsupported) 0 else posix.SOCK.CLOEXEC;
    const rc = posix.system.socket(family, posix.SOCK.STREAM | cloexec, 0);
    const fd: posix.fd_t = switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => |e| return posix.unexpectedErrno(e),
    };
    errdefer closeFd(fd);

    if (Threaded.socket_flags_unsupported) {
        const set_rc = posix.system.fcntl(fd, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC));
        switch (posix.errno(set_rc)) {
            .SUCCESS => {},
            else => |e| return posix.unexpectedErrno(e),
        }
    }

    try setNonblocking(fd, true);
    return fd;
}

/// Turns O_NONBLOCK on or off. Off is required before handing the socket to std: its reads
/// treat EAGAIN as a programmer bug.
fn setNonblocking(fd: posix.fd_t, on: bool) error{Unexpected}!void {
    const get_rc = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    const flags: usize = switch (posix.errno(get_rc)) {
        .SUCCESS => @intCast(get_rc),
        else => |e| return posix.unexpectedErrno(e),
    };

    const nonblock: usize = 1 << @bitOffsetOf(posix.O, "NONBLOCK");
    const new_flags = if (on) flags | nonblock else flags & ~nonblock;

    switch (posix.errno(posix.system.fcntl(fd, posix.F.SETFL, new_flags))) {
        .SUCCESS => {},
        else => |e| return posix.unexpectedErrno(e),
    }
}

/// Makes a connected TCP socket blocking and wraps it; reads the local address as std does.
fn finishTcp(fd: posix.fd_t) TcpError!Io.net.Stream {
    errdefer closeFd(fd);

    try setNonblocking(fd, false);

    var storage: Threaded.PosixAddress = undefined;
    var len: posix.socklen_t = @sizeOf(Threaded.PosixAddress);
    switch (posix.errno(posix.system.getsockname(fd, &storage.any, &len))) {
        .SUCCESS => {},
        .NOBUFS => return error.SystemResources,
        else => |e| return posix.unexpectedErrno(e),
    }

    return .{ .socket = .{ .handle = fd, .address = Threaded.addressFromPosix(&storage) } };
}

/// Closes a socket we are giving up on. Nothing useful can be done if close fails, and std's
/// own close ignores the result too.
fn closeFd(fd: posix.fd_t) void {
    _ = posix.system.close(fd);
}

fn mapTcp(e: posix.E) TcpError {
    return switch (e) {
        .CONNREFUSED => error.ConnectionRefused,
        .CONNRESET => error.ConnectionResetByPeer,
        .TIMEDOUT => error.Timeout,
        .NETUNREACH => error.NetworkUnreachable,
        .HOSTUNREACH => error.HostUnreachable,
        .ADDRNOTAVAIL => error.AddressUnavailable,
        .ACCES => error.AccessDenied,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        else => posix.unexpectedErrno(e),
    };
}

fn mapUnix(e: posix.E) UnixError {
    return switch (e) {
        .NOENT => error.FileNotFound,
        .NOTDIR => error.NotDir,
        .LOOP => error.SymLinkLoop,
        .ROFS => error.ReadOnlyFileSystem,
        .PERM => error.PermissionDenied,
        .ACCES => error.AccessDenied,
        .CONNREFUSED => error.ConnectionRefused,
        .AGAIN => error.WouldBlock,
        else => posix.unexpectedErrno(e),
    };
}

const t = std.testing;

// Sends SIGIO to `thread`, as std does to interrupt a blocked syscall.
fn signalThread(thread: std.Thread) void {
    if (comptime std.Thread.use_pthreads) {
        _ = std.c.pthread_kill(thread.getHandle(), .IO);
        return;
    }
    if (comptime builtin.os.tag == .linux) {
        const linux = std.os.linux;
        _ = linux.tgkill(linux.getpid(), thread.getHandle(), .IO);
        return;
    }
    unreachable; // the test skips other targets
}

// One thread connects in a loop to a local listener; std's `posixConnect` would retry an
// interrupted connect and panic with ISCONN.
const Storm = struct {
    port: u16,
    done: std.atomic.Value(bool) = .init(false),
    connects: u32 = 0,
    err: ?anyerror = null,

    // std panicked within 250 connects in 8 of 8 runs. A cap keeps the run short; the
    // reset close keeps ports out of TIME_WAIT.
    const max_connects = 2_000;
    // Safety bound only; 2_000 connects take ~0.3 s in Debug.
    const max_ms = 10_000;

    fn connectLoop(storm: *Storm) void {
        defer storm.done.store(true, .release);

        // Own single-threaded Io: lookup and connect run on this thread, where the signals land.
        var threaded: Io.Threaded = .init_single_threaded;
        const io = threaded.io();
        const start_ts = Io.Timestamp.now(io, .awake);

        while (storm.connects < max_connects) : (storm.connects += 1) {
            if (start_ts.untilNow(io, .awake).toMilliseconds() > max_ms) return;

            const stream = tcp(io, "127.0.0.1", storm.port) catch |err| {
                storm.err = err;
                return;
            };

            // Close with a reset, so the port is not parked in TIME_WAIT.
            const linger: posix.linger = .{ .onoff = 1, .linger = 0 };
            posix.setsockopt(
                stream.socket.handle,
                posix.SOL.SOCKET,
                posix.SO.LINGER,
                std.mem.asBytes(&linger),
            ) catch |err| {
                stream.close(io);
                storm.err = err;
                return;
            };
            stream.close(io);
        }
    }
};

const Acceptor = struct {
    server: *Io.net.Server,
    stop: std.atomic.Value(bool) = .init(false),
    err: ?anyerror = null,

    // Bounded by the storm's connects plus the final wake-up connect.
    const max_accepts = Storm.max_connects + 1;

    fn acceptLoop(acceptor: *Acceptor, io: Io) void {
        for (0..max_accepts) |_| {
            if (acceptor.stop.load(.acquire)) return;

            const stream = acceptor.server.accept(io) catch |err| switch (err) {
                // The client's reset close beat the accept.
                error.ConnectionAborted => continue,
                else => {
                    acceptor.err = err;
                    return;
                },
            };
            stream.close(io);
        }
    }
};

test "dial: survives SIGIO storm" {
    // Needs a way to signal one thread: pthreads, or Linux's tgkill.
    if (comptime !std.Thread.use_pthreads) {
        if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    }

    // std.testing.io installs std's SIGIO handler, so the signal interrupts syscalls (EINTR)
    // instead of being ignored (macOS) or killing the process (Linux).
    const io = t.io;

    var addr: Io.net.IpAddress = try .parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true, .kernel_backlog = 1024 });
    defer server.deinit(io);

    var acceptor: Acceptor = .{ .server = &server };
    const accept_thread = try std.Thread.spawn(.{}, Acceptor.acceptLoop, .{ &acceptor, io });

    var storm: Storm = .{ .port = server.socket.address.getPort() };
    const connect_thread = try std.Thread.spawn(.{}, Storm.connectLoop, .{&storm});

    // Signal until the connect loop ends.
    var signals: u64 = 0;
    while (signals < std.math.maxInt(u32)) : (signals += 1) {
        if (storm.done.load(.acquire)) break;
        signalThread(connect_thread);
    }
    connect_thread.join();

    // Wake the acceptor with one last connect.
    acceptor.stop.store(true, .release);
    const last = try server.socket.address.connect(io, .{ .mode = .stream });
    last.close(io);
    accept_thread.join();

    try t.expectEqual(null, storm.err);
    try t.expectEqual(null, acceptor.err);
    try t.expectEqual(Storm.max_connects, storm.connects);
}

// A listening socket is never writable, so a wait on it never ends by itself: it stands in
// for an address that never answers. (A connected socket with a full send buffer does not:
// macOS grows the buffer and reports it writable again.)
fn listenLocal(io: Io) !Io.net.Server {
    var addr: Io.net.IpAddress = try .parse("127.0.0.1", 0);
    return addr.listen(io, .{ .reuse_address = true });
}

test "dial: wait sees cancel" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const io = t.io;

    var server = try listenLocal(io);
    defer server.deinit(io);

    var set: Set = .{};
    set.add(server.socket.handle);

    const started = Io.Timestamp.now(io, .awake);
    const deadline = started.addDuration(.fromSeconds(connect_timeout_s));
    var future = try io.concurrent(wait, .{ io, &set, deadline, .SUCCESS });

    // Let the wait reach poll(), then cancel.
    try io.sleep(.fromMilliseconds(100), .awake);
    const result = future.cancel(io);

    try t.expectError(error.Canceled, result);
    try t.expect(started.untilNow(io, .awake).toMilliseconds() < 1_000);

    // Still in the set: the wait did not take it; `server` closes it.
    try t.expectEqual(1, set.len);
}

test "dial: dead address does not block live one" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const io = t.io;

    var server = try listenLocal(io);
    defer server.deinit(io);

    const live = try server.socket.address.connect(io, .{ .mode = .stream });
    defer live.close(io);
    const live_peer = try server.accept(io);
    defer live_peer.close(io);

    var set: Set = .{};
    set.add(server.socket.handle);
    set.add(live.socket.handle);

    const started = Io.Timestamp.now(io, .awake);
    const deadline = started.addDuration(.fromSeconds(connect_timeout_s));
    const outcome = try wait(io, &set, deadline, .SUCCESS);

    try t.expectEqual(Outcome{ .connected = live.socket.handle }, outcome);
    try t.expect(started.untilNow(io, .awake).toMilliseconds() < 1_000);
    try t.expectEqual(1, set.len);
    try t.expectEqual(server.socket.handle, set.fds[0].fd);
}

test "dial: refused" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const io = t.io;

    // A port just freed: refused at once. (A port bound but not listening is not refused on
    // macOS: the connect times out after ~8 s, with std's connect too.)
    const addr: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    const socket = try addr.bind(io, .{ .mode = .stream });
    const port = socket.address.getPort();
    socket.close(io);

    try t.expectError(error.ConnectionRefused, tcp(io, "127.0.0.1", port));
}

test "dial: unix" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    if (comptime !Io.net.has_unix_sockets) return error.SkipZigTest;
    const io = t.io;

    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();

    // Relative to the working directory, where tmpDir puts its directory.
    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/pg.sock", .{tmp.sub_path});

    try t.expectError(error.FileNotFound, unix(io, path));

    const addr: Io.net.UnixAddress = try .init(path);
    var server = try addr.listen(io, .{});
    defer server.deinit(io);

    // The kernel completes the connect from its backlog; no accept needed.
    const stream = try unix(io, path);
    stream.close(io);
}
