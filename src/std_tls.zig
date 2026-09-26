// TLS with std.crypto.tls, the default when pg.zig is built without
// -Dopenssl. A Context is what a Pool (or a lone Conn) shares between its
// connections: the verification mode and the CA bundle, loaded once.

const std = @import("std");
const lib = @import("lib.zig");

const Conn = lib.Conn;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Bundle = std.crypto.Certificate.Bundle;

pub const Verify = enum {
    /// Encrypted, but the server's certificate is not checked (require, prefer).
    none,
    /// The certificate must chain to the bundle; the host name is not checked.
    ca,
    /// As `ca`, and the certificate must name the host we dialled.
    full,
};

pub const Context = struct {
    gpa: Allocator,
    io: Io,
    verify: Verify,
    bundle: Bundle,
    /// std's TLS client takes the lock to rescan an empty bundle; shared
    /// by every connection using this context.
    lock: Io.RwLock,

    /// init loads the CA bundle for `verify_ca` / `verify_full`: from the
    /// given file, or from the OS trust store when the path is null.
    pub fn init(io: Io, gpa: Allocator, config: Conn.Opts.TLS) !*Context {
        const ctx = try gpa.create(Context);
        errdefer gpa.destroy(ctx);
        ctx.* = .{ .gpa = gpa, .io = io, .verify = .none, .bundle = .empty, .lock = .init };
        errdefer ctx.bundle.deinit(gpa);

        const path: ?[]const u8 = switch (config) {
            .off, .prefer, .require => return ctx,
            .verify_ca => |p| blk: {
                ctx.verify = .ca;
                break :blk p;
            },
            .verify_full => |p| blk: {
                ctx.verify = .full;
                break :blk p;
            },
        };

        const now = Io.Clock.real.now(io);
        if (path) |p| {
            if (std.fs.path.isAbsolute(p)) {
                try ctx.bundle.addCertsFromFilePathAbsolute(gpa, io, now, p);
            } else {
                try ctx.bundle.addCertsFromFilePath(gpa, io, now, Io.Dir.cwd(), p);
            }
            // An empty bundle would reject every server (on Windows, std
            // would fall back to the OS store instead): say why up front.
            if (ctx.bundle.map.count() == 0) return error.NoCertificatesInFile;
        } else {
            try ctx.bundle.rescan(gpa, io, now);
        }
        return ctx;
    }

    pub fn deinit(self: *Context) void {
        const gpa = self.gpa;
        self.bundle.deinit(gpa);
        gpa.destroy(self);
    }

    /// options fills tls.Client.Options' verification fields for a dial to `host`.
    pub fn hostOption(self: *const Context, host: []const u8) !@FieldType(std.crypto.tls.Client.Options, "host") {
        if (self.verify != .full) return .no_verification;
        // std matches DNS names only, never IP SANs: refuse rather than
        // silently check less than verify-full promises.
        if (!isHostName(host)) return error.VerifyFullNeedsHostName;
        return .{ .explicit = host };
    }

    pub fn caOption(self: *Context) @FieldType(std.crypto.tls.Client.Options, "ca") {
        if (self.verify == .none) return .no_verification;
        return .{ .bundle = .{ .gpa = self.gpa, .io = self.io, .lock = &self.lock, .bundle = &self.bundle } };
    }
};

/// isHostName: false for IPv4 and IPv6 literals.
fn isHostName(host: []const u8) bool {
    if (std.mem.findScalar(u8, host, ':') != null) return false;
    return std.mem.findNone(u8, host, "0123456789.") != null;
}

const t = lib.testing;

test "std_tls: modes pick their verification" {
    const require = try Context.init(t.io, t.allocator, .require);
    defer require.deinit();
    try t.expectEqual(.none, require.verify);
    try t.expectEqual(.no_verification, try require.hostOption("db.example.com"));
    try t.expectEqual(.no_verification, require.caOption());

    const full = try Context.init(t.io, t.allocator, .{ .verify_full = "tests/root.crt" });
    defer full.deinit();
    try t.expectEqual(.full, full.verify);
    try t.expectString("db.example.com", (try full.hostOption("db.example.com")).explicit);
    try t.expectError(error.VerifyFullNeedsHostName, full.hostOption("127.0.0.1"));
    try t.expectError(error.VerifyFullNeedsHostName, full.hostOption("::1"));

    const ca = try Context.init(t.io, t.allocator, .{ .verify_ca = "tests/root.crt" });
    defer ca.deinit();
    try t.expectEqual(.no_verification, try ca.hostOption("127.0.0.1"));
    try std.testing.expect(ca.caOption() == .bundle);
}

test "std_tls: a CA file without certificates is refused" {
    try t.expectError(error.NoCertificatesInFile, Context.init(t.io, t.allocator, .{ .verify_ca = "tests/pg_hba.conf" }));
}
