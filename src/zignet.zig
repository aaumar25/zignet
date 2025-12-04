const Network = @This();
const std = @import("std");

const builtin = @import("builtin");

const AddressFamily = enum { ipv4, ipv6 };

/// A network address abstraction. Contains one member for each possible type of address.
pub const Address = union(AddressFamily) {
    ipv4: IPv4,
    ipv6: IPv6,

    pub const Error = error{
        /// Invalid string to be parsed
        InvalidFormat,
    };

    pub fn parse(string: []const u8) Error!Address {
        return if (Address.IPv4.parse(string)) |ip|
            Address{ .ipv4 = ip }
        else |_| if (Address.IPv6.parse(string)) |ip|
            Address{ .ipv6 = ip }
        else |_|
            return error.InvalidFormat;
    }

    pub fn format(value: Address, writer: *std.io.Writer) !void {
        switch (value) {
            inline else => |a| try a.format(writer),
        }
    }

    pub const IPv4 = struct {
        value: [4]u8,

        pub fn format(self: IPv4, writer: *std.io.Writer) std.io.Writer.Error!void {
            try writer.print(
                "{}.{}.{}.{}",
                .{ self.value[0], self.value[1], self.value[2], self.value[3] },
            );
        }

        pub fn parse(string: []const u8) std.fmt.ParseIntError!IPv4 {
            var dot_it = std.mem.splitScalar(u8, string, '.');

            const d0 = dot_it.next().?; // is always != null
            const d1 = dot_it.next();
            const d2 = dot_it.next();
            const d3 = dot_it.next();

            var ip = IPv4{ .value = undefined };
            if (d3 != null) {
                ip.value[0] = try std.fmt.parseInt(u8, d0, 10);
                ip.value[1] = try std.fmt.parseInt(u8, d1.?, 10);
                ip.value[2] = try std.fmt.parseInt(u8, d2.?, 10);
                ip.value[3] = try std.fmt.parseInt(u8, d3.?, 10);
            } else if (d2 != null) {
                ip.value[0] = try std.fmt.parseInt(u8, d0, 10);
                ip.value[1] = try std.fmt.parseInt(u8, d1.?, 10);
                const int = try std.fmt.parseInt(u16, d2.?, 10);
                std.mem.writeInt(u16, ip.value[2..4], int, .big);
            } else if (d1 != null) {
                ip.value[0] = try std.fmt.parseInt(u8, d0, 10);
                const int = try std.fmt.parseInt(u24, d1.?, 10);
                std.mem.writeInt(u24, ip.value[1..4], int, .big);
            } else {
                const int = try std.fmt.parseInt(u32, d0, 10);
                std.mem.writeInt(u32, &ip.value, int, .big);
            }
            return ip;
        }
    };

    pub const IPv6 = struct {
        value: [16]u8,
        scope_id: u32,

        pub fn format(self: IPv6, writer: *std.io.Writer) std.io.Writer.Error!void {
            if (std.mem.eql(u8, self.value[0..12], &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
                try writer.print("[::ffff:{}.{}.{}.{}]", .{
                    self.value[12],
                    self.value[13],
                    self.value[14],
                    self.value[15],
                });
                return;
            }
            const big_endian_parts: *align(1) const [8]u16 = @ptrCast(&self.value);
            const native_endian_parts = switch (builtin.target.cpu.arch.endian()) {
                .big => big_endian_parts.*,
                .little => blk: {
                    var buf: [8]u16 = undefined;
                    for (big_endian_parts, 0..) |part, i| {
                        buf[i] = std.mem.bigToNative(u16, part);
                    }
                    break :blk buf;
                },
            };
            try writer.writeAll("[");
            var i: usize = 0;
            var abbrv = false;
            while (i < native_endian_parts.len) : (i += 1) {
                if (native_endian_parts[i] == 0) {
                    if (!abbrv) {
                        try writer.writeAll(if (i == 0) "::" else ":");
                        abbrv = true;
                    }
                    continue;
                }
                try writer.print("{x}", .{native_endian_parts[i]});
                if (i != native_endian_parts.len - 1) {
                    try writer.writeAll(":");
                }
            }
            if (self.scope_id != 0) try writer.print("%{d}", .{self.scope_id});
            try writer.writeAll("]");
        }

        /// Parse an IPv6 representation. Scope ID may be represented by suffix
        /// "%ID" where ID shall be number. This library does not support using
        /// Scope ID with device name, i.e., eth0.
        pub fn parse(string: []const u8) (Error || std.fmt.ParseIntError)!IPv6 {
            if (string.len < 2 or string.len > 39) {
                return error.InvalidFormat;
            }
            // Address cannot start or end with a single ':'.
            if ((string[0] == ':' and string[1] != ':') or
                (string[string.len - 2] != ':' and
                    string[string.len - 1] == ':'))
            {
                return error.InvalidFormat;
            }

            var ip: IPv6 = .{ .value = undefined, .scope_id = 0 };
            // Group index of abbreviation, to know how many groups have been
            // abbreviated.
            var abbreviated: ?u3 = null;
            // Current group index.
            var cg_index: u3 = 0;
            var groups: [8][]const u8 = .{""} ** 8;

            groups[0].ptr = string.ptr;

            for (string, 0..) |c, i| {
                switch (c) {
                    ':' => {
                        // Check for "::".
                        if (i + 1 < string.len and string[i + 1] == ':') {
                            // "::" cannot appear more than once.
                            if (abbreviated) |_| {
                                return error.InvalidFormat;
                            }
                            abbreviated = cg_index;
                            continue;
                        }

                        var abbreviation_ending: bool = false;
                        if (abbreviated != null and abbreviated.? == cg_index) {
                            // This ':' is the second in "::".
                            abbreviation_ending = true;
                        }

                        // Empty groups are not allowed, unless
                        // leading/trailing abbreviation.
                        if (groups[cg_index].len == 0 and
                            (!abbreviation_ending or
                                (i != 1 and i != string.len - 1)))
                        {
                            return error.InvalidFormat;
                        }

                        // Exactly 8 groups are allowed in a valid address.
                        if (cg_index == 7) {
                            return error.InvalidFormat;
                        }

                        cg_index += 1;
                        groups[cg_index].ptr = string[i + 1 ..].ptr;
                    },
                    'a'...'f', 'A'...'F', '0'...'9' => {
                        groups[cg_index].len += 1;
                    },
                    '%' => {
                        // Parse scope ID.
                        ip.scope_id = try std.fmt.parseUnsigned(u32, string[i + 1 ..], 0);
                        break;
                    },
                    else => {
                        return error.InvalidFormat;
                    },
                }
            }

            // Reorder groups to expand to exactly 8 groups if abbreviated.
            if (cg_index != 7) {
                if (abbreviated) |index| {
                    // Number of groups that must be copied past abbreviation
                    // expansion.
                    const num_groups_copy: usize = cg_index - index;
                    std.mem.copyBackwards(
                        []const u8,
                        groups[8 - num_groups_copy ..],
                        groups[index + 1 .. cg_index + 1],
                    );
                    @memset(groups[index + 1 .. 8 - num_groups_copy], "");
                } else {
                    return error.InvalidFormat;
                }
            }

            // Parse groups, after accounting for abbreviations.
            for (groups, 0..) |group, i| {
                if (group.len > 4) {
                    return error.InvalidFormat;
                }

                // Second byte in group to be parsed.
                var b2 = group;

                // First byte exists.
                if (group.len > 2) {
                    ip.value[i * 2] = try std.fmt.parseInt(
                        u8,
                        group[0 .. group.len - 2],
                        16,
                    );
                    b2 = group[group.len - 2 ..];
                } else {
                    ip.value[i * 2] = 0;
                }

                if (group.len > 0) {
                    ip.value[i * 2 + 1] = try std.fmt.parseInt(u8, b2, 16);
                } else {
                    ip.value[i * 2 + 1] = 0;
                }
            }

            return ip;
        }
    };
};

pub const Endpoint = struct {
    addr: Address,
    port: u16,

    const SockAddr = union(enum) {
        ipv4: std.posix.sockaddr.in,
        ipv6: std.posix.sockaddr.in6,
    };

    /// Convert the endpoint to the SockAddr based on the address family.
    pub fn toSockAddr(self: Endpoint) SockAddr {
        switch (self.addr) {
            .ipv4 => |addr| return .{
                .ipv4 = .{
                    .addr = @bitCast(addr.value),
                    .port = std.mem.nativeToBig(u16, self.port),
                },
            },
            .ipv6 => |addr| return .{
                .ipv6 = .{
                    .addr = addr.value,
                    .port = std.mem.nativeToBig(u16, self.port),
                    .flowinfo = 0,
                    .scope_id = addr.scope_id,
                },
            },
        }
    }

    pub fn fromSockAddr(sockaddr: *const std.posix.sockaddr) Error!Endpoint {
        if (sockaddr.family == std.posix.AF.INET) {
            const value: *align(4) const std.posix.sockaddr.in =
                @ptrCast(@alignCast(sockaddr));
            return .{
                .port = std.mem.bigToNative(u16, value.port),
                .addr = .{
                    .ipv4 = .{
                        .value = @bitCast(value.addr),
                    },
                },
            };
        } else if (sockaddr.family == std.posix.AF.INET6) {
            const value: *align(4) const std.posix.sockaddr.in6 =
                @ptrCast(@alignCast(sockaddr));
            return .{
                .port = std.mem.bigToNative(u16, value.port),
                .addr = .{
                    .ipv6 = .{
                        .value = @bitCast(value.addr),
                        .scope_id = value.scope_id,
                    },
                },
            };
        } else return Error.UnsupportedFamily;
    }

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try writer.print("{f}:{d}", .{ self.addr, self.port });
    }

    pub const Error = error{UnsupportedFamily};
};

/// A network socket. Create a socket by either call `listen()` to create a
/// server socket, `connect()` or `connectToHost()` to create a client socket.
/// The created socket must close the socket by calling `close()` at the end
/// of use. Read the message by calling `reader()` to use zig std.io.Reader and
/// write the message by calling `writer()` to use zig std.io.Writer.
pub const Socket = struct {
    /// File descriptor
    fd: std.posix.socket_t,

    pub const Error = (error{
        UnknownHostName,
        InterruptedByLocal,
    } ||
        std.posix.ConnectError ||
        std.posix.SocketError ||
        std.posix.ListenError ||
        std.posix.BindError ||
        std.posix.AcceptError);

    pub const Reader = switch (builtin.os.tag) {
        .windows => struct {
            /// Intended to be accessed directly by users.
            interface: std.Io.Reader,
            /// Intended to be accessed directly by users if necessary. Meant to
            /// store the file descriptor of the socket.
            fd: std.posix.socket_t,
            /// Shall not be accessed by users. Meant to keep the overlapped
            /// pointer valid.
            overlapped: ?std.os.windows.OVERLAPPED = null,
            /// Store the actual error if interface return `ReadFailed`.
            error_state: ?Reader.Error,

            pub const Error = std.posix.ReadError || error{
                SocketNotBound,
                MessageTooBig,
                NetworkSubsystemFailed,
                ConnectionResetByPeer,
                SocketNotConnected,
            };

            pub fn init(fd: std.posix.socket_t, buffer: []u8) Reader {
                return .{
                    .interface = .{
                        .vtable = &.{
                            .stream = stream,
                            .readVec = readVec,
                        },
                        .buffer = buffer,
                        .seek = 0,
                        .end = 0,
                    },
                    .fd = fd,
                    .error_state = null,
                };
            }

            fn stream(
                io_r: *std.Io.Reader,
                io_w: *std.Io.Writer,
                limit: std.Io.Limit,
            ) std.Io.Reader.StreamError!usize {
                const dest = limit.slice(try io_w.writableSliceGreedy(1));
                var bufs: [1][]u8 = .{dest};
                const n = try readVec(io_r, &bufs);
                io_w.advance(n);
                return n;
            }

            fn readVec(
                io_r: *std.Io.Reader,
                data: [][]u8,
            ) std.Io.Reader.Error!usize {
                const max_buffers_len = 8;
                const r: *Reader =
                    @alignCast(@fieldParentPtr("interface", io_r));
                var iovecs: [max_buffers_len]std.os.windows.ws2_32.WSABUF =
                    undefined;
                const bufs_n, const data_size =
                    try io_r.writableVectorWsa(&iovecs, data);
                const bufs = iovecs[0..bufs_n];
                std.debug.assert(bufs[0].len != 0);
                var n: u32 = undefined;
                if (r.overlapped) |_| {
                    var result_flags: u32 = undefined;
                    if (std.os.windows.ws2_32.WSAGetOverlappedResult(
                        r.fd,
                        &r.overlapped.?,
                        &n,
                        std.os.windows.FALSE,
                        &result_flags,
                    ) == std.os.windows.FALSE) {
                        handleRecvError(std.os
                            .windows.ws2_32.WSAGetLastError()) catch |err| {
                            if (err == error.WouldBlock)
                                return error.EndOfStream;
                            r.error_state = err;
                            return error.ReadFailed;
                        };
                    }
                    r.overlapped = null;
                } else {
                    var flags: u32 = 0;
                    r.overlapped = std.mem.zeroInit(std.os.windows.OVERLAPPED, .{});
                    if (std.os.windows.ws2_32.WSARecv(
                        r.fd,
                        bufs.ptr,
                        @intCast(bufs.len),
                        &n,
                        &flags,
                        &r.overlapped.?,
                        null,
                    ) == std.os.windows.ws2_32.SOCKET_ERROR)
                        // Keep the IO reads until new message is received.
                        handleRecvError(std.os
                            .windows.ws2_32.WSAGetLastError()) catch |err| {
                            if (err == error.WouldBlock) return error.EndOfStream;
                            r.error_state = err;
                            return error.ReadFailed;
                        };
                }
                // If 0 bytes are received, the connection was closed gracefully
                // from remote end.
                if (n == 0) {
                    r.error_state = Reader.Error.ConnectionResetByPeer;
                    return error.ReadFailed;
                }
                if (n > data_size) {
                    io_r.seek = 0;
                    io_r.end = n - data_size;
                    return data_size;
                }
                return n;
            }

            fn handleRecvError(
                winsock_error: std.os.windows.ws2_32.WinsockError,
            ) Reader.Error!void {
                switch (winsock_error) {
                    .WSAECONNRESET => return error.ConnectionResetByPeer,
                    // a pointer is not completely contained in user address
                    // space.
                    .WSAEFAULT => unreachable,
                    // deprecated and removed in WSA 2.2
                    .WSAEINPROGRESS, .WSAEINTR => unreachable,
                    .WSAEINVAL => return error.SocketNotBound,
                    .WSAEMSGSIZE => return error.MessageTooBig,
                    .WSAENETDOWN => return error.NetworkSubsystemFailed,
                    .WSAENETRESET => return error.ConnectionResetByPeer,
                    .WSAENOTCONN => return error.SocketNotConnected,
                    .WSAEWOULDBLOCK,
                    .WSA_IO_PENDING,
                    .WSA_IO_INCOMPLETE,
                    => return error.WouldBlock,
                    // WSAStartup must be called before this function.
                    .WSANOTINITIALISED => unreachable,
                    // not using overlapped I/O.
                    .WSA_OPERATION_ABORTED => unreachable,
                    else => |err| return std.os.windows.unexpectedWSAError(err),
                }
            }
        },
        else => struct {
            interface: std.Io.Reader,
            fd: std.posix.socket_t,
            error_state: ?Reader.Error,

            pub const Error = std.posix.ReadError || error{
                SocketNotBound,
                MessageTooBig,
                NetworkSubsystemFailed,
                ConnectionResetByPeer,
                SocketNotConnected,
            };

            pub fn init(fd: std.posix.socket_t, buffer: []u8) Reader {
                return .{
                    .interface = .{
                        .vtable = &.{
                            .stream = stream,
                            .readVec = readVec,
                        },
                        .buffer = buffer,
                        .seek = 0,
                        .end = 0,
                    },
                    .fd = fd,
                    .error_state = null,
                };
            }

            /// Number of slices to store on the stack, when trying to send as
            /// many byte vectors through the underlying read calls as possible.
            const max_buffers_len = 8;

            fn stream(
                io_r: *std.Io.Reader,
                io_w: *std.Io.Writer,
                limit: std.Io.Limit,
            ) std.Io.Reader.StreamError!usize {
                const dest = limit.slice(try io_w.writableSliceGreedy(1));
                var bufs: [1][]u8 = .{dest};
                const n = try readVec(io_r, &bufs);
                io_w.advance(n);
                return n;
            }

            /// Modified readVec
            fn readVec(
                io_r: *std.Io.Reader,
                data: [][]u8,
            ) std.Io.Reader.Error!usize {
                const r: *Reader =
                    @alignCast(@fieldParentPtr("interface", io_r));
                var iovecs_buffer: [max_buffers_len]std.posix.iovec = undefined;
                const dest_n, const data_size =
                    try io_r.writableVectorPosix(&iovecs_buffer, data);
                const dest = iovecs_buffer[0..dest_n];
                std.debug.assert(dest[0].len > 0);
                const n = std.posix.readv(r.fd, dest) catch |err| {
                    // Handle `WouldBlock` to `EndOfStream`. The user has to
                    // ensure that the socket is already receiving a message.
                    if (err == std.posix.ReadError.WouldBlock)
                        return error.EndOfStream;
                    r.error_state = err;
                    return error.ReadFailed;
                };
                // If 0 bytes are received, the connection was closed gracefully
                // from remote end.
                if (n == 0) {
                    r.error_state = Reader.Error.ConnectionResetByPeer;
                    return error.ReadFailed;
                }
                if (n > data_size) {
                    io_r.seek = 0;
                    io_r.end = n - data_size;
                    return data_size;
                }
                return n;
            }
        },
    };
    pub const Writer = switch (builtin.os.tag) {
        .windows => struct {
            interface: std.Io.Writer,
            fd: std.posix.socket_t,
            error_state: ?Writer.Error = null,

            pub const Error = std.posix.SendMsgError || error{
                ConnectionResetByPeer,
                SocketNotBound,
                MessageTooBig,
                NetworkSubsystemFailed,
                SystemResources,
                SocketNotConnected,
                Unexpected,
            };

            pub fn init(fd: std.posix.socket_t, buffer: []u8) Writer {
                return .{
                    .interface = .{
                        .vtable = &.{ .drain = drain },
                        .buffer = buffer,
                    },
                    .fd = fd,
                    .error_state = null,
                };
            }

            fn addWsaBuf(
                v: []std.os.windows.ws2_32.WSABUF,
                i: *u32,
                bytes: []const u8,
            ) void {
                const cap = std.math.maxInt(u32);
                var remaining = bytes;
                while (remaining.len > cap) {
                    if (v.len - i.* == 0) return;
                    v[i.*] = .{ .buf = @constCast(remaining.ptr), .len = cap };
                    i.* += 1;
                    remaining = remaining[cap..];
                } else {
                    @branchHint(.likely);
                    if (v.len - i.* == 0) return;
                    v[i.*] = .{
                        .buf = @constCast(remaining.ptr),
                        .len = @intCast(remaining.len),
                    };
                    i.* += 1;
                }
            }

            fn drain(
                io_w: *std.Io.Writer,
                data: []const []const u8,
                splat: usize,
            ) std.Io.Writer.Error!usize {
                const max_buffers_len = 8;
                const w: *Writer =
                    @alignCast(@fieldParentPtr("interface", io_w));
                const buffered = io_w.buffered();
                comptime std.debug.assert(builtin.os.tag == .windows);
                var iovecs: [max_buffers_len]std.os.windows.ws2_32.WSABUF =
                    undefined;
                var len: u32 = 0;
                addWsaBuf(&iovecs, &len, buffered);
                for (data[0 .. data.len - 1]) |bytes|
                    addWsaBuf(&iovecs, &len, bytes);
                const pattern = data[data.len - 1];
                if (iovecs.len - len != 0) switch (splat) {
                    0 => {},
                    1 => addWsaBuf(&iovecs, &len, pattern),
                    else => switch (pattern.len) {
                        0 => {},
                        1 => {
                            const splat_buffer_candidate =
                                io_w.buffer[io_w.end..];
                            var backup_buffer: [64]u8 = undefined;
                            const splat_buffer = if (splat_buffer_candidate
                                .len >= backup_buffer.len)
                                splat_buffer_candidate
                            else
                                &backup_buffer;
                            const memset_len = @min(splat_buffer.len, splat);
                            const buf = splat_buffer[0..memset_len];
                            @memset(buf, pattern[0]);
                            addWsaBuf(&iovecs, &len, buf);
                            var remaining_splat = splat - buf.len;
                            while (remaining_splat > splat_buffer.len and
                                len < iovecs.len)
                            {
                                addWsaBuf(&iovecs, &len, splat_buffer);
                                remaining_splat -= splat_buffer.len;
                            }
                            addWsaBuf(
                                &iovecs,
                                &len,
                                splat_buffer[0..remaining_splat],
                            );
                        },
                        else => for (0..@min(splat, iovecs.len - len)) |_| {
                            addWsaBuf(&iovecs, &len, pattern);
                        },
                    },
                };
                const n =
                    sendBufs(w.fd, iovecs[0..len]) catch |err| n: {
                        if (err == Writer.Error.WouldBlock) break :n 0;
                        w.error_state = err;
                        return error.WriteFailed;
                    };
                return io_w.consume(n);
            }

            fn handleSendError(
                winsock_error: std.os.windows.ws2_32.WinsockError,
            ) Writer.Error!void {
                switch (winsock_error) {
                    .WSAECONNABORTED => return error.ConnectionResetByPeer,
                    .WSAECONNRESET => return error.ConnectionResetByPeer,
                    // a pointer is not completely contained in user address
                    // space.
                    .WSAEFAULT => unreachable,
                    // deprecated and removed in WSA 2.2
                    .WSAEINPROGRESS, .WSAEINTR => unreachable,
                    .WSAEINVAL => return error.SocketNotBound,
                    .WSAEMSGSIZE => return error.MessageTooBig,
                    .WSAENETDOWN => return error.NetworkSubsystemFailed,
                    .WSAENETRESET => return error.ConnectionResetByPeer,
                    .WSAENOBUFS => return error.SystemResources,
                    .WSAENOTCONN => return error.SocketNotConnected,
                    .WSAENOTSOCK => unreachable, // not a socket
                    // only for message-oriented sockets
                    .WSAEOPNOTSUPP => unreachable,
                    // cannot send on a socket after write shutdown
                    .WSAESHUTDOWN => unreachable,
                    .WSAEWOULDBLOCK => return error.WouldBlock,
                    // WSAStartup must be called before this function
                    .WSANOTINITIALISED => unreachable,
                    .WSA_IO_PENDING => unreachable,
                    // not using overlapped I/O
                    .WSA_OPERATION_ABORTED => unreachable,
                    else => |err| return std.os.windows.unexpectedWSAError(err),
                }
            }

            fn sendBufs(
                fd: std.posix.socket_t,
                bufs: []std.os.windows.ws2_32.WSABUF,
            ) Writer.Error!u32 {
                var n: u32 = undefined;
                var overlapped: std.os.windows.OVERLAPPED =
                    std.mem.zeroes(std.os.windows.OVERLAPPED);
                if (std.os.windows.ws2_32.WSASend(
                    fd,
                    bufs.ptr,
                    @intCast(bufs.len),
                    &n,
                    0,
                    &overlapped,
                    null,
                ) == std.os.windows.ws2_32.SOCKET_ERROR)
                    switch (std.os.windows.ws2_32.WSAGetLastError()) {
                        .WSA_IO_PENDING => {
                            var result_flags: u32 = undefined;
                            if (std.os.windows.ws2_32.WSAGetOverlappedResult(
                                fd,
                                &overlapped,
                                &n,
                                std.os.windows.TRUE,
                                &result_flags,
                            ) == std.os.windows.FALSE)
                                try handleSendError(std.os.windows.ws2_32
                                    .WSAGetLastError());
                        },
                        else => |winsock_error| {
                            try handleSendError(winsock_error);
                        },
                    };

                return n;
            }
        },
        else => struct {
            interface: std.Io.Writer,
            fd: std.posix.socket_t,
            error_state: ?Writer.Error = null,

            pub const Error = std.posix.SendMsgError || error{
                ConnectionResetByPeer,
                SocketNotBound,
                MessageTooBig,
                NetworkSubsystemFailed,
                SystemResources,
                SocketNotConnected,
                Unexpected,
            };

            pub fn init(fd: std.posix.socket_t, buffer: []u8) Writer {
                return .{
                    .interface = .{
                        .vtable = &.{ .drain = drain },
                        .buffer = buffer,
                    },
                    .fd = fd,
                    .error_state = null,
                };
            }

            fn addBuf(
                v: []std.posix.iovec_const,
                i: *@FieldType(std.posix.msghdr_const, "iovlen"),
                bytes: []const u8,
            ) void {
                // OS checks ptr addr before length so zero length vectors must
                // be omitted.
                if (bytes.len == 0) return;
                if (v.len - i.* == 0) return;
                v[i.*] = .{ .base = bytes.ptr, .len = bytes.len };
                i.* += 1;
            }

            fn drain(
                io_w: *std.Io.Writer,
                data: []const []const u8,
                splat: usize,
            ) std.Io.Writer.Error!usize {
                const max_buffers_len = 8;
                const w: *Writer =
                    @alignCast(@fieldParentPtr("interface", io_w));
                const buffered = io_w.buffered();
                var iovecs: [max_buffers_len]std.posix.iovec_const = undefined;
                var msg: std.posix.msghdr_const = .{
                    .name = null,
                    .namelen = 0,
                    .iov = &iovecs,
                    .iovlen = 0,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                };
                addBuf(&iovecs, &msg.iovlen, buffered);
                for (data[0 .. data.len - 1]) |bytes|
                    addBuf(&iovecs, &msg.iovlen, bytes);
                const pattern = data[data.len - 1];
                if (iovecs.len - msg.iovlen != 0) switch (splat) {
                    0 => {},
                    1 => addBuf(&iovecs, &msg.iovlen, pattern),
                    else => switch (pattern.len) {
                        0 => {},
                        1 => {
                            const splat_buffer_candidate =
                                io_w.buffer[io_w.end..];
                            var backup_buffer: [64]u8 = undefined;
                            const splat_buffer =
                                if (splat_buffer_candidate.len >= backup_buffer
                                    .len)
                                    splat_buffer_candidate
                                else
                                    &backup_buffer;
                            const memset_len = @min(splat_buffer.len, splat);
                            const buf = splat_buffer[0..memset_len];
                            @memset(buf, pattern[0]);
                            addBuf(&iovecs, &msg.iovlen, buf);
                            var remaining_splat = splat - buf.len;
                            while (remaining_splat > splat_buffer.len and
                                iovecs.len - msg.iovlen != 0)
                            {
                                std.debug.assert(buf.len == splat_buffer.len);
                                addBuf(&iovecs, &msg.iovlen, splat_buffer);
                                remaining_splat -= splat_buffer.len;
                            }
                            addBuf(
                                &iovecs,
                                &msg.iovlen,
                                splat_buffer[0..remaining_splat],
                            );
                        },
                        else => {
                            for (0..@min(splat, iovecs.len - msg.iovlen)) |_| {
                                addBuf(&iovecs, &msg.iovlen, pattern);
                            }
                        },
                    },
                };
                const flags = std.posix.MSG.NOSIGNAL | std.posix.MSG.DONTWAIT;
                return io_w.consume(std.posix.sendmsg(
                    w.fd,
                    &msg,
                    flags,
                ) catch |err| {
                    if (err == Writer.Error.WouldBlock) return 0;
                    w.error_state = err;
                    return error.WriteFailed;
                });
            }
        },
    };

    pub fn listen(
        endpoint: Endpoint,
    ) Error!Socket {
        // Have to return any error due to the nature of the `exit_fn`
        const sockaddr = endpoint.toSockAddr();
        const sockaddr_ptr: *const std.posix.sockaddr, const socklen: std
            .posix.socklen_t =
            switch (sockaddr) {
                .ipv4 => |in| .{ @ptrCast(&in), @sizeOf(@TypeOf(in)) },
                .ipv6 => |in6| .{ @ptrCast(&in6), @sizeOf(@TypeOf(in6)) },
            };
        // NOTE: Instead of providing protocol TCP, we use 0 since using protocol
        //       TCP does not allow to connect with hostname.
        // Create a blocking socket for listening to incoming connection.
        const fd = try std.posix.socket(
            sockaddr_ptr.family,
            std.posix.SOCK.STREAM,
            0,
        );
        errdefer std.posix.close(fd);
        // Bind the socket to the specified endpoint
        try std.posix.bind(fd, sockaddr_ptr, socklen);
        try std.posix.listen(fd, 0);
        return .{ .fd = fd };
    }

    /// Connect to a server by endpoint.
    pub fn connect(
        /// Remote endpoint to be connected.
        endpoint: Endpoint,
        /// Custom function to interrupt the connect process.
        interrupt_fn: ?*const fn () anyerror!void,
        /// Time, in milliseconds, to wait for the connection to establish.
        /// 0 return `error.ConnectionTimedOut` if the connection is not
        /// established instantly. Providing value less than 0 means infinite
        /// timeout.
        timeout: u64,
    ) Error!Socket {
        // Have to return any error due to the nature of the `exit_fn`
        const sockaddr = endpoint.toSockAddr();
        const sockaddr_ptr: *const std.posix.sockaddr, const socklen: std.posix
            .socklen_t =
            switch (sockaddr) {
                .ipv4 => |in| .{
                    @ptrCast(@alignCast(&in)),
                    @sizeOf(@TypeOf(in)),
                },
                .ipv6 => |in6| .{
                    @ptrCast(@alignCast(&in6)),
                    @sizeOf(@TypeOf(in6)),
                },
            };
        // Create a nonblocking socket.
        const fd = try std.posix.socket(
            sockaddr_ptr.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            std.posix.IPPROTO.TCP,
        );
        errdefer std.posix.close(fd);
        const socket: Socket = .{ .fd = fd };
        std.posix.connect(socket.fd, sockaddr_ptr, socklen) catch |e|
            switch (e) {
                std.posix.ConnectError.WouldBlock => {
                    // Wait until the socket is ready to write.
                    var timer = std.time.Timer.start() catch
                        {
                            @branchHint(.unlikely);
                            @panic("TimerUnsupported");
                        };
                    const pollfd: std.posix.pollfd = .{
                        .fd = fd,
                        .events = std.posix.POLL.OUT,
                        .revents = 0,
                    };
                    var pollfds: [1]std.posix.pollfd = .{pollfd};
                    while (true) {
                        if (timer.read() / std.time.ns_per_ms > timeout)
                            return std.posix.ConnectError.ConnectionTimedOut;
                        if (interrupt_fn) |interrupt| interrupt() catch
                            return Error.InterruptedByLocal;
                        _ = try std.posix.poll(&pollfds, 0);
                        // Socket ready to write. Connection established.
                        if (pollfds[0].revents & std.posix.POLL.OUT ==
                            std.posix.POLL.OUT) break;
                        // Connection was reset by peer before connect could
                        // complete.
                        if (pollfds[0].revents & std.posix.POLL.HUP ==
                            std.posix.POLL.HUP)
                            return std.posix.ConnectError.ConnectionResetByPeer;
                    }
                },
                else => return e,
            };
        return socket;
    }

    /// Connect using a hostname. Anything that is allocated by this function
    /// is released before the function returns.
    pub fn connectToHost(
        allocator: std.mem.Allocator,
        /// The host name of the server.
        name: []const u8,
        /// Port of the host.
        port: u16,
        /// Custom function to interrupt the connect process.
        interrupt_fn: ?*const fn () anyerror!void,
        /// Time, in milliseconds, to wait for the connection of each found
        /// endpoint to establish. 0 return `error.ConnectionTimedOut` if the
        /// connection is not established instantly. Providing value less than 0
        /// means infinite timeout.
        timeout: u64,
    ) (Error || Endpoint.Error)!Socket {
        const list = std.net.getAddressList(allocator, name, port) catch
            return error.UnknownHostName;
        defer list.deinit();

        if (list.addrs.len == 0) return error.UnknownHostName;
        var err: (std.posix.ConnectError || Error) = undefined;
        for (list.addrs) |addr| {
            const endpoint = try Endpoint.fromSockAddr(&addr.any);
            return Socket.connect(endpoint, interrupt_fn, timeout) catch |e| {
                // Save the latest error. Continue to the next endpoint.
                err = e;
                continue;
            };
        }
        // Return the latest error catched from the last endpoint.
        return err;
    }

    pub fn close(self: Socket) void {
        std.posix.close(self.fd);
    }

    pub fn accept(
        self: Socket,
    ) Error!Socket {
        var accepted_addr: std.posix.sockaddr.storage = undefined;
        var addr_size: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
        const accepted_addr_ptr: *std.posix.sockaddr = @ptrCast(&accepted_addr);
        const fd = try std.posix.accept(
            self.fd,
            accepted_addr_ptr,
            &addr_size,
            std.posix.SOCK.NONBLOCK,
        );
        return .{ .fd = fd };
    }

    pub fn getLocalEndPoint(self: Socket) (Endpoint.Error ||
        std.posix.GetSockNameError)!Endpoint {
        var sockaddr: std.posix.sockaddr.storage = undefined;
        var sockaddr_len: std.posix.socklen_t =
            @sizeOf(std.posix.sockaddr.storage);
        const sockaddr_ptr: *std.posix.sockaddr = @ptrCast(&sockaddr);
        try std.posix.getsockname(self.fd, sockaddr_ptr, &sockaddr_len);
        return try Endpoint.fromSockAddr(sockaddr_ptr);
    }

    pub fn getRemoteEndPoint(self: Socket) (Endpoint.Error ||
        std.posix.GetSockNameError)!Endpoint {
        var sockaddr: std.posix.sockaddr.storage = undefined;
        var sockaddr_len: std.posix.socklen_t =
            @sizeOf(std.posix.sockaddr.storage);
        const sockaddr_ptr: *std.posix.sockaddr = @ptrCast(&sockaddr);
        try std.posix.getpeername(self.fd, sockaddr_ptr, &sockaddr_len);
        return try Endpoint.fromSockAddr(sockaddr_ptr);
    }

    /// Return `Socket.Reader`. Use `Socket.Reader.Interface` as the interface
    /// to std.Io.Reader in order to read the message. Note that the socket is
    /// blocking if there is no message to be read. Consider call `waitToRead()`
    /// to ensure the socket is ready to read.
    pub fn reader(self: Socket, buffer: []u8) Reader {
        return Reader.init(self.fd, buffer);
    }

    /// Return `Socket.Writer`. Use `Socket.Writer.Interface` as the interface
    /// to std.Io.Writer in order to write the message. Note that the socket is
    /// blocking if the writer buffer is full. Consider call `waitToWrite()`
    /// to ensure the socket is ready to write.
    pub fn writer(self: Socket, buffer: []u8) Writer {
        // Falls back to std.net.Stream.Writer. No necessity to write own Writer.
        return Writer.init(self.fd, buffer);
    }
};

test "convert sockaddr" {
    const ipv4: Endpoint = .{
        .addr = .{ .ipv4 = try .parse("127.0.0.1") },
        .port = 1000,
    };
    const sockaddr = ipv4.toSockAddr();
    // TODO: Make the following declaration as a function.
    const any: *const std.posix.sockaddr = switch (sockaddr) {
        .ipv4 => |in| @ptrCast(&in),
        .ipv6 => |in6| @ptrCast(&in6),
    };
    try std.testing.expectEqual(any.family, std.posix.AF.INET);
    // Convert back to endpoint
    const back = try Endpoint.fromSockAddr(any);
    try std.testing.expectEqual(ipv4, back);
}

test {
    std.testing.refAllDeclsRecursive(@This());
}
