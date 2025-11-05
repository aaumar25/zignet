const Network = @This();
const std = @import("std");
const builtin = @import("builtin");

const SockAddr = union(enum) {
    any: std.posix.sockaddr,
    ipv4: std.posix.sockaddr.in,
    ipv6: std.posix.sockaddr.in6,
};

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
            try writer.writeAll("]");
        }

        /// Parse an IPv6 representation according to the canonical format
        /// described in
        /// [RFC5952](https://datatracker.ietf.org/doc/html/rfc5952). The
        /// "scope ID" (otherwise known as "zone ID", `<zone_id>`) is
        /// intentionally not supported as parsing according to
        /// [RFC6874](https://datatracker.ietf.org/doc/html/rfc6874) is highly
        /// platform-specific and difficult to validate.
        /// (See https://www.w3.org/Bugs/Public/show_bug.cgi?id=27234#c2).
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
    /// Socket address
    sockaddr: SockAddr,
    /// Exit function, allowing users to run the function on blocking operation.
    exit_fn: ?*const fn () anyerror!void,

    pub const Error = error{ConnectionClosedByPeer};

    pub const Reader = switch (builtin.os.tag) {
        .windows => struct {
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

            fn stream(io_r: *std.Io.Reader, io_w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
                const dest = limit.slice(try io_w.writableSliceGreedy(1));
                var bufs: [1][]u8 = .{dest};
                const n = try readVec(io_r, &bufs);
                io_w.advance(n);
                return n;
            }

            fn readVec(io_r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
                const max_buffers_len = 8;
                const r: *Reader = @alignCast(@fieldParentPtr("interface", io_r));
                if (io_r.bufferedLen() == 0) {
                    // If the stream is not ready to read while there is nothing
                    // left in the buffer, it is the end of the stream.
                    if (!(readyToRead(r.fd, 0) catch
                        return error.ReadFailed))
                        return error.EndOfStream;
                }
                var iovecs: [max_buffers_len]std.os.windows.ws2_32.WSABUF = undefined;
                const bufs_n, const data_size = try io_r.writableVectorWsa(&iovecs, data);
                const bufs = iovecs[0..bufs_n];
                std.debug.assert(bufs[0].len != 0);
                const n = streamBufs(r, bufs) catch |err| {
                    r.error_state = err;
                    return error.ReadFailed;
                };
                if (n > data_size) {
                    io_r.seek = 0;
                    io_r.end = n - data_size;
                    return data_size;
                }
                return n;
            }

            fn handleRecvError(winsock_error: std.os.windows.ws2_32.WinsockError) Reader.Error!void {
                switch (winsock_error) {
                    .WSAECONNRESET => return error.ConnectionResetByPeer,
                    .WSAEFAULT => unreachable, // a pointer is not completely contained in user address space.
                    .WSAEINPROGRESS, .WSAEINTR => unreachable, // deprecated and removed in WSA 2.2
                    .WSAEINVAL => return error.SocketNotBound,
                    .WSAEMSGSIZE => return error.MessageTooBig,
                    .WSAENETDOWN => return error.NetworkSubsystemFailed,
                    .WSAENETRESET => return error.ConnectionResetByPeer,
                    .WSAENOTCONN => return error.SocketNotConnected,
                    .WSAEWOULDBLOCK => return error.WouldBlock,
                    .WSANOTINITIALISED => unreachable, // WSAStartup must be called before this function
                    .WSA_IO_PENDING => unreachable,
                    .WSA_OPERATION_ABORTED => unreachable, // not using overlapped I/O
                    else => |err| return std.os.windows.unexpectedWSAError(err),
                }
            }

            fn streamBufs(r: *Reader, bufs: []std.os.windows.ws2_32.WSABUF) Reader.Error!u32 {
                var flags: u32 = 0;
                var overlapped: std.os.windows.OVERLAPPED = std.mem.zeroes(std.os.windows.OVERLAPPED);

                var n: u32 = undefined;
                if (std.os.windows.ws2_32.WSARecv(
                    r.fd,
                    bufs.ptr,
                    @intCast(bufs.len),
                    &n,
                    &flags,
                    &overlapped,
                    null,
                ) == std.os.windows.ws2_32.SOCKET_ERROR) switch (std.os.windows.ws2_32.WSAGetLastError()) {
                    .WSA_IO_PENDING => {
                        var result_flags: u32 = undefined;
                        if (std.os.windows.ws2_32.WSAGetOverlappedResult(
                            r.fd,
                            &overlapped,
                            &n,
                            std.os.windows.TRUE,
                            &result_flags,
                        ) == std.os.windows.FALSE) try handleRecvError(std.os.windows.ws2_32.WSAGetLastError());
                    },
                    else => |winsock_error| try handleRecvError(winsock_error),
                };

                return n;
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

            /// Number of slices to store on the stack, when trying to send as many byte
            /// vectors through the underlying read calls as possible.
            const max_buffers_len = 16;

            fn stream(io_r: *std.Io.Reader, io_w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
                const dest = limit.slice(try io_w.writableSliceGreedy(1));
                var bufs: [1][]u8 = .{dest};
                const n = try readVec(io_r, &bufs);
                io_w.advance(n);
                return n;
            }

            /// Modified readVec to read when the socket is ready to read.
            fn readVec(io_r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
                const r: *Reader = @alignCast(@fieldParentPtr("interface", io_r));

                if (io_r.bufferedLen() == 0) {
                    // If the stream is not ready to read while there is nothing
                    // left in the buffer, it is the end of the stream.
                    if (!(readyToRead(r.fd, 0) catch
                        return error.ReadFailed))
                        return error.EndOfStream;
                }
                var iovecs_buffer: [max_buffers_len]std.posix.iovec = undefined;
                const dest_n, const data_size = try io_r.writableVectorPosix(&iovecs_buffer, data);
                const dest = iovecs_buffer[0..dest_n];
                std.debug.assert(dest[0].len > 0);
                const n = std.posix.readv(r.fd, dest) catch |err| {
                    r.error_state = err;
                    return error.ReadFailed;
                };
                if (n > data_size) {
                    io_r.seek = 0;
                    io_r.end = n - data_size;
                    return data_size;
                }
                return n;
            }
        },
    };
    pub const Writer = std.net.Stream.Writer;

    pub fn listen(
        endpoint: Endpoint,
        exit_fn: ?*const fn () anyerror!void,
    ) (std.posix.SocketError || std.posix.BindError ||
        std.posix.ListenError)!Socket {
        const sockaddr = endpoint.toSockAddr();
        const sockaddr_ptr: *const std.posix.sockaddr, const socklen: std.posix.socklen_t =
            switch (sockaddr) {
                .ipv4 => |in| .{ @ptrCast(&in), @sizeOf(@TypeOf(in)) },
                .ipv6 => |in6| .{ @ptrCast(&in6), @sizeOf(@TypeOf(in6)) },
                .any => |any| .{ &any, @sizeOf(@TypeOf(any)) },
            };
        // NOTE: Instead of providing protocol TCP, we use 0 since using protocol
        //       TCP does not allow to connect with hostname.
        // Create a socket
        const fd = try std.posix.socket(
            sockaddr_ptr.family,
            std.posix.SOCK.STREAM,
            0,
        );
        errdefer std.posix.close(fd);
        // Bind the socket to the specified endpoint
        try std.posix.bind(fd, sockaddr_ptr, socklen);
        try std.posix.listen(fd, 0);
        return .{ .fd = fd, .sockaddr = sockaddr, .exit_fn = exit_fn };
    }

    /// Connect to a server by endpoint.
    pub fn connect(
        endpoint: Endpoint,
        exit_fn: ?*const fn () anyerror!void,
    ) (std.posix.ConnectError || std.posix.SocketError)!Socket {
        const sockaddr = endpoint.toSockAddr();
        const sockaddr_ptr: *const std.posix.sockaddr, const socklen: std.posix.socklen_t =
            switch (sockaddr) {
                .ipv4 => |in| .{ @ptrCast(&in), @sizeOf(@TypeOf(in)) },
                .ipv6 => |in6| .{ @ptrCast(&in6), @sizeOf(@TypeOf(in6)) },
                .any => |any| .{ &any, @sizeOf(@TypeOf(any)) },
            };
        // NOTE: Instead of providing protocol TCP, we use 0 since using protocol
        //       TCP does not allow to connect with hostname.
        // Create a socket
        const fd = try std.posix.socket(
            sockaddr_ptr.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            std.posix.IPPROTO.TCP,
        );
        errdefer std.posix.close(fd);
        const socket: Socket =
            .{ .fd = fd, .sockaddr = sockaddr, .exit_fn = exit_fn };
        std.posix.connect(fd, sockaddr_ptr, socklen) catch |e| switch (e) {
            std.posix.ConnectError.WouldBlock => {
                // Wait until the sockeet is ready to write.
                try socket.waitToWrite();
                // Check whether the connect has completed successfully.
                // source:
                // https://man7.org/linux/man-pages/man2/connect.2.html
                // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect
                var opt: [@sizeOf(u32)]u8 = undefined;
                try std.posix.getsockopt(
                    socket.fd,
                    std.posix.SOL.SOCKET,
                    std.posix.SO.ERROR,
                    &opt,
                );
            },
            else => return e,
        };
        return socket;
    }

    /// Connect using a hostname. Anything that is allocated by this function
    /// is released before the function returns.
    pub fn connectToHost(
        allocator: std.mem.Allocator,
        name: []const u8,
        port: u16,
        exit_fn: ?*const fn () anyerror!void,
    ) !Socket {
        const list = try std.net.getAddressList(allocator, name, port);
        defer list.deinit();

        if (list.addrs.len == 0) return error.UnknownHostName;
        var err: std.posix.ConnectError = undefined;
        for (list.addrs) |addr| {
            const endpoint = try Endpoint.fromSockAddr(&addr.any);
            return Socket.connect(endpoint, exit_fn) catch |e| {
                switch (e) {
                    // These 3 errors are allowed to attempt reconnect by
                    // windows. With that allowance, instead of returning error,
                    // continue the next endpoint.
                    // see: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect
                    std.posix.ConnectError.ConnectionRefused => {
                        err = std.posix.ConnectError.ConnectionRefused;
                        continue;
                    },
                    std.posix.ConnectError.ConnectionTimedOut => {
                        err = std.posix.ConnectError.ConnectionTimedOut;
                        continue;
                    },
                    std.posix.ConnectError.NetworkUnreachable => {
                        err = std.posix.ConnectError.NetworkUnreachable;
                        continue;
                    },
                    else => return e,
                }
            };
        }
        // Return the latest `ConnectError` catched from the last endpoint.
        return err;
    }

    pub fn close(self: Socket) void {
        std.posix.close(self.fd);
    }

    pub fn accept(self: Socket) std.posix.AcceptError!Socket {
        var accepted_addr: SockAddr = .{ .any = undefined };
        var addr_size: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
        const fd = try std.posix.accept(
            self.fd,
            &accepted_addr.any,
            &addr_size,
            0,
        );

        return Socket{ .fd = fd, .sockaddr = accepted_addr };
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
        return std.net.Stream.Writer.init(
            .{ .handle = self.fd },
            buffer,
        );
    }

    // TODO: If zig support adding declaration in comptime, move this function
    //       to the Reader.
    /// Wait the socket until it is ready to read. If exit function is given,
    /// this execute the function and exit from this function if the exit function
    /// return error.
    pub fn waitToRead(self: Socket) anyerror!void {
        while (readyToRead(self.fd, 0)) |ready| {
            if (self.exit_fn) |exit|
                exit() catch |e| return e;
            if (ready) return;
        } else |e| return e;
    }

    // TODO: If zig support adding declaration in comptime, move this function
    //       to the Writer.
    /// Wait the socket until it is ready to write. If exit function is given,
    /// this execute the function and exit from this function if the exit function
    /// return error.
    pub fn waitToWrite(self: Socket) anyerror!void {
        while (readyToWrite(self.fd, 0)) |ready| {
            if (self.exit_fn) |exit|
                exit() catch |e| return e;
            if (ready) return;
        } else |e| return e;
    }

    // TODO: If zig support adding declaration in comptime, move this function
    //       to the Reader.
    /// Check if the socket is ready to read.
    pub fn readyToRead(
        fd: std.posix.socket_t,
        /// Time, in milliseconds, to wait. 0 return immediately. <0 blocking.
        timeout: i32,
    ) (std.posix.PollError || Error)!bool {
        const revents = try poll(fd, std.posix.POLL.RDNORM, timeout);

        if (checkRevents(revents, std.posix.POLL.HUP))
            return Error.ConnectionClosedByPeer;
        return checkRevents(revents, std.posix.POLL.RDNORM);
    }

    // TODO: If zig support adding declaration in comptime, move this function
    //       to the Writer.
    /// Check if the socket is ready to write.
    pub fn readyToWrite(
        fd: std.posix.socket_t,
        /// Time, in milliseconds, to wait. 0 return immediately. <0 blocking.
        timeout: i32,
    ) (std.posix.PollError || error{ConnectionClosedByPeer})!bool {
        const revents = try poll(fd, std.posix.POLL.OUT, timeout);
        if (checkRevents(revents, std.posix.POLL.HUP))
            return error.ConnectionClosedByPeer;
        return checkRevents(revents, std.posix.POLL.OUT);
    }

    fn checkRevents(revents: i16, mask: i16) bool {
        if (revents & mask == mask) return true else return false;
    }

    /// Query the socket status with the given event, return the revent.
    /// Note that `POLLHUP`, `POLLNVAL`, and `POLLERR` is always returned
    /// without any request.
    fn poll(
        socket: std.posix.socket_t,
        events: i16,
        /// Time, in milliseconds, to wait. 0 return immediately. <0 blocking.
        timeout: i32,
    ) std.posix.PollError!i16 {
        const fd: std.posix.pollfd = .{
            .fd = socket,
            .events = events,
            .revents = 0,
        };
        var poll_fd: [1]std.posix.pollfd = .{fd};
        // check whether the expected socket event happen
        _ = try std.posix.poll(&poll_fd, timeout);
        return poll_fd[0].revents;
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
        .any => |any| &any,
    };
    try std.testing.expectEqual(any.family, std.posix.AF.INET);
    // Convert back to endpoint
    const back = try Endpoint.fromSockAddr(any);
    try std.testing.expectEqual(ipv4, back);
}
