Minimal zig TCP library that fully comply with zig Writergate. Say no more to
blocking socket event by utilizing easy way to ensure the socket readiness.

### Prevent blocking on socket read and write
```zig
const zignet = @import("../src/zignet.zig");
const std = @import("std");

test {
    const endpoint: zignet.Endpoint = .{
        .addr = .{ .ipv4 = .parse("0.0.0.0") },
        .port = 9001,
    };

    var writer_buf: [4096]u8 = undefined;
    var reader_buf: [4096]u8 = undefined;

    const sock = try zignet.Socket.connect(endpoint, null);
    defer sock.close();
    var writer = sock.writer(&writer_buf);
    var reader = sock.reader(&reader_buf);

    // This call ensure that the socket is ready to write. Pass function with
    // type `fn () anyerror!void` to stop waiting the socket to be ready.
    try sock.waitToWrite();
    try writer.interface.write("Hello, World!");
    try writer.interface.flush();

    try sock.waitToRead();
    while (reader.interface.takeByte()) |byte| {
        std.debug.print("{c}", .{byte});
    } else |e| {
        switch (e) {
            error.EndOfStream => std.debug.print(
                "\nFinished reading\n",
                .{},
            ),
            error.ReadFailed => return e,
        }
    }
}

```
