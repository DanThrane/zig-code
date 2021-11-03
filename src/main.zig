const std = @import("std");
const StreamServer = std.net.StreamServer;
const Address = std.net.Address;
const ws = @import("ws.zig");

pub fn main() anyerror!void {
    var server = StreamServer.init(StreamServer.Options{});
    const address = try Address.parseIp4("0.0.0.0", 14000);
    try server.listen(address);
    std.log.info("Server is now ready on {}", .{address});

    while (true) {
        var connection = try server.accept();

        var session = try ws.ServerSession.init(std.heap.page_allocator, &connection);
        const result = session.handleHandshake() catch .Invalid;
        if (result != .Valid) {
            connection.stream.close();
            continue;
        }

        while (true) {
            switch (session.readFrame()) {
                .ReadyAndNeedsReset => {
                    if (session.opcode) |op| switch(op) {
                        .Text => {
                            const buffer = session.frameBuffer[0..session.ptr];
                            std.log.info("Text: {s}", .{buffer});
                            
                            session.sendFrame(.Text, buffer) catch break;
                        },

                        .Ping => {
                            std.log.info("Ping", .{});
                        },

                        .Pong => {
                            std.log.info("Pong", .{});
                        },

                        .Binary => {
                            std.log.info("Binary", .{});
                        },

                        else => {
                            std.log.info("Something else", .{});
                        },
                    };

                    std.log.info("We just received {}", .{session.opcode});

                    session.reset();
                },

                .NotReady => {
                    std.log.info("Not ready!", .{});
                    continue;
                },

                .Invalid => {
                    std.log.info("invalid", .{});
                    break;
                }
            }
        }

        connection.stream.close();
    }
}
