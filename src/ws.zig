const std = @import("std");
const StreamServer = std.net.StreamServer;

const WC_SHA_BLOCK_SIZE = 64;
const WC_SHA_DIGEST_SIZE = 20;
const WC_SHA_PAD_SIZE = 56;
const wc_Sha = struct {
    buffLen: i32 = 0,
    loLen: i32 = 0,
    hiLen: i32 = 0,
    buffer: [16]i32 = undefined,
    digest: [5]i32 = undefined,
    heap: ?[*]u8 = null,
};
extern "wolfssl" fn wc_InitSha(instance: ?*wc_Sha) i32;
extern "wolfssl" fn wc_InitSha_ex(sha: *wc_Sha, heap: *u8, devId: i32) i32;
extern "wolfssl" fn wc_ShaUpdate(sha: *wc_Sha, *u8, i32) i32;
extern "wolfssl" fn wc_ShaFinalRaw(sha: *wc_Sha, data: *u8) i32;
extern "wolfssl" fn wc_ShaFinal(sha: *wc_Sha, data: *u8) i32;
extern "wolfssl" fn wc_ShaFree(sha: *wc_Sha) void;

const websocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const WebSocketOpCode = enum(u8) {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    ConnectionClose = 0x8,
    Ping = 0x9,
    Pong = 0xA,
    Invalid = 0xFF,

    fn parse(value: u8) WebSocketOpCode {
        if (value == @enumToInt(WebSocketOpCode.Continuation)) return WebSocketOpCode.Continuation;
        if (value == @enumToInt(WebSocketOpCode.Text)) return WebSocketOpCode.Text;
        if (value == @enumToInt(WebSocketOpCode.Binary)) return WebSocketOpCode.Binary;
        if (value == @enumToInt(WebSocketOpCode.ConnectionClose)) return WebSocketOpCode.ConnectionClose;
        if (value == @enumToInt(WebSocketOpCode.Ping)) return WebSocketOpCode.Ping;
        if (value == @enumToInt(WebSocketOpCode.Pong)) return WebSocketOpCode.Pong;
        return WebSocketOpCode.Invalid;
    }
};

pub const FrameAssemblyResult = enum { Invalid, ReadyAndNeedsReset, NotReady };

pub const ServerSession = struct {
    parentAllocator: *std.mem.Allocator,
    ptr: u64 = 0,
    opcode: ?WebSocketOpCode = null,
    arena: std.heap.ArenaAllocator,
    connection: *StreamServer.Connection,
    frameBuffer: []u8,
    readBuffer: []u8,
    reader: std.io.BufferedReader(4096, std.net.Stream.Reader),
    writer: std.io.BufferedWriter(4096, std.net.Stream.Writer),

    pub fn init(
        allocator: *std.mem.Allocator, 
        connection: *StreamServer.Connection
    ) std.mem.Allocator.Error!ServerSession {
        var buffer = try allocator.alloc(u8, 1024 * 256);
        var readBuffer = try allocator.alloc(u8, 1024 * 8);
        var arena = std.heap.ArenaAllocator.init(allocator);

        return ServerSession{
            .parentAllocator = allocator,
            .readBuffer = readBuffer,
            .frameBuffer = buffer,
            .arena = arena,
            .connection = connection,
            .reader = std.io.bufferedReader(connection.stream.reader()),
            .writer = std.io.bufferedWriter(connection.stream.writer()),
        };
    }

    pub fn destroy(self: *ServerSession) void {
        self.parentAllocator.free(self.frameBuffer);
        self.arena.deinit();
    }

    pub fn reset(self: *ServerSession) void {
        self.ptr = 0;
        self.opcode = null;
    }

    pub fn handleHandshake(self: *ServerSession) !WebSocketHandshakeResult {
        var reader = self.reader.reader();

        // NOTE(Dan): We start by parsing the request line
        const requestLine = try reader.readUntilDelimiter(self.readBuffer, '\n');
        var requestLineIterator = std.mem.tokenize(u8, requestLine, " ");
        const method = requestLineIterator.next();
        const path = requestLineIterator.next();
        const httpVersion = requestLineIterator.next();
        const trailing = requestLineIterator.next();

        if (httpVersion) |version| {
            if (!std.mem.eql(u8, version, "HTTP/1.1\r")) return .Invalid;
        }

        if (trailing != null or httpVersion == null or method == null) {
            // Don't even attempt to handle protocols we don't understand
            return .Invalid;
        }

        const allocator = &self.arena.allocator;

        if (method.?.len > 20) return .Invalid;
        const upperMethod = std.ascii.upperString(
            try allocator.alloc(u8, 20),
            method.?
        );

        if (!std.mem.eql(u8, upperMethod, "GET")) {
            try self.sendHttpResponse(405, 0, null);
            return .Invalid;
        }

        // NOTE(Dan): At this point we know that we are receiving an HTTP request we understand with the correct method
        // Next up, we will parse the headers
        var upgradeToWebSocket: bool = false;
        var wsKey: ?[]const u8 = null;
        var wsVersion: ?[]const u8 = null;

        // TODO(dan): potential DoS if the server keeps sending non-empty lines
        while (true) {
            // TODO(Dan): Might want to be smarter about invalid headers than just closing the connection
            const line = std.mem.trimRight(
                u8, 
                try reader.readUntilDelimiter(self.readBuffer, '\n'),
                &[_]u8{'\r'}
            );
            if (std.mem.eql(u8, line, "")) break;

            var tokens = std.mem.tokenize(u8, line, ":");
            const rawKey = tokens.next() orelse return .Invalid;
            const value = tokens.next() orelse return .Invalid;
            const key = try std.ascii.allocLowerString(allocator, rawKey);

            if (std.mem.eql(u8, key, "upgrade")) {
                const normalizedValue = try normalizeHeaderValue(allocator, value);
                if (std.mem.eql(u8, normalizedValue, "websocket")) {
                    upgradeToWebSocket = true;
                }
            } else if (std.mem.eql(u8, key, "sec-websocket-key")) {
                wsKey = try normalizeHeaderValue(allocator, value);
            } else if (std.mem.eql(u8, key, "sec-websocket-version")) {
                wsVersion = try normalizeHeaderValue(allocator, value);
            }
        }


        if (upgradeToWebSocket) {
            if (wsKey == null or wsVersion == null) {
                try self.sendHttpResponse(400, 0, null);
                return .Invalid;
            }

            // NOTE(Dan): Check if we understand this version of WebSockets. We only support RFC 6455 (version 13).
            var versions = std.mem.tokenize(u8, wsVersion.?, ",");
            var versionIsSupported = false;
            while (true) {
                var version = versions.next();
                if (version) |v| {
                    const trimmedVersion = std.mem.trim(u8, v, &std.ascii.spaces);
                    if (std.mem.eql(u8, trimmedVersion, "13")) {
                        versionIsSupported = true;
                        break;
                    }
                } else {
                    break;
                }
            }

            if (!versionIsSupported) {
                try self.sendHttpResponse(400, 0, null);
                return .Invalid;
            }

            var wsAcceptKeyBuffer: [64]u8 = undefined;
            var websocketAcceptValue = blk: {
                var valueToHash = try std.mem.concat(
                    allocator, 
                    u8, 
                    &[_][]const u8{wsKey.?, websocketGuid}
                );
                var hash: [WC_SHA_DIGEST_SIZE]u8 = undefined;
                var sha = wc_Sha{};
                _ = wc_InitSha(&sha);
                _ = wc_ShaUpdate(&sha, &valueToHash[0], @intCast(i32, valueToHash.len));
                _ = wc_ShaFinal(&sha, &hash[0]);

                break :blk std.base64.standard.Encoder.encode(&wsAcceptKeyBuffer, &hash);
            };

            try self.sendHttpResponse(
                101, 
                0, 
                try std.fmt.allocPrint(
                    allocator, 
                    "Sec-WebSocket-Accept: {s}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n", 
                    .{websocketAcceptValue}
                )
            );

            return .Valid;
        }

        _ = path;
        try self.sendHttpResponse(200, 0, null);
        return .Valid;
    }

    /// Sends the HTTP response header (without a response)
    /// The `headers` must be encoded in the correct format: "Header: value\r\n"
    /// The function will automatically add default headers (Date and Server)
    /// The function will automatically add the trailing new line
    fn sendHttpResponse(
        self: *ServerSession,
        statusCode: u32, 
        contentLength: u32,
        headers: ?[]const u8,
    ) !void {
        var writer = self.writer.writer();
        _ = try writer.print("HTTP/1.1 {} S{}\r\n", .{statusCode, statusCode});
        _ = try writer.write("Date: Mon, 01 Jan 1970 00:00:00 GMT\r\n");
        _ = try writer.write("Server: Zig Server\r\n");
        _ = try writer.print("Content-Length: {}\r\n", .{contentLength});
        if (headers) |h| _ = try writer.write(h);
        _ = try writer.write("\r\n");
        try self.writer.flush();
    }

    pub fn sendFrame(
        self: *ServerSession,
        opcode: WebSocketOpCode,
        payload: []const u8
    ) !void {
        try sendFrameRaw(&self.writer, opcode, payload);
    }
};

const FrameAssembler = struct {
    ptr: u64 = 0,
    opcode: ?WebSocketOpCode = null,
    frameBuffer: *[]u8,
    readBuffer: *[]u8,
    reader: *std.io.BufferedReader(4096, std.net.Stream.Reader),
    writer: *std.io.BufferedWriter(4096, std.net.Stream.Writer),

    fn handleFrame(self: *FrameAssembler, fin: bool, opcode: ?WebSocketOpCode, payload: []u8) FrameAssemblyResult {
        const isContinuation = if (opcode) |op| op == .Continuation else false;

        if (!fin or isContinuation) {
            if (opcode != WebSocketOpCode.Continuation) {
                // NOTE(Dan): First frame has !fin and opcode != Continuation
                // Remaining frames will have opcode = Continuation
                // Last frame will have fin and opcode = Continuation
                self.ptr = 0;
                self.opcode = opcode;
            }

            if (self.ptr + payload.len >= self.frameBuffer.len) {
                std.log.info("Dropping connection. Packet size exceeds limit.", .{});
                return FrameAssemblyResult.Invalid;
            }

            std.mem.copy(u8, self.frameBuffer[self.ptr..], payload);
            self.ptr += payload.len;
            if (!fin) return FrameAssemblyResult.NotReady;
            return FrameAssemblyResult.ReadyAndNeedsReset;
        } else {
            if (self.opcode == null) {
                // NOTE(Dan): If no opcode was set, then we must set it now.
                self.opcode = opcode;
            }
            std.mem.copy(u8, self.frameBuffer, payload);
            self.ptr = payload.len;
            return FrameAssemblyResult.ReadyAndNeedsReset;
        }
    }

    pub fn readFrame(self: *FrameAssembler) FrameAssemblyResult {
        // TODO Looks a lot like this isn't capable of receiving more than 4096 bytes at the moment
        // TODO Looks a lot like this isn't capable of receiving more than 4096 bytes at the moment
        // TODO Looks a lot like this isn't capable of receiving more than 4096 bytes at the moment
        // TODO Looks a lot like this isn't capable of receiving more than 4096 bytes at the moment
        const reader = self.reader.reader();
        const initialByte = reader.readByte() catch return FrameAssemblyResult.Invalid;
        const fin = (initialByte & (1 << 7)) != 0;

        const opcode = WebSocketOpCode.parse((initialByte & 0x0F));
        if (opcode == WebSocketOpCode.Invalid) return FrameAssemblyResult.Invalid;

        const maskAndPayload = reader.readByte() catch return FrameAssemblyResult.Invalid;
        const mask = (maskAndPayload & (1 << 7)) != 0;

        const payloadLength: u64 = blk: {
            const payloadB1 = (maskAndPayload & 0b01111111);
            if (payloadB1 < 126) {
                break :blk @intCast(u64, payloadB1);
            } else if (payloadB1 == 126) {
                const b1 = reader.readByte() catch return FrameAssemblyResult.Invalid;
                const b2 = reader.readByte() catch return FrameAssemblyResult.Invalid;
                break :blk (@intCast(u64, b1) << 8) | @intCast(u64, b2);
            } else if (payloadB1 == 127) {
                const b1 = @intCast(u64, reader.readByte() catch return FrameAssemblyResult.Invalid);
                const b2 = @intCast(u64, reader.readByte() catch return FrameAssemblyResult.Invalid);
                const b3 = @intCast(u64, reader.readByte() catch return FrameAssemblyResult.Invalid);
                const b4 = @intCast(u64, reader.readByte() catch return FrameAssemblyResult.Invalid);
                const b5 = @intCast(u64, reader.readByte() catch return FrameAssemblyResult.Invalid);
                const b6 = @intCast(u64, reader.readByte() catch return FrameAssemblyResult.Invalid);
                const b7 = @intCast(u64, reader.readByte() catch return FrameAssemblyResult.Invalid);
                const b8 = @intCast(u64, reader.readByte() catch return FrameAssemblyResult.Invalid);
                break :blk @intCast(u64, (b1 << (64 - 8 * 1)) |
                    (b2 << (64 - 8 * 2)) |
                    (b3 << (64 - 8 * 3)) |
                    (b4 << (64 - 8 * 4)) |
                    (b5 << (64 - 8 * 5)) |
                    (b6 << (64 - 8 * 6)) |
                    (b7 << (64 - 8 * 7)) |
                    (b8 << (64 - 8 * 8)));
            } else {
                unreachable;
            }
        };

        const maskingKey: ?[4]u8 = blk: {
            if (mask) {
                break :blk [4]u8{
                    reader.readByte() catch return FrameAssemblyResult.Invalid,
                    reader.readByte() catch return FrameAssemblyResult.Invalid,
                    reader.readByte() catch return FrameAssemblyResult.Invalid,
                    reader.readByte() catch return FrameAssemblyResult.Invalid,
                };
            } else {
                break :blk null;
            }
        };

        if (payloadLength >= self.readBuffer.len) {
            return FrameAssemblyResult.Invalid;
        }

        var payloadSlice = self.readBuffer[0..payloadLength];
        const bytesRead = reader.readAll(payloadSlice) catch return FrameAssemblyResult.Invalid;
        if (bytesRead != payloadLength) return FrameAssemblyResult.Invalid;

        if (maskingKey) |key| {
           for (payloadSlice) |byte, index| {
               payloadSlice[index] = byte ^ key[index % 4];
           }
        }
        return self.handleFrame(fin, opcode, payloadSlice);
    }
};



fn sendFrameRaw(
    bufWriter: *std.io.BufferedWriter(4096, std.net.Stream.Writer),
    opcode: WebSocketOpCode,
    payload: []const u8
) !void {
    // TODO Masking
    var writer = bufWriter.writer();
    try writer.writeByte(@intCast(u8, 0b1000 << 4 | @enumToInt(opcode)));
    var initialPayloadByte: u8 = blk: {
        if (payload.len < 126) {
            break :blk @intCast(u8, payload.len);
        } else if (payload.len < 65536) {
            break :blk 126;
        } else {
            break :blk 127;
        }
    };

    try writer.writeByte(initialPayloadByte);
    if (initialPayloadByte == 126) {
        try writer.writeByte(@intCast(u8, payload.len >> 8));
        try writer.writeByte(@intCast(u8, payload.len & 0xFF));
        std.log.debug("Length is: {}", .{payload.len});
    } else if (initialPayloadByte == 127) {
        try writer.writeByte(@intCast(u8, (payload.len >> (64 - 8 * 1)) & 0xFF));
        try writer.writeByte(@intCast(u8, (payload.len >> (64 - 8 * 2)) & 0xFF));
        try writer.writeByte(@intCast(u8, (payload.len >> (64 - 8 * 3)) & 0xFF));
        try writer.writeByte(@intCast(u8, (payload.len >> (64 - 8 * 4)) & 0xFF));
        try writer.writeByte(@intCast(u8, (payload.len >> (64 - 8 * 6)) & 0xFF));
        try writer.writeByte(@intCast(u8, (payload.len >> (64 - 8 * 7)) & 0xFF));
        try writer.writeByte(@intCast(u8, (payload.len >> (64 - 8 * 8)) & 0xFF));
    }

    try writer.writeAll(payload);
    try bufWriter.flush();
}

fn normalizeHeaderValue(allocator: *std.mem.Allocator, rawValue: []const u8) ![]const u8 {
    return std.mem.trim(
        u8, 
        try std.mem.dupe(allocator, u8, rawValue), 
        &std.ascii.spaces
    );
}

pub const WebSocketHandshakeResult = enum { Invalid, Valid };

pub const WebSocketClientError = error {
    InvalidResponse,
};

pub const Client = struct {
    parentAllocator: *std.mem.Allocator,
    frameBuffer: []u8,
    readBuffer: []u8,
    connection: std.net.Stream,
    reader: std.io.BufferedReader(4096, std.net.Stream.Reader),
    writer: std.io.BufferedWriter(4096, std.net.Stream.Writer),
    arena: std.heap.ArenaAllocator,

    pub fn init(
        allocator: *std.mem.Allocator, 
        address: std.net.Address,
        path: []const u8,
        origin: []const u8,
    ) !Client {
        var connection = try std.net.tcpConnectToAddress(address);
        errdefer connection.close();

        var buffer = try allocator.alloc(u8, 1024 * 256);
        errdefer allocator.destroy(buffer);
        
        var readBuffer = try allocator.alloc(u8, 1024 * 8);
        errdefer allocator.destroy(readBuffer);
        
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var bufReader = std.io.bufferedReader(connection.stream.reader());
        var bufWriter = std.io.bufferedWriter(connection.stream.writer());

        var writer = bufWriter.writer();
        var reader = bufReader.reader();

        var key: [64]u8 = undefined;
        std.crypto.random.bytes(key);
        var encodedKeyBuffer: [(64 * 4) / 3 + 4]u8 = undefined;
        const encodedKey = std.base64.standard.Encoder.encode(encodedKeyBuffer, key);
        
        try writer.print("GET {s} HTTP/1.1\r\n", .{path});
        try writer.print("Origin: {s}\r\n", .{origin});
        try writer.print("Sec-WebSocket-Version: 13\r\n", .{});
        try writer.print("Upgrade: websocket\r\n", .{});
        try writer.print("Sec-WebSocket-Key: {s}\r\n", .{encodedKey});
        try writer.print("\r\n", .{});
        try bufWriter.flush();

        const responseLine = std.mem.trimRight(
            u8,
            try reader.readUntilDelimiter(readBuffer, '\n'),
            &[_]u8{'\r'}
        );

        var responseLineIterator = std.mem.tokenize(u8, responseLine, " ");
        const httpVersion = responseLineIterator.next();
        const statusCode = responseLineIterator.next();
        const statusName = responseLineIterator.next();

        if (httpVersion == null or statusCode == null or statusName == null) {
            return .InvalidResponse;
        }

        if (!std.mem.eql(u8, httpVersion.?, "HTTP/1.1")) return .InvalidResponse;
        if (!std.mem.eql(u8, statusCode.?, "101")) return .InvalidResponse;

        // TODO(dan): potential DoS if the server keeps sending non-empty lines
        while (true) {
            const headerLine = std.mem.trimRight(
                u8, 
                try reader.readUntilDelimiter(readBuffer, '\n'),
                &[_]u8{'\r'}
            );

            if (std.mem.eql(u8, headerLine, "")) break;

            // TODO(Dan): use the headers, if we actually need them
        }

        return .{
            .parentAllocator = allocator,
            .frameBuffer = buffer,
            .readBuffer = readBuffer,
            .arena = arena,
            .connection = connection,
            .reader = bufReader,
            .writer = bufWriter,
        };
    }

    pub fn destroy(self: *Client) void {
        self.connection.close();
        self.parentAllocator.destroy(self.frameBuffer);
        self.parentAllocator.destroy(self.readBuffer);
        self.arena.deinit();
    }
};

