const std = @import("std");
const Atomic = std.atomic.Atomic;
const math = std.math;

const MaxBuckets = 64;

pub const OptimisticLock = struct {
    lock: Atomic(u64),

    pub fn init() OptimisticLock {
        return OptimisticLock { .lock = Atomic(u64).init(0) };
    }
};

pub const BTreeTag = enum {
    internal,
    leaf,
};

pub fn BTreeNode(
    comptime Key: type, 
    comptime Value: type,
    comptime compare: fn(Key, Key) math.Order
) type {
    _ = compare;
    return struct {
        const Self = @This();

        len: u16 = 0,
        lock: OptimisticLock = OptimisticLock.init(),
        keys: [MaxBuckets]Key = undefined,
        content: union(BTreeTag) {
            internal: struct {
                children: [MaxBuckets]?*Self = undefined,
            },

            leaf: struct {
                values: [MaxBuckets]Value = undefined,
                next: ?*Self = null,
            }
        },

        pub fn init() Self {
            return Self {
                .content = .{
                    .leaf = .{}
                }
            };
        }

        fn findNode(self: *Self, key: Key) *Self {
            var node: *Self = self;
            while (node.content != .leaf) {
                const length = node.len;
                var idx: usize = 0;
                while (idx < length) {
                    if (compare(key, self.keys[idx]) == .lt) {
                        node = self.content.internal.children[idx] orelse unreachable;
                        break;
                    }
                    idx += 1;
                }

                if (idx == length) {
                    node = self.content.internal.children[idx - 1] orelse unreachable;
                }
            }
            return node;
        }
    };
}

fn u32Comparator(a: u32, b: u32) math.Order {
    return math.order(a, b);
}

test "Foo" {
    var tree = BTreeNode(u32, u32, u32Comparator).init();
    std.debug.print("{}", . { tree.findNode(42) });
}

