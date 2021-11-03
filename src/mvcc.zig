const std = @import("std");
const Atomic = std.atomic.Atomic;

// TODO Something like this https://levelup.gitconnected.com/implementing-your-own-transactions-with-mvcc-bba11cab8e70
// Probably want to do something more efficient for tracking the active transactions (bit mask?)
// https://stackoverflow.com/questions/5179676/how-do-i-implement-mvcc
// https://github.com/kennethho/mvcc11

const CHUNK_SIZE = 1024;
const Chunk = struct {
    buckets: [CHUNK_SIZE]DataBucket,
    next: ?*Chunk = null,
};

const MAX_VERSIONS = 16;
const DataBucket = struct {
    activeVersion: Atomic(u64),
    versions: [MAX_VERSIONS]u64,
    data: [MAX_VERSIONS][]u8,
};

const StoreError = error {
    InvalidPointer
};

const WriteableData = struct {
    ptr: u64,
    data: []u8
};

const Transaction = struct {
    id: u64,
    didFail: bool = false
};

const Store = struct {
    transactionIdTracker: Atomic(u64),
    dataPointerAllocator: Atomic(u64),
    allocator: *std.mem.Allocator,
    rootChunk: *Chunk,

    pub fn init(allocator: *std.mem.Allocator) !Store {
        var result = Store {
            .transactionIdTracker = Atomic(u64).init(1),
            .allocator = allocator,
            .rootChunk = try allocator.create(Chunk),
            .dataPointerAllocator = Atomic(u64).init(0),
        };

        for (result.rootChunk.buckets) |bucket, bucketIdx| {
            result.rootChunk.buckets[bucketIdx].activeVersion.value = 0;
            for (bucket.versions) |v, versionIdx| {
                result.rootChunk.buckets[bucketIdx].versions[versionIdx] = 0;
                _ = v;
            }
        }

        return result;
    }

    pub fn openTransaction(self: *Store) Transaction {
        return Transaction { .id = self.transactionIdTracker.fetchAdd(1, .Monotonic) };
    }

    inline fn findBucket(self: *Store, dataPointer: u64) !*DataBucket {
        const chunkIdx = dataPointer / CHUNK_SIZE;
        const internalIdx = dataPointer % CHUNK_SIZE;

        var i: usize = 0;
        var currentChunk: *Chunk = self.rootChunk;
        while (i < chunkIdx) {
            if (currentChunk.next) |next| {
                currentChunk = next;
            } else {
                return StoreError.InvalidPointer;
            }


            i += 1;
        }
        
        i = 0;
        return &currentChunk.buckets[internalIdx];
    }

    pub fn readData(self: *Store, transaction: *Transaction, dataPointer: u64) ![]const u8 {
        const transactionId = transaction.id;
        const bucket = try self.findBucket(dataPointer);

        var i: usize = 0;
        for (bucket.versions) |version| {
            if (version != 0 and version <= transactionId) {
                return bucket.data[i];
            }

            i += 1;
        }

        return StoreError.InvalidPointer;
    }

    pub fn updateData(self: *Store, transaction: *Transaction, dataPointer: u64) ![]u8 {
        const transactionId = transaction.id;
        const bucket = try self.findBucket(dataPointer);

        _ = self;
        _ = transaction;
        _ = dataPointer;
        return StoreError.InvalidPointer;
    }

    pub fn createAndWriteData(self: *Store, transaction: *Transaction, size: u64) !WriteableData {
        const transactionId = transaction.id;
        const dataPointer = self.dataPointerAllocator.fetchAdd(1, .Monotonic);
        const chunkIdx = dataPointer / CHUNK_SIZE;
        const internalIdx = dataPointer % CHUNK_SIZE;

        var i: usize = 0;
        var currentChunk: *Chunk = self.rootChunk;
        while (i < chunkIdx) {
            if (currentChunk.next) |next| {
                currentChunk = next;
            } else {
                return StoreError.InvalidPointer;
            }


            i += 1;
        }

        var bucket = &currentChunk.buckets[internalIdx];
        bucket.activeVersion.value = transactionId;
        bucket.versions[0] = transactionId;
        bucket.data[0] = (try self.allocator.alloc(u8, size));
        return WriteableData { .ptr = dataPointer, .data = bucket.data[0] };
    }

    pub fn resizeAndWriteData(self: *Store, transaction: *Transaction, dataPointer: u64, newSize: u64) ![]u8 {
        _ = self;
        _ = transaction;
        _ = dataPointer;
        _ = newSize;
        return StoreError.InvalidPointer;
    }

    pub fn deleteData(self: *Store, transaction: *Transaction, dataPointer: u64) !void {
        _ = self;
        _ = transaction;
        _ = dataPointer;
        return StoreError.InvalidPointer;
    }

    pub fn commit(self: *Store, transaction: *Transaction) !void {
        _ = self;
        _ = transaction;
    }

    pub fn rollback(self: *Store, transaction: *Transaction) !void {
        _ = self;
        _ = transaction;
    }
};

test "Foo" {
    var store = try Store.init(std.heap.page_allocator);
    var transaction = store.openTransaction();
    var dataAndPointer = try store.createAndWriteData(&transaction, 5);
    dataAndPointer.data[0] = 'h';
    dataAndPointer.data[1] = 'e';
    dataAndPointer.data[2] = 'l';
    dataAndPointer.data[3] = 'l';
    dataAndPointer.data[4] = 'o';

    const ptr = dataAndPointer.ptr;
    std.debug.print("The data pointer is {} and transaction is {}\n", .{ptr, transaction});
    const myData = try store.readData(&transaction, ptr);
    std.debug.print("Data '{s}'\n", .{myData});
}

