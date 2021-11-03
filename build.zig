const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("zig-srv", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.addLibPath(b.pathFromRoot("lib"));
    exe.install();
    
    // TODO Automate this
    // std.fs.copyFileAbsolute(
    //     b.pathFromRoot("lib/wolfssl.dll"), 
    //     std.fs.path.join(b.allocator, &[_][]const u8{b.install_path, "wolfssl.dll"}) catch unreachable, 
    //     .{}
    // ) catch unreachable;

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
