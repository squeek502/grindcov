const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const clap = @import("clap");

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer assert(gpa.deinit() == false);
    const allocator = &gpa.allocator;

    const params = comptime [_]clap.Param(clap.Help){
        clap.parseParam("-h, --help        Display this help and exit.") catch unreachable,
        clap.parseParam(
            \\--root <PATH>          Root directory for source files.
            \\- Files outside of the root directory are not reported on.
            \\- Output paths are relative to the root directory.
            \\(default: '.')
        ) catch unreachable,
        clap.parseParam("--output-dir <PATH>     Directory to put the results. (default: './coverage')") catch unreachable,
        clap.parseParam("--cwd <PATH>            Directory to run the valgrind process from. (default: '.')") catch unreachable,
        clap.parseParam("--keep-out-file         Do not delete the callgrind file that gets generated.") catch unreachable,
        clap.parseParam("--out-file-name <PATH>  Set the name of the callgrind.out file.\n(default: 'callgrind.out.%p')") catch unreachable,
        clap.parseParam("--include <PATH>...     Include the specified callgrind file(s) when generating\ncoverage (can be specified multiple times).") catch unreachable,
        clap.parseParam("--skip-collect          Skip the callgrind data collection step.") catch unreachable,
        clap.parseParam("--skip-report           Skip the coverage report generation step.") catch unreachable,
        clap.parseParam("<CMD...>...") catch unreachable,
    };

    var diag = clap.Diagnostic{};
    var args = clap.parse(clap.Help, &params, .{ .diagnostic = &diag, .allocator = allocator }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer args.deinit();

    if (args.flag("--skip-collect") and args.flag("--skip-report")) {
        std.debug.print("Error: Nothing to do (--skip-collect and --skip-report are both set.)\n", .{});
        return error.NothingToDo;
    }

    if (args.flag("--skip-collect") and args.options("--include").len == 0) {
        std.debug.print("Error: --skip-collect is set but no callgrind.out files were specified. At least one callgrind.out file must be specified with --include in order to generate a report when --skip-collect is set.\n", .{});
        return error.NoCoverageData;
    }

    var should_print_usage = !args.flag("--skip-collect") and args.positionals().len == 0;
    if (args.flag("--help") or should_print_usage) {
        const writer = std.io.getStdErr().writer();
        try writer.writeAll("Usage: grindcov [options] -- <cmd> [<args>...]\n\n");
        try writer.writeAll("Available options:\n");
        try clap.help(writer, &params);
        return;
    }

    const root_dir = root_dir: {
        const path = args.option("--root") orelse ".";
        const realpath = std.fs.cwd().realpathAlloc(allocator, path) catch |err| switch (err) {
            error.FileNotFound => |e| {
                std.debug.print("Unable to resolve root directory: '{s}'\n", .{path});
                return e;
            },
            else => return err,
        };
        break :root_dir realpath;
    };
    defer allocator.free(root_dir);

    var coverage = Coverage.init(allocator);
    defer coverage.deinit();

    if (!args.flag("--skip-collect")) {
        const callgrind_out_path = try genCallgrind(allocator, args.positionals(), args.option("--cwd"), args.option("--out-file-name"));
        defer allocator.free(callgrind_out_path);
        defer if (!args.flag("--keep-out-file")) {
            std.fs.cwd().deleteFile(callgrind_out_path) catch {};
        };

        if (args.flag("--keep-out-file")) {
            std.debug.print("Kept callgrind out file: '{s}'\n", .{callgrind_out_path});
        }

        try coverage.getFromPath(allocator, callgrind_out_path);
    }

    if (!args.flag("--skip-report")) {
        for (args.options("--include")) |include_callgrind_out_path| {
            coverage.getFromPath(allocator, include_callgrind_out_path) catch |err| switch (err) {
                error.FileNotFound => |e| {
                    std.debug.print("Included callgrind out file not found: {s}\n", .{include_callgrind_out_path});
                    return e;
                },
                else => |e| return e,
            };
        }

        const output_dir = args.option("--output-dir") orelse "coverage";

        try std.fs.cwd().deleteTree(output_dir);
        var out_dir = try std.fs.cwd().makeOpenPath(output_dir, .{});
        defer out_dir.close();

        const num_dumped = try coverage.dumpDiffsToDir(out_dir, root_dir);

        if (num_dumped == 0) {
            std.debug.print("Warning: No source files were included in the coverage results. ", .{});
            std.debug.print("If this is unexpected, check to make sure that the root directory is set appropriately.\n", .{});
            std.debug.print(" - Current --root setting: ", .{});
            if (args.option("--root")) |setting| {
                std.debug.print("'{s}'\n", .{setting});
            } else {
                std.debug.print("(not specified)\n", .{});
            }
            std.debug.print(" - Current root directory: '{s}'\n", .{root_dir});
        } else {
            std.debug.print("Results for {} source files generated in directory '{s}'\n", .{ num_dumped, output_dir });
        }
    }
}

pub fn genCallgrind(allocator: *Allocator, user_args: []const []const u8, cwd: ?[]const u8, custom_out_file_name: ?[]const u8) ![]const u8 {
    const valgrind_args = &[_][]const u8{
        "valgrind",
        "--tool=callgrind",
        "--compress-strings=no",
        "--compress-pos=no",
        "--collect-jumps=yes",
    };

    var out_file_name = custom_out_file_name orelse "callgrind.out.%p";
    var out_file_arg = try std.mem.concat(allocator, u8, &[_][]const u8{
        "--callgrind-out-file=",
        out_file_name,
    });
    defer allocator.free(out_file_arg);

    const args = try std.mem.concat(allocator, []const u8, &[_][]const []const u8{
        valgrind_args,
        &[_][]const u8{out_file_arg},
        user_args,
    });
    defer allocator.free(args);

    const result = try std.ChildProcess.exec(.{
        .allocator = allocator,
        .argv = args,
        .cwd = cwd,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    const failed = switch (result.term) {
        .Exited => |exit_code| exit_code != 0,
        else => true,
    };
    if (failed) {
        std.debug.print("{s}\n", .{result.stderr});
        return error.CallgrindError;
    }

    // TODO: this would get blown up by %%p which is meant to be an escaped % and a p
    var pid_pattern_count = std.mem.count(u8, out_file_name, "%p");
    var callgrind_out_path = callgrind_out_path: {
        if (pid_pattern_count > 0) {
            const maybe_first_equals = std.mem.indexOf(u8, result.stderr, "==");
            if (maybe_first_equals == null) {
                std.debug.print("{s}\n", .{result.stderr});
                return error.UnableToFindPid;
            }
            const first_equals = maybe_first_equals.?;
            const next_equals_offset = std.mem.indexOf(u8, result.stderr[(first_equals + 2)..], "==").?;
            const pid_as_string = result.stderr[(first_equals + 2)..(first_equals + 2 + next_equals_offset)];

            const delta_mem_needed: i64 = @intCast(i64, pid_pattern_count) * (@intCast(i64, pid_as_string.len) - @as(i64, 2));
            const mem_needed = @intCast(usize, @intCast(i64, out_file_name.len) + delta_mem_needed);
            const buf = try allocator.alloc(u8, mem_needed);
            _ = std.mem.replace(u8, out_file_name, "%p", pid_as_string, buf);

            break :callgrind_out_path buf;
        } else {
            break :callgrind_out_path try allocator.dupe(u8, out_file_name);
        }
    };

    if (cwd) |cwd_path| {
        var cwd_callgrind_out_path = try std.fs.path.join(allocator, &[_][]const u8{
            cwd_path,
            callgrind_out_path,
        });
        allocator.free(callgrind_out_path);
        callgrind_out_path = cwd_callgrind_out_path;
    }
    return callgrind_out_path;
}

const Coverage = struct {
    allocator: *Allocator,
    paths_to_covered_line_nums: Info,

    pub const CoveredLineSet = std.AutoHashMapUnmanaged(usize, void);
    pub const Info = std.StringHashMapUnmanaged(*CoveredLineSet);

    pub fn init(allocator: *Allocator) Coverage {
        return .{
            .allocator = allocator,
            .paths_to_covered_line_nums = Coverage.Info{},
        };
    }

    pub fn deinit(self: *Coverage) void {
        var it = self.paths_to_covered_line_nums.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.paths_to_covered_line_nums.deinit(self.allocator);
    }

    pub fn getFromPath(coverage: *Coverage, allocator: *Allocator, callgrind_file_path: []const u8) !void {
        var callgrind_file = try std.fs.cwd().openFile(callgrind_file_path, .{});
        defer callgrind_file.close();

        var current_path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        var current_path: ?[]u8 = null;

        var reader = std.io.bufferedReader(callgrind_file.reader()).reader();
        while (try reader.readUntilDelimiterOrEofAlloc(allocator, '\n', std.math.maxInt(usize))) |_line| {
            defer allocator.free(_line);
            var line = std.mem.trimRight(u8, _line, "\r");

            const is_source_file_path = std.mem.startsWith(u8, line, "fl=") or std.mem.startsWith(u8, line, "fi=") or std.mem.startsWith(u8, line, "fe=");
            if (is_source_file_path) {
                var path = line[3..];
                if (std.fs.cwd().access(path, .{})) {
                    std.mem.copy(u8, current_path_buf[0..], path);
                    current_path = current_path_buf[0..path.len];
                } else |_| {
                    current_path = null;
                }
                continue;
            }
            if (current_path == null) {
                continue;
            }

            const is_jump = std.mem.startsWith(u8, line, "jump=") or std.mem.startsWith(u8, line, "jncd=");
            var line_num: usize = 0;
            if (is_jump) {
                line = line[5..];
                // jcnd seems to use a '/' to separate exe-count and jump-count, although
                // https://valgrind.org/docs/manual/cl-format.html doesn't seem to think so
                // target-position is always last, though, so just get the last tok
                var tok_it = std.mem.tokenize(u8, line, " /");
                var last_tok = tok_it.next() orelse continue;
                while (tok_it.next()) |tok| {
                    last_tok = tok;
                }
                line_num = try std.fmt.parseInt(usize, last_tok, 10);
            } else {
                var tok_it = std.mem.tokenize(u8, line, " ");
                var first_tok = tok_it.next() orelse continue;
                line_num = std.fmt.parseInt(usize, first_tok, 10) catch continue;
            }

            // not sure exactly what causes this, but ignore line nums given as 0
            if (line_num == 0) continue;

            try coverage.markCovered(current_path.?, line_num);
        }
    }

    pub fn markCovered(self: *Coverage, path: []const u8, line_num: usize) !void {
        var entry = try self.paths_to_covered_line_nums.getOrPut(self.allocator, path);
        if (!entry.found_existing) {
            entry.key_ptr.* = try self.allocator.dupe(u8, path);
            var created_set = try self.allocator.create(CoveredLineSet);
            created_set.* = CoveredLineSet{};
            entry.value_ptr.* = created_set;
        }

        var line_set = entry.value_ptr.*;
        try line_set.put(self.allocator, line_num, {});
    }

    pub fn dumpDiffsToDir(self: *Coverage, dir: std.fs.Dir, root_dir_path: []const u8) !usize {
        var num_dumped: usize = 0;
        var filename_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        var it = self.paths_to_covered_line_nums.iterator();
        while (it.next()) |path_entry| {
            const abs_path = path_entry.key_ptr.*;
            if (!std.mem.startsWith(u8, abs_path, root_dir_path)) {
                continue;
            }

            var in_file = try std.fs.cwd().openFile(abs_path, .{});
            defer in_file.close();

            var relative_path = abs_path[root_dir_path.len..];
            // trim any preceding separators
            while (relative_path.len != 0 and std.fs.path.isSep(relative_path[0])) {
                relative_path = relative_path[1..];
            }
            if (std.fs.path.dirname(relative_path)) |dirname| {
                try dir.makePath(dirname);
            }

            const filename = try std.fmt.bufPrint(&filename_buf, "{s}.diff", .{relative_path});
            var out_file = try dir.createFile(filename, .{ .truncate = true });

            var line_num: usize = 1;
            var reader = std.io.bufferedReader(in_file.reader()).reader();
            var writer = out_file.writer();
            while (try reader.readUntilDelimiterOrEofAlloc(self.allocator, '\n', std.math.maxInt(usize))) |line| {
                defer self.allocator.free(line);

                if (path_entry.value_ptr.*.get(line_num) != null) {
                    try writer.writeAll("> ");
                } else {
                    try writer.writeAll("! ");
                }
                try writer.writeAll(line);
                try writer.writeByte('\n');
                line_num += 1;
            }

            num_dumped += 1;
        }

        return num_dumped;
    }
};
