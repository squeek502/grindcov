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
        clap.parseParam("--skip-summary          Skip printing a summary to stdout.") catch unreachable,
        clap.parseParam("<CMD...>...") catch unreachable,
    };

    var diag = clap.Diagnostic{};
    var args = clap.parse(clap.Help, &params, .{ .diagnostic = &diag, .allocator = allocator }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer args.deinit();

    const valgrind_available = try checkCommandAvailable(allocator, "valgrind");
    if (!valgrind_available) {
        std.debug.print("Error: valgrind not found, make sure valgrind is installed.\n", .{});
        return error.NoValgrind;
    }

    const readelf_available = try checkCommandAvailable(allocator, "readelf");
    if (!readelf_available) {
        std.debug.print("Warning: readelf not found, information about executable lines will not be available.\n", .{});
    }

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

        try coverage.getCoveredLines(allocator, callgrind_out_path);
    }

    var got_executable_line_info = false;
    if (readelf_available) {
        got_executable_line_info = true;
        coverage.getExecutableLines(allocator, args.positionals()[0], args.option("--cwd")) catch |err| switch (err) {
            error.ReadElfError => {
                got_executable_line_info = false;
                std.debug.print("Warning: Unable to use readelf to get information about executable lines. This information will not be in the results.\n", .{});
            },
            else => |e| return e,
        };
    }

    if (!args.flag("--skip-report")) {
        for (args.options("--include")) |include_callgrind_out_path| {
            coverage.getCoveredLines(allocator, include_callgrind_out_path) catch |err| switch (err) {
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

    if (!args.flag("--skip-summary") and got_executable_line_info) {
        std.debug.print("\n", .{});
        try coverage.writeSummary(std.io.getStdOut().writer(), root_dir);
    }
}

pub fn checkCommandAvailable(allocator: *Allocator, cmd: []const u8) !bool {
    const result = std.ChildProcess.exec(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ cmd, "--version" },
    }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    const failed = switch (result.term) {
        .Exited => |exit_code| exit_code != 0,
        else => true,
    };
    return !failed;
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
        .max_output_bytes = std.math.maxInt(usize),
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
    paths_to_file_info: Info,

    pub const LineSet = std.AutoHashMapUnmanaged(usize, void);
    pub const FileInfo = struct {
        covered: *LineSet,
        executable: *LineSet,
    };
    pub const Info = std.StringHashMapUnmanaged(FileInfo);

    pub fn init(allocator: *Allocator) Coverage {
        return .{
            .allocator = allocator,
            .paths_to_file_info = Coverage.Info{},
        };
    }

    pub fn deinit(self: *Coverage) void {
        var it = self.paths_to_file_info.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.covered.deinit(self.allocator);
            entry.value_ptr.executable.deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.covered);
            self.allocator.destroy(entry.value_ptr.executable);
            self.allocator.free(entry.key_ptr.*);
        }
        self.paths_to_file_info.deinit(self.allocator);
    }

    pub fn getCoveredLines(coverage: *Coverage, allocator: *Allocator, callgrind_file_path: []const u8) !void {
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

    pub fn getExecutableLines(coverage: *Coverage, allocator: *Allocator, cmd: []const u8, cwd: ?[]const u8) !void {
        // TODO: instead of readelf, use Zig's elf/dwarf std lib functions
        const result = try std.ChildProcess.exec(.{
            .allocator = allocator,
            .argv = &[_][]const u8{
                "readelf",
                // to get DW_AT_comp_dir
                "--debug-dump=info",
                "--dwarf-depth=1",
                // to get the line nums
                "--debug-dump=decodedline",
                cmd,
            },
            .cwd = cwd,
            .max_output_bytes = std.math.maxInt(usize),
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        const failed = switch (result.term) {
            .Exited => |exit_code| exit_code != 0,
            else => true,
        };
        if (failed) {
            std.debug.print("{s}\n", .{result.stderr});
            return error.ReadElfError;
        }

        const debug_line_start_line = "Contents of the .debug_line section:\n";
        var start_of_debug_line = std.mem.indexOf(u8, result.stdout, debug_line_start_line) orelse return error.MissingDebugLine;

        const debug_info_section = result.stdout[0..start_of_debug_line];
        const main_comp_dir_start = std.mem.indexOf(u8, debug_info_section, "DW_AT_comp_dir") orelse return error.MissingCompDir;
        const main_comp_dir_line_end = std.mem.indexOfScalar(u8, debug_info_section[main_comp_dir_start..], '\n').?;
        const main_comp_dir_line = debug_info_section[main_comp_dir_start..(main_comp_dir_start + main_comp_dir_line_end)];
        const main_comp_dir_sep_pos = std.mem.lastIndexOf(u8, main_comp_dir_line, "): ").?;
        const main_comp_dir = main_comp_dir_line[(main_comp_dir_sep_pos + 3)..];

        var line_it = std.mem.split(u8, result.stdout[start_of_debug_line..], "\n");
        var past_header = false;
        var file_path: ?[]const u8 = null;
        var file_path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        var file_path_basename: ?[]const u8 = null;
        while (line_it.next()) |line| {
            if (!past_header) {
                if (std.mem.startsWith(u8, line, "File name ")) {
                    past_header = true;
                }
                continue;
            }

            if (line.len == 0) {
                file_path = null;
                file_path_basename = null;
                continue;
            }

            if (file_path == null) {
                if (std.mem.endsWith(u8, line, ":")) {
                    file_path = std.mem.trimRight(u8, line, ":");
                }
                // some files are relative to the main_comp_dir, they are indicated
                // by the suffix [++]
                else if (std.mem.endsWith(u8, line, ":[++]")) {
                    const relative_file_path = line[0..(line.len - (":[++]").len)];
                    const resolved_path = try std.fs.path.resolve(allocator, &[_][]const u8{ main_comp_dir, relative_file_path });
                    defer allocator.free(resolved_path);
                    std.mem.copy(u8, &file_path_buf, resolved_path);
                    file_path = file_path_buf[0..resolved_path.len];
                } else {
                    std.debug.print("Unhandled line, expecting a file path line: '{s}'\n", .{line});
                    @panic("Unhandled readelf output");
                }
                file_path_basename = std.fs.path.basename(file_path.?);
                continue;
            }

            const past_basename = line[(file_path_basename.?.len)..];
            var tok_it = std.mem.tokenize(u8, past_basename, " \t");
            const line_num_str = tok_it.next() orelse continue;
            const line_num = std.fmt.parseInt(usize, line_num_str, 10) catch continue;
            try coverage.markExecutable(file_path.?, line_num);
        }
    }

    pub fn getFileInfo(self: *Coverage, path: []const u8) !*FileInfo {
        var entry = try self.paths_to_file_info.getOrPut(self.allocator, path);
        if (!entry.found_existing) {
            entry.key_ptr.* = try self.allocator.dupe(u8, path);
            var covered_set = try self.allocator.create(LineSet);
            covered_set.* = LineSet{};
            var executable_set = try self.allocator.create(LineSet);
            executable_set.* = LineSet{};
            entry.value_ptr.* = .{
                .covered = covered_set,
                .executable = executable_set,
            };
        }
        return entry.value_ptr;
    }

    pub fn markCovered(self: *Coverage, path: []const u8, line_num: usize) !void {
        var file_info = try self.getFileInfo(path);
        try file_info.covered.put(self.allocator, line_num, {});
    }

    pub fn markExecutable(self: *Coverage, path: []const u8, line_num: usize) !void {
        var file_info = try self.getFileInfo(path);
        try file_info.executable.put(self.allocator, line_num, {});
    }

    pub fn dumpDiffsToDir(self: *Coverage, dir: std.fs.Dir, root_dir_path: []const u8) !usize {
        var num_dumped: usize = 0;
        var filename_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        var it = self.paths_to_file_info.iterator();
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

            var has_executable_info = path_entry.value_ptr.executable.count() != 0;
            var line_num: usize = 1;
            var reader = std.io.bufferedReader(in_file.reader()).reader();
            var writer = out_file.writer();
            while (try reader.readUntilDelimiterOrEofAlloc(self.allocator, '\n', std.math.maxInt(usize))) |line| {
                defer self.allocator.free(line);

                if (path_entry.value_ptr.covered.get(line_num) != null) {
                    try writer.writeAll("> ");
                } else {
                    if (has_executable_info) {
                        if (path_entry.value_ptr.executable.get(line_num) != null) {
                            try writer.writeAll("! ");
                        } else {
                            try writer.writeAll("  ");
                        }
                    } else {
                        try writer.writeAll("! ");
                    }
                }
                try writer.writeAll(line);
                try writer.writeByte('\n');
                line_num += 1;
            }

            num_dumped += 1;
        }

        return num_dumped;
    }

    pub fn writeSummary(self: *Coverage, stream: anytype, root_dir_path: []const u8) !void {
        try stream.print("{s:<36} {s:<11} {s:<14} {s:>8}\n", .{ "File", "Covered LOC", "Executable LOC", "Coverage" });
        try stream.print("{s:-<36} {s:-<11} {s:-<14} {s:-<8}\n", .{ "", "", "", "" });

        var total_covered_lines: usize = 0;
        var total_executable_lines: usize = 0;
        var it = self.paths_to_file_info.iterator();
        while (it.next()) |path_entry| {
            const abs_path = path_entry.key_ptr.*;
            if (!std.mem.startsWith(u8, abs_path, root_dir_path)) {
                continue;
            }

            var relative_path = abs_path[root_dir_path.len..];
            // trim any preceding separators
            while (relative_path.len != 0 and std.fs.path.isSep(relative_path[0])) {
                relative_path = relative_path[1..];
            }

            var has_executable_info = path_entry.value_ptr.executable.count() != 0;
            if (!has_executable_info) {
                try stream.print("{s:<36} <no executable line info>\n", .{relative_path});
            } else {
                const covered_lines = path_entry.value_ptr.covered.count();
                const executable_lines = path_entry.value_ptr.executable.count();
                const percentage_covered = @intToFloat(f64, covered_lines) / @intToFloat(f64, executable_lines);
                if (truncatePathLeft(relative_path, 36)) |truncated_path| {
                    try stream.print("...{s:<33}", .{truncated_path});
                } else {
                    try stream.print("{s:<36}", .{relative_path});
                }
                try stream.print(" {d:<11} {d:<14} {d:>7.2}%\n", .{ covered_lines, executable_lines, percentage_covered * 100 });

                total_covered_lines += covered_lines;
                total_executable_lines += executable_lines;
            }
        }

        if (total_executable_lines > 0) {
            try stream.print("{s:-<36} {s:-<11} {s:-<14} {s:-<8}\n", .{ "", "", "", "" });

            const total_percentage_covered = @intToFloat(f64, total_covered_lines) / @intToFloat(f64, total_executable_lines);
            try stream.print("{s:<36} {d:<11} {d:<14} {d:>7.2}%\n", .{ "Total", total_covered_lines, total_executable_lines, total_percentage_covered * 100 });
        }
    }
};

fn truncatePathLeft(str: []const u8, max_width: usize) ?[]const u8 {
    if (str.len <= max_width) return null;
    const start_offset = str.len - (max_width - 3);
    var truncated = str[start_offset..];
    while (truncated.len > 0 and !std.fs.path.isSep(truncated[0])) {
        truncated = truncated[1..];
    }
    // if we got to the end with no path sep found, then just return
    // the plain (max widdth - 3) string
    if (truncated.len == 0) {
        return str[start_offset..];
    } else {
        return truncated;
    }
}
