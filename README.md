grindcov
========

> Note: Since writing this tool, I was made aware of [kcov](https://github.com/SimonKagstrom/kcov) which is a more robust and *much* faster tool that can generate coverage information for Zig binaries. If you'd like to use `kcov` with Zig, I've written a [post that describes more generally how coverage tools like kcov can be used with Zig on zig.news](https://zig.news/squeek502/code-coverage-for-zig-1dk1).

---

Code coverage generation tool using [Callgrind](https://valgrind.org/docs/manual/cl-manual.html) (via Valgrind). Created with [Zig](https://ziglang.org/) code in mind, but should work for any compiled binary with debug information.

The output is a directory with `.diff` files for each source file instrumented by callgrind, with either a `! ` (not executed), a `> ` (executed), or a `  ` (not executable) prefix for every line of source code (the `.diff` and `!`/`>` prefixes are just so that code editors syntax highlight the results in an understandable way).

Example (note: contents of `main.zig` omitted here, the source can be seen in the output):

```sh
$ zig build-exe main.zig
$ grindcov -- ./main hello
Results for 1 source files generated in directory 'coverage'

File                                 Covered LOC Executable LOC Coverage
------------------------------------ ----------- -------------- --------
main.zig                             6           7                85.71%
------------------------------------ ----------- -------------- --------
Total                                6           7                85.71%
```

`coverage/main.zig.diff` then contains:

```diff
  const std = @import("std");
  
> pub fn main() !void {
>     var args_it = std.process.args();
>     std.debug.assert(args_it.skip());
>     const arg = args_it.nextPosix() orelse "goodbye";
  
>     if (std.mem.eql(u8, arg, "hello")) {
>         std.debug.print("hello!\n", .{});
      } else {
!         std.debug.print("goodbye!\n", .{});
      }
  }
```

## Building / Installation

### Prebuilt Binaries

A prebuilt x86_64 Linux binary can be downloaded from the [latest release](https://github.com/squeek502/grindcov/releases/latest).

### Runtime Dependencies

- [Valgrind](https://valgrind.org/)
- [`readelf`](https://man7.org/linux/man-pages/man1/readelf.1.html) (optional, necessary for information about which lines are executable)

### From Source

Requires latest master of Zig. Currently only tested on Linux.

1. Clone this repository and its submodules (`git clone --recursive` to get submodules)
2. `zig build`
3. The compiled binary will be in `zig-out/bin/grindcov`
4. `mv` or `ln` the binary somewhere in your `PATH`

## Usage

```
Usage: grindcov [options] -- <cmd> [<args>...]

Available options:
	-h, --help                	Display this help and exit.
	    --root <PATH>         	Root directory for source files.
	                          	- Files outside of the root directory are not reported on.
	                          	- Output paths are relative to the root directory.
	                          	(default: '.')
	    --output-dir <PATH>   	Directory to put the results. (default: './coverage')
	    --cwd <PATH>          	Directory to run the valgrind process from. (default: '.')
	    --keep-out-file       	Do not delete the callgrind file that gets generated.
	    --out-file-name <PATH>	Set the name of the callgrind.out file.
	                          	(default: 'callgrind.out.%p')
	    --include <PATH>...   	Include the specified callgrind file(s) when generating
	                          	coverage (can be specified multiple times).
	    --skip-collect        	Skip the callgrind data collection step.
	    --skip-report         	Skip the coverage report generation step.
	    --skip-summary        	Skip printing a summary to stdout.
```

### Integrating with Zig

`grindcov` can be also used as a test executor by Zig's test runner via `--test-cmd` and `--test-cmd-bin`:

```
zig test file.zig --test-cmd grindcov --test-cmd -- --test-cmd-bin
```

This can be integrated with `build.zig` by doing:

```zig
const coverage = b.option(bool, "test-coverage", "Generate test coverage with grindcov") orelse false;

var tests = b.addTest("test.zig");
if (coverage) {
    tests.setExecCmd(&[_]?[]const u8{
        "grindcov",
        //"--keep-out-file", // any grindcov flags can be specified here
        "--",
        null, // to get zig to use the --test-cmd-bin flag
    });
}

const test_step = b.step("test", "Run all tests");
test_step.dependOn(&tests.step);
```

Test coverage information can then be generated by doing:
```
zig build test -Dtest-coverage
```

## How it works

This tool is mostly a convenience wrapper for a two step process:

- Generating a callgrind output file via `valgrind --tool=callgrind --compress-strings=no --compress-pos=no --collect-jumps=yes` (the flags are mostly used to make it easier to parse)
- Parsing the callgrind file, generating a set of all lines executed, and outputting that in a human-readable format

The idea comes from [numpy's c_coverage tool](https://github.com/numpy/numpy/tree/main/tools/c_coverage), which works pretty much identically (with a tiny bit of C/numpy specific stuff).

In addition, `grindcov` attempts to read the executed binary to get information about which lines are executable to improve the legibility/accuracy/relevance of the results.

## Limitations / Room for Improvement

Stuff that might be possible but isn't supported right now:
- Non-Linux platform support (Valgrind must support the platform, though)
- Support for following child processes and/or support for multiple threads (not sure about threads--they might already be handled fine by callgrind)
- More output formats
  + [`lcov`-compatible tracefiles (`.info`)](https://manpages.debian.org/stretch/lcov/geninfo.1.en.html#FILES)
