# Fuzzing
## tldr:
* [Install afl](#Install-afl).
* Create a testcase.
* Run: `nim fuzz.nims afl testfolder/testcase.nim`

Or

* [Install libFuzzer](#Install-libFuzzer) (comes with LLVM).
* Create a testcase.
* Run: `nim fuzz.nims libFuzzer testfolder/testcase.nim`

## Fuzzing Helpers
There are two convenience templates which will help you set up a quick fuzzing
test.

These are the mandatory `test` block and the optional `init` block.

Example usage:
```nim
test:
  var rlp = rlpFromBytes(payload)
  discard rlp.inspect()
```

Any unhandled `Exception` will result in a failure of the testcase. If certain
`Exception`s are to be allowed to occur within the test, they should be caught.

E.g.:
```nim
test:
  try:
    var rlp = rlpFromBytes(payload)
    discard rlp.inspect()
  except RlpError as e:
    debug "Inspect failed", err = e.msg
```

## Supported Fuzzers
The two templates can prepare the code for both
[afl](http://lcamtuf.coredump.cx/afl/) and
[libFuzzer](http://llvm.org/docs/LibFuzzer.html).

You will need to install first the fuzzer you want to use.
### Install afl
```sh
# Ubuntu / Debian
sudo apt-get install afl

# Fedora
dnf install american-fuzzy-lop
# for usage with clang & clang-fast you will have to install
# american-fuzzy-lop-clang or american-fuzzy-lop-clang-fast

# Arch Linux
pacman -S afl

# NixOS
nix-env -i afl

```

### Install libFuzzer

LibFuzzer is part of llvm and will be installed together with llvm-libs in
recent versions. Installing clang should install llvm-libs.
```sh
# Ubuntu / Debian
sudo apt-get install clang

# Fedora
dnf install clang

# Arch Linux
pacman -S clang

# NixOS
nix-env -iA nixos.clang_7 nixos.llvm_7
```

## Compiling & Starting the Fuzzer
### Scripted helper
There is a nimscript helper to compile & start the fuzzer:
```sh
# for afl
nim fuzz.nims afl testcase.nim

# for libFuzzer
nim fuzz.nims libFuzzer testcase.nim
```
### Manually with afl
#### Compiling
With gcc:
```sh
nim c -d:afl -d:release -d:chronicles_log_level=fatal -d:noSignalHandler --cc=gcc --gcc.exe=afl-gcc --gcc.linkerexe=afl-gcc testcase.nim
```
The `afl` define is specifically required for the `init` and `test`
templates.

You typically want to fuzz in `-d:release` and probably also want to lower down
the logging. But this is not strictly necessary.

There is also a nimscript task in `config.nims` for this:
```
nim c build_afl testcase.nim
```

With clang:
```sh
# afl-clang
nim c -d:afl -d:noSignalHandler --cc=clang --clang.exe=afl-clang --clang.linkerexe=afl-clang ftestcase.nim
# afl-clang-fast
nim c -d:afl -d:noSignalHandler --cc=clang --clang.exe=afl-clang-fast --clang.linkerexe=afl-clang-fast testcase.nim
```

#### Starting the Fuzzer

To start the fuzzer:
```sh
afl-fuzz -i input -o results -- ./testcase
```

To rerun it without losing previous results/corpus:
```sh
afl-fuzz -i - -o results -- ./testcase
```

To run several parallel fuzzing sessions:
```sh
# Start master fuzzer
afl-fuzz -i input -o results -M fuzzer01 -- ./testcase
# Start slaves (usually 1 per core available)
afl-fuzz -i input -o results -S fuzzer02 -- ./testcase
afl-fuzz -i input -o results -S fuzzer03 -- ./testcase
# add more if needed
```

When compiled with `-d:afl` the resulting application can also be run
manually by providing it input data, e.g.:
```sh
./testcase < testfile
```

During debugging you might not want the testcase to generate a segmentation
fault on exceptions. You can do this by rebuilding the test without the `-d:afl`
flag. Changing to `-d:debug` will also help but might also change the
behaviour.

### Manually with libFuzzer
#### Compiling
```sh
nim c -d:libFuzzer -d:release -d:chronicles_log_level=fatal --noMain --cc=clang --passC="-fsanitize=fuzzer" --passL="-fsanitize=fuzzer" testcase.nim
```

The `libFuzzer` define is specifically required for the `init` and `test`
templates.

You typically want to fuzz in `-d:release` and probably also want to lower down
the logging. But this is not strictly necessary.

There is also a nimscript task in `config.nims` for compiling:
```
nim c build_libFuzzer testcase.nim
```

#### Starting the Fuzzer
Starting the fuzzer is as simple as running the compiled program:
```sh
./testcase corpus_dir -runs=1000000
```

To see the available options:
```sh
./testcase test=1
```

Parallel fuzzing on 8 cores:
```sh
./fuzz-libfuzzer -jobs=8 -workers=8
```

You can also use the application to verify a specific test case:
```sh
./testcase input_file
```

## Additional notes
The `init` template, when used with **afl**, is only cosmetic. It will be
run before each test block, compared to libFuzzer, where it will be run only
once.

In case of using afl with `alf-clang-fast` you can make use of `aflInit()` proc
and `aflLoop()` template.

`aflInit()` will allow using what is called deferred instrumentation. Basically,
the forking of the process will only happen after this call, where normally it
is done right before `main()`.

`aflLoop:` will allow for (experimental) persistant mode. It will run the test
in loop (1000 iterations) with different payloads. This is more comparable with
libFuzzer.

These calls are enabled with `-d:clangfast`, and have to be manually added.
They are currently not part of the `test` or `init` templates.
