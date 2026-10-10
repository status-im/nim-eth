mode = ScriptMode.Verbose

version       = "0.9.3"
author        = "Status Research & Development GmbH"
description   = "Ethereum Common library"
license       = "MIT"
skipDirs      = @["tests"]

requires "nim >= 2.0.10",
         "chronicles >= 0.12.4",
         "chronos >= 4.0.1",
         "confutils >= 0.1.1",
         "metrics >= 0.2.0",
         "minilru >= 0.1.1",
         "nat_traversal",
         "nimcrypto >= 0.7.0",
         "results >= 0.5.0",
         "secp256k1 >= 0.7.0",
         "snappy",
         "sqlite3_abi >= 3.53.4.1",
         "stew >= 0.5.0",
         "stint >= 0.8.0",
         "testutils >= 0.8.5",
         "unittest2 >= 0.2.0"

from std/os import parentDir, quoteShell

let nimc = getEnv("NIMC", "nim") # Which nim compiler to use
let lang = getEnv("NIMLANG", "c") # Which backend (c/cpp/js)
let flags = getEnv("NIMFLAGS", "") # Extra flags for the compiler
let verbose = getEnv("V", "") notin ["", "0"]
let platform = getEnv("PLATFORM", "")
let testArguments = [
  "-d:release",
]

let cfg =
  " --styleCheck:usages --styleCheck:error" &
  (if verbose: "" else: " --verbosity:0") &
  " --skipParentCfg --skipUserCfg --outdir:build -f " &
  quoteShell("--nimcache:build/nimcache/$projectName")

proc build(args, path: string) =
  exec nimc & " " & lang & " " & cfg & " " & flags & " " & args & " " & path

proc run(args, path: string) =
  build args & " -r", path

task test, "Run all tests":
  for args in testArguments:
    run args & " --mm:refc", "tests/all_tests"
    run args & " --mm:orc", "tests/all_tests"

task test_asan, "Run all tests with ASAN":
  if platform != "x86" and (NimMajor, NimMinor) >= (2, 2):
    try:
      exec "echo '#if __clang_major__ < 20\n#error\n#endif' | clang -E - >/dev/null"
    except OSError:
      return

    # https://clang.llvm.org/docs/AddressSanitizer.html
    putEnv("ASAN_OPTIONS", "detect_leaks=0:detect_stack_use_after_return=1")
    # https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
    putEnv("UBSAN_OPTIONS", "print_stacktrace=1")
    let asanArgs =
      " --mm:orc -d:useMalloc --cc:clang --debugger:native" &
      " --passC:-fsanitize=address,undefined" &
      " --passL:-fsanitize=address,undefined" &
      " --passC:-fno-sanitize-recover=undefined" &
      " --passC:-fno-sanitize-merge" &
      " --passC:-fno-omit-frame-pointer"
    for args in testArguments:
      run args & asanArgs, "tests/all_tests"

task build_dcli, "Build dcli":
  build "-d:release -d:chronicles_log_level=TRACE", "tools/dcli"

let
  fuzzSeconds = getEnv("FUZZ_SECONDS", "100")
  fuzzTime =
    if fuzzSeconds == "": " "
    else: " --duration=" & fuzzSeconds & " "

proc fuzz(target: string) =
  for fuzzer in ["libFuzzer", "honggfuzz", "afl"]:
    when defined(macosx):
      if fuzzer == "honggfuzz":
        continue

    if fuzzer == "libFuzzer":
      # detect_stack_use_after_return does not work with refc
      # https://github.com/nim-lang/Nim/issues/26334
      putEnv("ASAN_OPTIONS", "detect_stack_use_after_return=0")
    else:
      delEnv("ASAN_OPTIONS")

    exec "ntu fuzz --fuzzer=" & fuzzer & fuzzTime &
      "--corpus=tests/fuzzing/" & target.parentDir & "/corpus " &
      "tests/fuzzing/" & target

task fuzz, "Run fuzzing tests":
  fuzz "discoveryv5/fuzz_decode_message"
  fuzz "discoveryv5/fuzz_decode_packet"
  run "", "tests/fuzzing/enr/generate"
  fuzz "enr/fuzz_enr"
  fuzz "rlp/rlp_decode"
  fuzz "rlp/rlp_inspect"
