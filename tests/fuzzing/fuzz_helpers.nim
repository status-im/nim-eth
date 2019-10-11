import strformat, ospaths

# Dependencies:
# - afl fuzzing: afl and gcc or clang/llvm
# - libFuzzer fuzzing: libFuzzer and clang/llvm
# - in afl experimental modes clang/llvm is also required

# TODO:
# - switch clang / gcc option for afl
# - afl init and persistent modes
# - parallel fuzzing options
# - custom generate test cases from this script?
# - rerun testcases option (or create tests from failed cases)
# - currently not cross platform
# - ...

const
  aflGcc = "--cc=gcc " &
           "--gcc.exe=afl-gcc " &
           "--gcc.linkerexe=afl-gcc"
  aflClang = "--cc=clang " &
             "--clang.exe=afl-clang " &
             "--clang.linkerexe=afl-clang"
  aflClangFast = "--cc=clang " &
                 "--clang.exe=afl-clang-fast " &
                 "--clang.linkerexe=afl-clang-fast " &
                 "-d:clangfast"
  libFuzzerClang = "--cc=clang " &
                   "--passC='-fsanitize=fuzzer,address' " &
                   "--passL='-fsanitize=fuzzer,address'"
# Can also test in debug mode obviously, but might be slower
# Can turn on more logging, in case of libFuzzer it will get very verbose though
  defaultFlags = "-d:release -d:chronicles_log_level=fatal " &
                 "--hints:off --warnings:off --verbosity:0"

type
  Fuzzer* = enum
    afl,
    libFuzzer

  Compiler* = enum
    gcc = aflGcc,
    clang = aflClang,
    clangFast = aflClangFast

proc aflCompile*(target: string, c: Compiler) =
  let aflOptions = &"-d:afl -d:noSignalHandler {$c}"
  let compileCmd = &"nim c {defaultFlags} {aflOptions} {target.quoteShell()}"
  exec compileCmd

proc aflExec*(target: string, inputDir: string, resultsDir: string,
    cleanStart = false) =
  let exe = target.addFileExt(ExeExt)
  if not dirExists(inputDir):
    # create a input dir with one 0 file for afl
    mkDir(inputDir)
    # TODO: improve
    withDir inputDir: exec "echo '0' > test"

  var fuzzCmd: string
  # if there is an output dir already, continue fuzzing from previous run
  if (not dirExists(resultsDir)) or cleanStart:
    fuzzCmd = &"afl-fuzz -i {inputDir.quoteShell()} -o {resultsDir.quoteShell()} -M fuzzer01 -- {exe.quoteShell()}"
  else:
    fuzzCmd = &"afl-fuzz -i - -o {resultsDir.quoteShell()} -M fuzzer01 -- {exe.quoteShell()}"
  exec fuzzCmd

proc libFuzzerCompile*(target: string) =
  let libFuzzerOptions = &"-d:libFuzzer --noMain {libFuzzerClang}"
  let compileCmd = &"nim c {defaultFlags} {libFuzzerOptions} {target.quoteShell()}"
  exec compileCmd

proc libFuzzerExec*(target: string, corpusDir: string) =
  let exe = target.addFileExt(ExeExt)
  if not dirExists(corpusDir):
    # libFuzzer is OK when starting with empty corpus dir
    mkDir(corpusDir)

  exec &"{exe.quoteShell()} {corpusDir.quoteShell()}"

proc runFuzzer*(targetPath: string, fuzzer: Fuzzer) =
  let (path, target, ext) = splitFile(targetPath)

  case fuzzer
  of afl:
    aflCompile(targetPath, gcc)
    aflExec(path / target, path / "input", path / "results")

  of libFuzzer:
    libFuzzerCompile(targetPath)
    # Note: Lets not mix afl input with libFuzzer corpus default. This can have
    # consequences on speed for afl. Better to look into merging afl results &
    # libFuzzer corpus.
    libFuzzerExec(path / target, path / "corpus")
