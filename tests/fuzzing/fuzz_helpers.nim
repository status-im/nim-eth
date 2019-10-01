import strformat, strutils

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
                 "--clang.linkerexe=afl-clang-fast"
  libFuzzerClang = "--cc=clang " &
                   "--passC='-fsanitize=fuzzer,address' " &
                   "--passL='-fsanitize=fuzzer,address'"
# Can also test in debug mode obviously, but might be slower
# Can turn on more logging, in case of libFuzzer it will get very verbose though
  defaultFlags = "-d:release -d:chronicles_log_level=fatal "# &
                #  "--hints:off --warnings:off --verbosity:0"

type
  Fuzzer* = enum
    afl,
    libFuzzer

  Compiler* = enum
    gcc = aflGcc,
    clang = aflClang,
    clangFast = aflClangFast

proc aflCompile*(target: string, c: Compiler) =
  let aflOptions = &"-d:standalone -d:noSignalHandler {$c}"
  let compileCmd = &"""nim c {defaultFlags} {aflOptions} {target}"""
  exec compileCmd

proc aflExec*(target: string, inputDir: string, resultsDir: string,
    cleanStart = false) =
  if not dirExists(inputDir):
    # create a input dir with one 0 file for afl
    mkDir(inputDir)
    withDir inputDir: exec "echo '0' > test"

  var fuzzCmd: string
  # if there is an output dir already, continue fuzzing from previous run
  if (not dirExists(resultsDir)) or cleanStart:
    fuzzCmd = &"""afl-fuzz -i {inputDir} -o {resultsDir} -M fuzzer01 -- ./{target}"""
  else:
    fuzzCmd = &"""afl-fuzz -i - -o {resultsDir} -M fuzzer01 -- ./{target}"""
  exec fuzzCmd

proc libFuzzerCompile*(target: string) =
  let libFuzzerOptions = &"--noMain {libFuzzerClang}"
  let compileCmd = &"""nim c {defaultFlags} {libFuzzerOptions} {target}"""
  exec compileCmd

proc libFuzzerExec*(target: string, corpusDir: string) =
  if not dirExists(corpusDir):
    # libFuzzer is OK when starting with empty corpus dir
    mkDir(corpusDir)

  exec &"""./{target} {corpusDir}"""

proc getDir*(path: string): string =
  # TODO: This is not platform friendly at all.
  let splitFile = path.rsplit("/", 1)
  result = splitFile[0]

proc getTarget*(path: string): string =
  # TODO: error handling
  result = path
  result.removeSuffix(".nim")

proc runFuzzer*(targetPath: string, fuzzer: Fuzzer) =
  let
    path = getDir(targetPath)
    target = getTarget(targetPath)
  case fuzzer
  of afl:
    aflCompile(targetPath, gcc)
    aflExec(target, path & "/input", path & "/results")

  of libFuzzer:
    libFuzzerCompile(targetPath)
    # Note: Lets not mix afl input with libFuzzer corpus default. This can have
    # consequences on speed for afl. Better to look into merging afl results &
    # libFuzzer corpus.
    libFuzzerExec(target, path & "/corpus")
