import strformat, strutils

# Dependencies:
# - afl fuzzing: afl and gcc or clang/llvm
# - libFuzzer fuzzing: libFuzzer and clang/llvm
# - in afl experimental modes clang/llvm is also required

# TODO:
# - switch clang / gcc option for afl
# - afl init and persistent modes
# - parallel fuzzing
# - custom generate test cases from this script?
# - rerun testcases option (or create tests from failed cases)?
# - better cmd line parsing & and more options

const aflGcc = "--cc=gcc " &
                "--gcc.exe=afl-gcc " &
                "--gcc.linkerexe=afl-gcc"
const aflClang = "--cc=clang " &
                  "--clang.exe=afl-clang " &
                  "--clang.linkerexe=afl-clang"
const aflClangFast = "--cc=clang " &
                      "--clang.exe=afl-clang-fast " &
                      "--clang.linkerexe=afl-clang-fast"
const libFuzzerClang = "--cc=clang " &
                        "--passC='-fsanitize=fuzzer,address' " &
                        "--passL='-fsanitize=fuzzer,address'"
# Can also test in debug mode obviously, but might be slower
# Can turn on more logging, in case of libFuzzer it will get very verbose though
const defaultFlags = "-d:release -d:chronicles_log_level=fatal " &
                      "--hints:off --warnings:off --verbosity:0"
const inputDir = "input" # dir for input samples
const resultsDir = "results" # results dir (for afl)

if paramCount() < 3:
  echo "Usage: nim fuzz.nims FUZZER TARGET"
  echo "Fuzzer options are afl or libFuzzer"
  quit 1

let
  fuzzer = paramStr(2)
  targetPath = paramStr(3)

if not fileExists(targetPath):
  echo "Target file does not exist"
  quit 1

let splitFile = targetPath.rsplit("/", 1)
let workDir = splitFile[0]
let targetNimFile = splitFile[1]
var target = targetNimFile
target.removeSuffix(".nim")
cd workDir

case fuzzer
of "afl":
  let aflOptions = &"-d:afl -d:noSignalHandler {aflGcc}"
  let compileCmd = &"nim c {defaultFlags} {aflOptions} {target}"
  exec compileCmd

  if not dirExists(inputDir):
    # create a input dir with one 0 file for afl
    mkDir(inputDir)
    withDir inputDir: exec "echo '0' > test"

  var fuzzCmd: string
  # if there is an output dir already, continue fuzzing from previous run
  if not dirExists(resultsDir):
    fuzzCmd = &"afl-fuzz -i {inputDir} -o {resultsDir} -M fuzzer01 -- ./{target}"
  else:
    fuzzCmd = &"afl-fuzz -i - -o {resultsDir} -M fuzzer01 -- ./{target}"
  exec fuzzCmd

of "libFuzzer":
  let libFuzzerOptions = &"--noMain {libFuzzerClang}"
  let compileCmd = &"nim c {defaultFlags} {libFuzzerOptions} {target}"
  exec compileCmd

  if not dirExists(inputDir):
    # libFuzzer is OK with empty input dir
    mkDir(inputDir)

  # TODO: could use {resultsDir} of afl here also to reuse as corpus
  exec &"./{target} {inputDir}"

else:
  echo "Invalid fuzzer option: ", fuzzer
  echo "Fuzzer options are afl or libFuzzer"
  quit 1