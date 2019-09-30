import ./fuzz_helpers

# TODO: get this some nice cmd line options when confutils works for nimscript
# or if we want to put this in a nim application instead of script

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

case fuzzer
of "afl":
  runFuzzer(targetPath, afl)
of "libFuzzer":
  runFuzzer(targetPath, libFuzzer)

else:
  echo "Invalid fuzzer option: ", fuzzer
  echo "Fuzzer options are afl or libFuzzer"
  quit 1
