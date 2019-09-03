# TODO: make this configurable when more fuzzing targets
cd "discovery"

if not dirExists("generated-input"):
  exec "nim c -r generate"

if not fileExists("fuzz"):
  # Requires afl-gcc to be installed
  # TODO: add + test option for clang
  exec "nim c -d:afl -d:noSignalHandler --cc=gcc --gcc.exe=afl-gcc --gcc.linkerexe=afl-gcc fuzz"
if dirExists("output"):
  exec "afl-fuzz -i - -o output -M fuzzer01 -- ./fuzz"
else:
  exec "afl-fuzz -i generated-input -o output -M fuzzer01 -- ./fuzz"

# TODO: how to add slaves for multiple cores in nimscript?
# afl-fuzz -i generated-input -o output -S fuzzer02 -- ./fuzz
