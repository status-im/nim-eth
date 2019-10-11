proc aflSwitches() =
  switch("define", "afl")
  switch("define", "noSignalHandler")
  switch("cc", "gcc")
  switch("gcc.exe", "afl-gcc")
  switch("gcc.linkerexe", "afl-gcc")
  switch("out", "fuzz-afl")

proc libFuzzerSwitches() =
  switch("define", "libFuzzer")
  switch("noMain", "")
  switch("cc", "clang")
  switch("passC", "-fsanitize=fuzzer,address")
  switch("passL", "-fsanitize=fuzzer,address")
  switch("out", "fuzz-libfuzzer")

proc generalSwitches() =
  switch("verbosity", "0")
  switch("hints", "off")
  switch("warnings", "off")
  switch("define", "chronicles_log_level:fatal")

task build_afl, "Build for afl fuzzing":
  aflSwitches()
  generalSwitches()
  setCommand("c")

task build_libfuzzer, "Build for libFuzzer fuzzing":
  libFuzzerSwitches()
  generalSwitches()
  setCommand("c")
