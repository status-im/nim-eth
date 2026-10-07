# ORC leaks `result` when a proc raises, exceeding libFuzzer's memory limit
# https://github.com/nim-lang/Nim/issues/25919
--mm:refc
