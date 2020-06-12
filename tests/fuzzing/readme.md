# Fuzzing Tests
The fuzzing tests use the fuzzing templates from `nim-testutils`.

For more details see [the fuzzing readme of nim-testutils](https://github.com/status-im/nim-testutils/tree/master/testutils/fuzzing).

## Prerequisites
As [explained](https://github.com/status-im/nim-testutils/tree/master/testutils/fuzzing#supported-fuzzers)
in `nim-testutils` fuzzing readme, first install the fuzzer you want to run.

Next install `nim-testutils` its `ntu` application.

E.g. by running the `nim-testutils` nimble install:
```sh
nimble install nim-testutils
```

## How to run
To start fuzzing a testcase run following command:
```sh
# For libFuzzer
ntu fuzz --fuzzer:libFuzzer rlp/rlp_inspect
# For afl
ntu fuzz --fuzzer:afl rlp/rlp_inspect
```
