# Fuzzing Tests
This directory contains a set of subdirectories which hold one or more test cases that can be used for fuzzing.
The fuzzing test cases use the fuzzing templates from `nim-testutils`.

For more details see [the fuzzing readme of nim-testutils](https://github.com/status-im/nim-testutils/tree/master/testutils/fuzzing).

Some of the subdirectories also hold corpus generation tooling in order to have some corpus files to start fuzzing from.

## Prerequisites
As [explained](https://github.com/status-im/nim-testutils/tree/master/testutils/fuzzing#supported-fuzzers)
in `nim-testutils` fuzzing readme, first install the fuzzer you want to run.

Next install `nim-testutils` its `ntu` application.

E.g. by running the `nim-testutils` nimble install:
```sh
nimble install testutils
```

## How to run
To start fuzzing a test case run following command:
```sh
# Rlp fuzzing with libFuzzer
ntu fuzz --fuzzer:libFuzzer rlp/rlp_decode
# Rlp fuzzing with afl
ntu fuzz --fuzzer:afl rlp/rlp_decode
```
Or another example:
```sh
# ENR fuzzing with libFuzzer
ntu fuzz --fuzzer:libFuzzer enr/fuzz_enr
# ENR fuzzing with afl
ntu fuzz --fuzzer:afl enr/fuzz_enr
```

## Manual adjustments
The `ntu` application is still very limited in its functionality. Many of the underlying fuzzer functionality is not available for adjustment so you might want to configure the setup in a more manual way. 

How to do this is briefly explained [here for afl](https://github.com/status-im/nim-testutils/blob/master/testutils/fuzzing/readme.md#manually-with-afl) and [here for libFuzzer](https://github.com/status-im/nim-testutils/blob/master/testutils/fuzzing/readme.md#manually-with-libfuzzer).
