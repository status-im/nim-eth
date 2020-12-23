# eth - Eth Common Library

[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)
![Github action](https://github.com/status-im/nim-eth/workflows/nim-eth%20CI/badge.svg)

## Introduction

Ethereum-related utilities written in Nim. Includes things like Bloom filters, private/public key utilities, RLP, devp2p, and more.

## Docs

- [rlp](doc/rlp.md)
- [p2p](doc/p2p.md)
- [keys](doc/keys.md)
- [keyfile](doc/keyfile.md)
- [trie](doc/trie.md)
- [bloom](doc/bloom.md)
- [discv5](doc/discv5.md)

## Prerequisites

- Nim & Nimble
- RocksDB, SQLite, LMDB (required for the trie backend tests)

E.g. on Ubuntu one can run:
```
apt install -y librocksdb-dev liblmdb-dev sqlite3
```

## Building & Testing
```
# Install required modules
nimble install
# Run full test suite
nimble test
```

You can also run specific parts of the test suite, e.g.:
```
# Test p2p functionality
nimble test_p2p
# Test rlp functionality
nimble test_rlp
```
## Fuzzing
Next to the test suite, there are also several fuzzing test cases available.
How these can be run is explained in the [fuzzing readme](https://github.com/status-im/nim-eth/blob/master/tests/fuzzing/readme.md).

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT

or

* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. This file may not be copied, modified, or distributed except according to those terms.
