# keys

This library is a Nim re-implementation of [eth-keys](https://github.com/ethereum/eth-keys): the common API for working with Ethereum's public and private keys, signatures, and addresses.

By default, Nim eth-keys uses Bitcoin's [libsecp256k1](https://github.com/bitcoin-core/secp256k1) as a backend. Make sure libsecp256k1 is available on your system.

An experimental pure Nim backend (Warning ⚠: do not use in production) is available with the compilation switch `-d:backend_native`

