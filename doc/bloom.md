# bloom: an Ethereum Bloom Filter

# Introduction

A Nim implementation of the bloom filter used by Ethereum.

# Description

[Bloom filters](https://en.wikipedia.org/wiki/Bloom_filter) are data structures that use hash functions to test whether an element is a member of a set. They work like other data structures but are probabilistic in nature: that is, they allow false positive matches but not false negative. Bloom filters use less storage space than other data structures.

Ethereum bloom filters are implemented with the Keccak-256 cryptographic hash function.

To see the bloom filter used in the context of Ethereum, please refer to the [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).


# Usage
```nim
import eth/bloom, stint
var f: BloomFilter
f.incl("test1")
doAssert("test1" in f)
doAssert("test2" notin f)
f.incl("test2")
doAssert("test2" in f)
doAssert(f.value.toHex == "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000200000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000")
```

