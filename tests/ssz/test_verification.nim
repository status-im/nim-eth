{.used.}

import 
  sequtils, unittest,
  nimcrypto/[hash, sha2], 
  ../eth/ssz/merkleization

type TestCase = object
  root: string
  proof: seq[string]
  leaf: string
  index: uint64
  valid: bool

let testCases = @[
  TestCase(
    root: "2a23ef2b7a7221eaac2ffb3842a506a981c009ca6c2fcbf20adbc595e56f1a93",
    proof: @[
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
    ],
    leaf:  "0100000000000000000000000000000000000000000000000000000000000000",
    index: 4,
    valid: true
  ),
  TestCase(
    root: "2a23ef2b7a7221eaac2ffb3842a506a981c009ca6c2fcbf20adbc595e56f1a93",
    proof: @[
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
    ],
    leaf:  "0100000000000000000000000000000000000000000000000000000000000000",
    index: 6,
    valid: false
  ),
  TestCase(
    root: "2a23ef2b7a7221eaac2ffb3842a506a981c009ca6c2fcbf20adbc595e56f1a93",
    proof: @[
      "0100000000000000000000000000000000000000000000000000000000000000",
      "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
    ],
    leaf: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    index: 5,
    valid: true
  ),
  TestCase(
    root: "f1824b0084956084591ff4c91c11bcc94a40be82da280e5171932b967dd146e9",
    proof: @[
      "35210d64853aee79d03f30cf0f29c1398706cbbcacaf05ab9524f00070aec91e",
      "f38a181470ef1eee90a29f0af0a9dba6b7e5d48af3c93c29b4f91fa11b777582"
    ],
    leaf: "0100000000000000000000000000000000000000000000000000000000000000",
    index: 7,
    valid: true
  ),
  TestCase(
    root: "f1824b0084956084591ff4c91c11bcc94a40be82da280e5171932b967dd146e9",
    proof: @[
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
      "0100000000000000000000000000000000000000000000000000000000000000",
      "f38a181470ef1eee90a29f0af0a9dba6b7e5d48af3c93c29b4f91fa11b777582"
    ],
    leaf: "6001000000000000000000000000000000000000000000000000000000000000",
    index: 49,
    valid: true
  )
]

suite "Merkle Proof verification":
  test "correctly verify proof":
    for testCase in testCases:
      let root = MDigest[256].fromHex(testCase.root)
      let proof = map(testCase.proof, proc(x: string): Digest = MDigest[256].fromHex(x))
      let leaf = MDigest[256].fromHex(testCase.leaf)
      let valid = isValidProof(leaf, proof, testCase.index, root)

      if (testCase.valid):
        check valid
      else:
        check (not valid)
