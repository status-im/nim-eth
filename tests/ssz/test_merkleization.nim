{.used.}

import 
  sequtils, unittest,
  nimcrypto/[hash, sha2], stew/endians2, 
  ../eth/ssz/merkleization

proc h(a, b: seq[byte]): seq[byte] =
  var h: sha256
  h.init()
  h.update(a & b)
  h.finish().data.toSeq()
 
proc e(v: uint32): seq[byte] =
  let elem: uint8 = 255
  newSeqWith(28, elem) & v.toBytesLe().toSeq()

proc z(i: int): seq[byte] =
  zerohashes[i].data.toSeq()

type TestData[limit: static int64] = object
  count: uint32
  expectedRoot: seq[byte]

# only happy cases as our merkleizer will happy accept more chunks than limit
# cases from - https://github.com/ethereum/eth2.0-specs/blob/dev/tests/core/pyspec/eth2spec/utils/test_merkle_minimal.py
let cases = (
  TestData[0](count: 0, expectedRoot: z(0)),
  TestData[1](count: 0, expectedRoot: z(0)),
  TestData[1](count: 1, expectedRoot: e(0)),

  TestData[2](count: 0, expectedRoot: h(z(0), z(0))),
  TestData[2](count: 1, expectedRoot: h(e(0), z(0))),
  TestData[2](count: 2, expectedRoot: h(e(0), e(1))),

  TestData[4](count: 0, expectedRoot: h(h(z(0), z(0)), z(1))),
  TestData[4](count: 1, expectedRoot: h(h(e(0), z(0)), z(1))),
  TestData[4](count: 2, expectedRoot: h(h(e(0), e(1)), z(1))),
  TestData[4](count: 3, expectedRoot: h(h(e(0), e(1)), h(e(2), z(0)))),
  TestData[4](count: 4, expectedRoot: h(h(e(0), e(1)), h(e(2), e(3)))),

  TestData[8](count: 0, expectedRoot: h(h(h(z(0), z(0)), z(1)), z(2))),
  TestData[8](count: 1, expectedRoot: h(h(h(e(0), z(0)), z(1)), z(2))),
  TestData[8](count: 2, expectedRoot: h(h(h(e(0), e(1)), z(1)), z(2))),
  TestData[8](count: 3, expectedRoot: h(h(h(e(0), e(1)), h(e(2), z(0))), z(2))),
  TestData[8](count: 4, expectedRoot: h(h(h(e(0), e(1)), h(e(2), e(3))), z(2))),
  TestData[8](count: 5, expectedRoot: h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), z(0)), z(1)))),
  TestData[8](count: 6, expectedRoot: h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(z(0), z(0))))),
  TestData[8](count: 7, expectedRoot: h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), z(0))))),
  TestData[8](count: 8, expectedRoot: h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), e(7))))),

  TestData[16](count: 0, expectedRoot: h(h(h(h(z(0), z(0)), z(1)), z(2)), z(3))),
  TestData[16](count: 1, expectedRoot: h(h(h(h(e(0), z(0)), z(1)), z(2)), z(3))),
  TestData[16](count: 2, expectedRoot: h(h(h(h(e(0), e(1)), z(1)), z(2)), z(3))),
  TestData[16](count: 3, expectedRoot: h(h(h(h(e(0), e(1)), h(e(2), z(0))), z(2)), z(3))),
  TestData[16](count: 4, expectedRoot: h(h(h(h(e(0), e(1)), h(e(2), e(3))), z(2)), z(3))),
  TestData[16](count: 5, expectedRoot: h(h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), z(0)), z(1))), z(3))),
  TestData[16](count: 6, expectedRoot: h(h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(z(0), z(0)))), z(3))),
  TestData[16](count: 7, expectedRoot: h(h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), z(0)))), z(3))),
  TestData[16](count: 8, expectedRoot: h(h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), e(7)))), z(3))),
  TestData[16](count: 9, expectedRoot: h(h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), e(7)))), h(h(h(e(8), z(0)), z(1)), z(2))))
)

suite "Merkleization":
  test "calculate correct root from provided chunks":
    for testCase in cases.fields:
      var merk = createMerkleizer(testCase.limit)
      var i: uint32 = 0

      while i < testCase.count:
        let elem = e(i)
        merk.addChunk(elem)
        i = i + 1
        
      let calculatedRoot = merk.getFinalhash()

      check calculatedRoot.data.toSeq() == testCase.expectedRoot
