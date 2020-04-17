{.used.}

import
  os, json, tables, strutils, algorithm,
  eth/rlp/types,
  eth/trie/[trie_defs, db, hexary],
  ./testutils

type
  TestOp = object
    idx: int
    key: BytesRange
    value: BytesRange

proc cmp(lhs, rhs: TestOp): int = cmp(lhs.idx, rhs.idx)
proc `<=`(lhs, rhs: TestOp): bool = lhs.idx <= rhs.idx

proc runSingleTest(testSequence: openarray[TestOp],
                   secureMode: bool,
                   expectedRootHash: string): bool =
  var
    db = newMemoryDB()
    t = initHexaryTrie(db)

  for op in testSequence:
    let
      k = op.key
      v = op.value

    if v.len > 0:
      if secureMode:
        t.SecureHexaryTrie.put k, v
      else:
        t.put k, v
    else:
      if secureMode:
        t.SecureHexaryTrie.del k
      else:
        t.del k

  return t.rootHashHex == expectedRootHash

proc runTests*(filename: string) =
  let js = json.parseFile(filename)

  for testname, testdata in js:
    template testStatus(status: string) =
      echo status, " ", filename, " :: ", testname

    template invalidTest =
      testStatus "IGNORED"
      continue

    let
      input = testdata{"in"}
      root = testdata{"root"}
      secureMode = "secure" in filename
      permuteOrder = "anyorder" in filename

    if input.isNil or root.isNil or root.kind != JString:
      invalidTest()

    var inputs = newSeq[TestOp](0)

    case input.kind
    of JArray:
      for pair in input.elems:
        if pair.kind != JArray or pair.elems.len != 2:
          invalidTest()

        let
          k = pair.elems[0]
          v = pair.elems[1]

        if k.kind == JString:
          case v.kind
          of JString:
            inputs.add(TestOp(idx: inputs.len,
                              key: k.str.toBytesRange,
                              value: v.str.toBytesRange))
          of JNull:
            inputs.add(TestOp(idx: inputs.len,
                              key: k.str.toBytesRange,
                              value: zeroBytesRange))

          else: invalidTest()
        else: invalidTest()

    of JObject:
      for k, v in input.fields:
        case v.kind
        of JString:
          inputs.add(TestOp(idx: inputs.len,
                            key: k.toBytesRange,
                            value: v.str.toBytesRange))
        of JNull:
          inputs.add(TestOp(idx: inputs.len,
                            key: k.toBytesRange,
                            value: zeroBytesRange))

        else: invalidTest()
    else: invalidTest()

    let expectedRootHash = root.str.substr(2).toUpperAscii

    if permuteOrder:
      sort(inputs, cmp)
      while true:
        if not runSingleTest(inputs, secureMode, expectedRootHash):
          testStatus "FAILED"
          break

        if not nextPermutation(inputs):
          testStatus "OK"
          break

    else:
      if runSingleTest(inputs, secureMode, expectedRootHash):
        testStatus "OK"
      else:
        testStatus "FAILED"

for file in walkDirRec("tests/cases"):
  if file.endsWith("json"):
    runTests(file)

