{.used.}

import
  unittest, strutils,
  nimcrypto/[keccak, hash],
  eth/trie/[binaries, trie_bitseq],
  ./testutils, stew/byteutils

proc parseBitVector(x: string): TrieBitSeq =
  result = genBitVec(x.len)
  for i, c in x:
    result[i] = (c == '1')

const
  commonPrefixData = [
    (@[0b0000_0000.byte], @[0b0000_0000.byte], 8),
    (@[0b0000_0000.byte], @[0b1000_0000.byte], 0),
    (@[0b1000_0000.byte], @[0b1100_0000.byte], 1),
    (@[0b0000_0000.byte], @[0b0100_0000.byte], 1),
    (@[0b1110_0000.byte], @[0b1100_0000.byte], 2),
    (@[0b0000_1111.byte], @[0b1111_1111.byte], 0)
  ]

suite "binaries utils":

  test "get common prefix length":
    for c in commonPrefixData:
      var
        c0 = c[0]
        c1 = c[1]
      let actual_a = getCommonPrefixLength(c0.bits, c1.bits)
      let actual_b = getCommonPrefixLength(c1.bits, c0.bits)
      let expected = c[2]
      check actual_a == actual_b
      check actual_a == expected

  const
    None = ""
    parseNodeData = {
      "\x00\x03\x04\x05\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p":
        (0, "00110000010000000101", "\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p", false),
      "\x01\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p":
        (1, "\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p", "\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p", false),
      "\x02value": (2, None, "value", false),
      "": (0, None, None, true),
      "\x00\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p": (0, None, None, true),
      "\x01\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p": (0, None, None, true),
      "\x01\x02\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p":
        (0, None, None, true),
      "\x02": (0, None, None, true),
      "\x03": (0, None, None, true)
    }

  test "node parsing":
    for c in parseNodeData:
      let input = toBytes(c[0])
      let node = c[1]
      let kind = TrieNodeKind(node[0])
      let raiseError = node[3]
      var res: TrieNode

      if raiseError:
        expect(InvalidNode):
          res = parseNode(input)
      else:
        res = parseNode(input)

      check(kind == res.kind)
      case res.kind
      of KV_TYPE:
        check(res.keyPath == parseBitVector(node[1]))
        check(res.child == toBytes(node[2]))
      of BRANCH_TYPE:
        check(res.leftChild == toBytes(node[2]))
        check(res.rightChild == toBytes(node[2]))
      of LEAF_TYPE:
        check(res.value == toBytes(node[2]))

  const
    kvData = [
      ("0", "\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p", "\x00\x10\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p", false),
      (""    , "\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p", None, true),
      ("0", "\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p", None, true),
      ("1", "\x00\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p", None, true),
      ("2", "", None, true)
    ]

  test "kv node encoding":
    for c in kvData:
      let keyPath = parseBitVector(c[0])
      let node    = toBytes(c[1])
      let output  = toBytes(c[2])
      let raiseError = c[3]

      if raiseError:
        expect(ValidationError):
          check output == encodeKVNode(keyPath, node)
      else:
        check output == encodeKVNode(keyPath, node)

  const
    branchData = [
      ("\xc8\x9e\xfd\xaaT\xc0\xf2\x0cz\xdfa(\x82\xdf\tP\xf5\xa9Qc~\x03\x07\xcd\xcbLg/)\x8b\x8b\xc6", "\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p",
        "\x01\xc8\x9e\xfd\xaaT\xc0\xf2\x0cz\xdfa(\x82\xdf\tP\xf5\xa9Qc~\x03\x07\xcd\xcbLg/)\x8b\x8b\xc6\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p", false),
      ("", "\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p", None, true),
      ("\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p", "\x01", None, true),
      ("\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p", "12345", None, true),
      (repeat('\x01', 33), repeat('\x01', 32), None, true),
    ]

  test "branch node encode":
    for c in branchData:
      let left   = toBytes(c[0])
      let right  = toBytes(c[1])
      let output = toBytes(c[2])
      let raiseError = c[3]

      if raiseError:
        expect(ValidationError):
          check output == encodeBranchNode(left, right)
      else:
        check output == encodeBranchNode(left, right)

  const
    leafData = [
      ("\x03\x04\x05", "\x02\x03\x04\x05", false),
      ("", None, true)
    ]

  test "leaf node encode":
    for c in leafData:
      let raiseError = c[2]
      if raiseError:
        expect(ValidationError):
          check toBytes(c[1]) == encodeLeafNode(toBytes(c[0]))
      else:
        check toBytes(c[1]) == encodeLeafNode(toBytes(c[0]))

  test "random kv encoding":
    let lengths = randList(int, randGen(1, 999), randGen(100, 100), unique = false)
    for len in lengths:
      var k = len
      var bitvec = genBitVec(len)
      var nodeHash = keccak256.digest(cast[ptr byte](k.addr), uint(sizeof(int)))
      var kvnode = encodeKVNode(bitvec, @(nodeHash.data))
      # first byte if KV_TYPE
      # in the middle are 1..n bits of binary-encoded-keypath
      # last 32 bytes are hash
      var keyPath = decodeToBinKeypath(kvnode[1..^33])
      check kvnode[0].ord == KV_TYPE.ord
      check keyPath == bitvec
      check kvnode[^32..^1] == nodeHash.data

  test "optimized single bit keypath kvnode encoding":
    var k = 1
    var nodeHash = keccak256.digest(cast[ptr byte](k.addr), uint(sizeof(int)))
    var bitvec = genBitVec(1)
    bitvec[0] = false
    var kvnode = encodeKVNode(bitvec, @(nodeHash.data))
    var kp = decodeToBinKeypath(kvnode[1..^33])

    var okv = encodeKVNode(false, @(nodeHash.data))
    check okv == kvnode
    var okp = decodeToBinKeypath(kvnode[1..^33])
    check okp == kp
    check okp.len == 1
    check okp == bitvec

    bitvec[0] = true
    kvnode = encodeKVNode(bitvec, @(nodeHash.data))
    kp = decodeToBinKeypath(kvnode[1..^33])

    okv = encodeKVNode(true, @(nodeHash.data))
    check okv == kvnode
    okp = decodeToBinKeypath(kvnode[1..^33])
    check okp == kp
    check okp.len == 1
    check okp == bitvec
