{.used.}

import unittest, eth/common, eth/rlp

proc `==`(a, b: HashOrStatus): bool =
  result = a.isHash == b.isHash
  if not result: return
  if a.isHash:
    result = result and a.hash == b.hash
  else:
    result = result and a.status == b.status

suite "rlp encoding":

  test "receipt roundtrip":
    var a, b, c, d: Receipt

    var hash = rlpHash(a)
    a.stateRootOrStatus = hashOrStatus(hash)
    a.cumulativeGasUsed = 21000
    a.logs = @[]

    b.stateRootOrStatus = hashOrStatus(true)
    b.cumulativeGasUsed = 52000
    b.logs = @[]

    var x = rlp.encode(a)
    var y = rlp.encode(b)

    c = x.decode(Receipt)
    d = y.decode(Receipt)
    check c == a
    check d == b

    check c.hasStateRoot
    check c.stateRoot == hash
    check d.hasStatus
    check d.status == 1
