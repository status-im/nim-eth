import
  unittest2,
  ssz_serialization,
  macros,
  ../../eth/common/[addresses, base, hashes],
  ../../eth/ssz/[receipts]

template roundTrip*(v: var untyped) =
  var bytes = SSZ.encode(v)
  var v2 = SSZ.decode(bytes, v.type)
  var bytes2 = SSZ.encode(v2)
  check bytes == bytes2

template topicFill*(b: byte): untyped =
  (
    block:
      var buf: array[32, byte]
      for i in 0 ..< 32:
        buf[i] = b
      Hash32.copyFrom(buf)
  )

# Idea- pass only l values to this

macro testRT*(name: static[string], expr: typed): untyped =
  ## Roundtrip SSZ + size check.
  let valueSym = genSym(nskLet, "rtValue")
  let bytesSym = genSym(nskLet, "rtEncoded")
  let value2Sym = genSym(nskVar, "rtDecoded")
  let bytes2Sym = genSym(nskLet, "rtReencoded")

  result = quote:
    test `name`:
      let `valueSym` = `expr`
      when compiles(encodeReceipt(`valueSym`)):
        let `bytesSym` = encodeReceipt(`valueSym`)
        var `value2Sym` = decodeReceipt[type(`valueSym`)](`bytesSym`)
        let `bytes2Sym` = encodeReceipt(`value2Sym`)
        check `bytesSym` == `bytes2Sym`
        check sszSize(asTagged(`valueSym`)) == `bytesSym`.len
      else:
        let `bytesSym` = SSZ.encode(`valueSym`)
        var `value2Sym` = SSZ.decode(`bytesSym`, type(`valueSym`))
        let `bytes2Sym` = SSZ.encode(`value2Sym`)
        check `bytesSym` == `bytes2Sym`
        check sszSize(`valueSym`) == `bytesSym`.len

macro testRT*(name: static[string], expr: typed, body: untyped): untyped =
  ## Same as above, with an extra assertions block.
  let valueSym = genSym(nskLet, "rtValue")
  let bytesSym = genSym(nskLet, "rtEncoded")
  let value2Sym = genSym(nskVar, "rtDecoded")
  let bytes2Sym = genSym(nskLet, "rtReencoded")
  let userAlias = ident("v")

  result = quote:
    test `name`:
      let `valueSym` = `expr`
      when compiles(encodeReceipt(`valueSym`)):
        let `bytesSym` = encodeReceipt(`valueSym`)
        var `value2Sym` = decodeReceipt[type(`valueSym`)](`bytesSym`)
        let `bytes2Sym` = encodeReceipt(`value2Sym`)
        check `bytesSym` == `bytes2Sym`
        check sszSize(asTagged(`valueSym`)) == `bytesSym`.len
      else:
        let `bytesSym` = SSZ.encode(`valueSym`)
        var `value2Sym` = SSZ.decode(`bytesSym`, type(`valueSym`))
        let `bytes2Sym` = SSZ.encode(`value2Sym`)
        check `bytesSym` == `bytes2Sym`
        check sszSize(`valueSym`) == `bytesSym`.len
      block:
        let `userAlias` = `valueSym`
        `body`
