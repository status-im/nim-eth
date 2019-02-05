import
  json, strutils, eth/rlp

proc append(output: var RlpWriter, js: JsonNode) =
  case js.kind
  of JNull, JFloat, JObject:
    raise newException(ValueError, "Unsupported JSON value type " & $js.kind)
  of JBool:
    output.append js.bval.int
  of JInt:
    output.append int(js.num)
  of JString:
    output.append js.str
  of JArray:
    output.append js.elems

proc hexRepr*(bytes: BytesRange|Bytes): string =
  result = newStringOfCap(bytes.len * 2)
  for byte in bytes:
    result.add(toHex(int(byte), 2).toLowerAscii)

proc `==`(lhs: JsonNode, rhs: string): bool =
  lhs.kind == JString and lhs.str == rhs

proc runTests*(filename: string) =
  let js = json.parseFile(filename)

  for testname, testdata in js:
    template testStatus(status: string) =
      echo status, " ", filename, " :: ", testname

    let
      input = testdata{"in"}
      output = testdata{"out"}

    if input.isNil or output.isNil or output.kind != JString:
      testStatus "IGNORED"
      continue

    if input == "VALID":
      var rlp = rlpFromHex(output.str)
      discard rlp.inspect
    elif input == "INVALID":
      var success = false
      var inspectOutput = ""
      try:
        var rlp = rlpFromHex(output.str)
        inspectOutput = rlp.inspect(1)
        discard rlp.getType
        while rlp.hasData: discard rlp.toNodes
      except MalformedRlpError, ValueError:
        success = true
      if not success:
        testStatus "FAILED"
        echo "  ACCEPTED MALFORMED BYTES: ", output.str
        echo "  INTERPRETATION:\n", inspectOutput
        continue
    else:
      if input.kind == JString and input.str.len != 0 and input.str[0] == '#':
        continue

      var outRlp = initRlpWriter()
      outRlp.append input
      let
        actual = outRlp.finish.hexRepr
        expected = output.str
      if actual != expected:
        testStatus "FAILED"
        echo "  EXPECTED BYTES: ", expected
        echo "  ACTUAL   BYTES: ", actual
        continue

    testStatus "OK"

