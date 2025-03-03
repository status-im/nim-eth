# eth
# Copyright (c) 2019-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/json,
  unittest2,
  stew/byteutils,
  ../../../eth/rlp

proc append(output: var RlpWriter, js: JsonNode) =
  case js.kind
  of JNull, JFloat, JObject:
    raise newException(ValueError, "Unsupported JSON value type " & $js.kind)
  of JBool:
    output.append js.bval
  of JInt:
    if js.num < 0:
      raise  newException(ValueError, "Integer out of range: " & $js.num)
    output.append uint64(js.num)
  of JString:
    output.append js.str
  of JArray:
    output.append js.elems

proc `==`(lhs: JsonNode, rhs: string): bool =
  lhs.kind == JString and lhs.str == rhs

proc runTests*(filename: string) =
  let js = json.parseFile(filename)

  suite filename:
    for testname, testdata in js:
      test testname:
        let
          input = testdata{"in"}
          output = testdata{"out"}

        if input.isNil or output.isNil or output.kind != JString:
          skip()
          return

        if input == "VALID":
          var rlp = rlpFromHex(output.str)
          discard rlp.inspect
        elif input == "INVALID":
          var success = true
          var inspectOutput = ""
          expect MalformedRlpError, UnsupportedRlpError, ValueError:
            var rlp = rlpFromHex(output.str)
            inspectOutput = rlp.inspect(1)
            rlp.validate()
            success = false
          if not success:
            echo "  ACCEPTED MALFORMED BYTES: ", output.str
            echo "  INTERPRETATION:\n", inspectOutput
        else:
          if input.kind == JString and input.str.len != 0 and input.str[0] == '#':
            skip()
            return

          let
            actual = rlp.encode(input).toHex
            expected = output.str
          check actual == expected

