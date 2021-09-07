import
  testutils/fuzzing, stew/byteutils,
  ../../../eth/rlp, ../../../eth/p2p/discoveryv5/enr

test:
  block:
    # This is fuzzing the full ENR deserialisation. As ENRs contain a signature
    # this will practically always fail. So the second (encoding) steps will
    # never be reached.
    # However, as the signature checking is done at the end, a big part of the
    # parsing will still be fuzzed.
    let decoded = try: rlp.decode(payload, enr.Record)
                  except RlpError as e:
                        debug "decode failed", err = e.msg
                        break
                  except ValueError as e:
                        debug "decode failed", err = e.msg
                        break

    let encoded = try: rlp.encode(decoded)
                  except RlpError as e:
                    debug "decode failed", err = e.msg
                    doAssert(false, "decoding worked but encoding failed")
                    break
    if encoded != payload.toOpenArray(0, encoded.len - 1):
        echo "payload: ", toHex(payload.toOpenArray(0, encoded.len - 1))
        echo "encoded: ", toHex(encoded)

        doAssert(false, "re-encoded result does not equal original payload")
