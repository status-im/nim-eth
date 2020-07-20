import
  testutils/fuzzing, chronicles, stew/byteutils,
  eth/rlp, eth/p2p/discoveryv5/encoding

test:
  block:
    # This test also includes the decoding of the ENR, so it kinda overlaps with
    # the fuzz_enr test. And it will fail to decode most of the time for the
    # same reasons.
    let decoded = try: rlp.decode(payload, AuthResponse)
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
    # This will hit assert because of issue:
    # https://github.com/status-im/nim-eth/issues/255
    # if encoded != payload.toOpenArray(0, encoded.len - 1):
    #     echo "payload: ", toHex(payload.toOpenArray(0, encoded.len - 1))
    #     echo "encoded: ", toHex(encoded)

    #     doAssert(false, "re-encoded result does not equal original payload")
