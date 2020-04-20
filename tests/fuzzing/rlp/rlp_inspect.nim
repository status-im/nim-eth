import chronicles, eth/rlp, ../fuzztest

test:
  try:
    var rlp = rlpFromBytes(payload)
    discard rlp.inspect()
  except RlpError as e:
    debug "Inspect failed", err = e.msg
