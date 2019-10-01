import chronicles, eth/rlp, ../fuzztest

test:
  try:
    var rlp = rlpFromBytes(@payload.toRange)
    discard rlp.inspect()
  except RlpError:
    debug "Inspect failed", err = getCurrentExceptionMsg()
