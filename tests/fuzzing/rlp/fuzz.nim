import chronicles, eth/rlp, ../fuzztest

# TODO: have a default init as such
init:
  discard

test:
  try:
    var rlp = rlpFromBytes(payload.toRange)
    discard rlp.inspect()
  except RlpError:
    debug "Inspect failed", err = getCurrentExceptionMsg()
