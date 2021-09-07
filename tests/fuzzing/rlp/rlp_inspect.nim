import
  testutils/fuzzing, chronicles,
  ../../../eth/rlp

test:
  try:
    var rlp = rlpFromBytes(payload)
    discard rlp.inspect()
  except RlpError as e:
    debug "Inspect failed", err = e.msg
