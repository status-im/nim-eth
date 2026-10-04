import
  testutils/fuzzing,
  ../../../eth/rlp

test:
  try:
    var rlp = rlpFromBytes(payload)
    discard rlp.inspect()
  except RlpError:
    discard
