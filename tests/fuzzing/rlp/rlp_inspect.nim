import
  testutils/fuzzing,
  ../../../eth/rlp

test:
  try:
    var rlp = rlpFromBytes(payload)
    discard rlp.inspect()
  except RlpError as e:
    echo "Inspect failed: " & e.msg
