import os, ../../rlp

if paramCount() > 0:
  echo rlpFromHex(paramStr(1)).inspect
else:
  echo "Please provide an hex-encoded RLP string as an input"

