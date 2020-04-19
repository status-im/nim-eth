const
  db_tracing* {.strdefine.} = "off"

var
  dbTracingEnabled* = true

when db_tracing in ["on", "1"]:
  import nimcrypto/utils

  template traceGet*(k, v) =
    if dbTracingEnabled:
      echo "GET ", toHex(k), " = ", toHex(v) # rlpFromBytes(v).inspect

  template tracePut*(k, v) =
    if dbTracingEnabled:
      echo "PUT ", toHex(k), " = ", toHex(v) # rlpFromBytes(v).inspect

  template traceDel*(k) =
    if dbTracingEnabled:
      echo "DEL ", toHex(k)
else:
  template traceGet*(k, v) = discard
  template tracePut*(k, v) = discard
  template traceDel*(k) = discard

