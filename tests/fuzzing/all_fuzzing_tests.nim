{. warning[UnusedImport]:off .}

# This file is there to be able to quickly build the fuzzer test cases in order
# to avoid bit rot (e.g. for CI).

import
  ./discovery/fuzz,
  ./discovery/generate,
  ./discoveryv5/fuzz_decode_message,
  ./discoveryv5/fuzz_decode_packet,
  ./enr/fuzz_enr,
  ./rlp/rlp_decode,
  ./rlp/rlp_inspect,
  ./rlpx/thunk,
  ./whisper/encode_decode
