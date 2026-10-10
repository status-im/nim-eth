import
  testutils/fuzzing,
  ../../../eth/common/eth_types_rlp,
  ../fuzzing_helpers

test:
  checkRoundTrip(payload, Transaction)
  checkRoundTrip(payload, seq[Transaction])
  checkRoundTrip(payload, AccessList)
  checkRoundTrip(payload, seq[Authorization])
  checkRoundTrip(payload, Opt[Address])
  checkRoundTrip(payload, UInt256)
  checkRoundTrip(payload, Receipt)
  checkRoundTrip(payload, seq[Receipt])
  checkRoundTrip(payload, StoredReceipt)
  checkRoundTrip(payload, seq[StoredReceipt])
  checkRoundTrip(payload, Header)
  checkRoundTrip(payload, BlockBody)
  checkRoundTrip(payload, Block)
  checkRoundTrip(payload, BlockAccessList)
