## To replicate here after i have though of the transaction api 

# Header: rlp roundtrip EIP-1559 / EIP-4895 / EIP-4844
# EIP-2930 receipt
# Legacy Tx
# Access List Tx
# Contract creation
# Tx with EIP-155 chainId
# Tx with empty access list
# Contract creation with empty Access List
# Tx with Access List order swap
# Tx with empty access list
# Contract creation with access list
# Dynamic Fee Tx
# NetworkBlob Tx
# Minimal Blob Tx
# Minimal Blob Tx contract creation
# EIP 7702
# Minimal Blob tx recipient survive encode decode
# Tx List 0,1,2,3,4,5,6,7,8
# Tx List 8,7,6,5,4,3,2,1,0
# Tx List 0,5,8,7,6,4,3,2,1
# EIP-155 signature
# sign transaction
# 
# # --- BEGIN: Stubs for remaining coverage ---

# If you need extra helpers, add them here:
proc encodeRlp*(tx: Transaction): seq[byte] {.inline.} =
  ## TODO: wire to your actual RLP encoder for Transaction
  @[]

proc decodeRlpTx*(bytes: openArray[byte]): Transaction {.inline.} =
  ## TODO: wire to your actual RLP decoder for Transaction
  Transaction() # placeholder

proc encodeHeaderRlp*(/*Header*/): seq[byte] = @[]      # TODO
proc decodeHeaderRlp*(bytes: openArray[byte]) = discard # TODO

proc encodeReceiptRlp*(/*Receipt*/): seq[byte] = @[]    # TODO
proc decodeReceiptRlp*(bytes: openArray[byte]) = discard# TODO

suite "TODO: RLP roundtrips / receipts / lists":

  # --- Header: RLP roundtrip EIP-1559 / EIP-4895 / EIP-4844 ---
  test "Header RLP roundtrip: EIP-1559 basefee present":
    # TODO: build header with baseFeePerGas; encode→decode and assert equality
    let bytes = encodeHeaderRlp()
    decodeHeaderRlp(bytes)
    check true

  test "Header RLP roundtrip: EIP-4895 withdrawals root":
    # TODO: header with withdrawalsRoot set
    let bytes = encodeHeaderRlp()
    decodeHeaderRlp(bytes)
    check true

  test "Header RLP roundtrip: EIP-4844 blob fields":
    # TODO: header with blobGasUsed / excessBlobGas (London+4844 set)
    let bytes = encodeHeaderRlp()
    decodeHeaderRlp(bytes)
    check true

  # --- EIP-2930 receipt ---
  test "EIP-2930 receipt RLP roundtrip":
    # TODO: make a receipt (status/postState, cumulativeGasUsed, logs, bloom)
    let bytes = encodeReceiptRlp()
    decodeReceiptRlp(bytes)
    check true

  # --- Tx with EIP-155 chainId (legacy replay-protected) ---
  test "Legacy EIP-155 signature V calculation":
    # TODO: sign legacy tx with chainId=1
    # Assert V == chainId*2 + 35 or +36 depending on parity
    check true

  # --- Tx with empty access list (CALL variant) ---
  test "2930 Call (empty access list)":
    # TODO: build 0x01 call with access_list = @[]; assert kind, len==0
    check true

  # --- Contract creation with access list (non-empty) ---
  test "2930 Create (non-empty access list)":
    # TODO: build 0x01 create with non-empty access_list; assert fields
    check true

  # --- Tx with Access List order swap ---
  test "2930 access list order swap behavior":
    # TODO: build two identical txs differing only by AL tuple order
    # Decide spec expectation: either different encoding OR canonical sort
    check true

  # --- NetworkBlob Tx (if distinct from 4844 Blob Tx) ---
  test "NetworkBlob Tx (placeholder)":
    # TODO: if your code defines a separate network-blob type, construct & check
    check true

  # --- Minimal Blob Tx ---
  when compiles(BlobFeesPerGas):
    test "4844 minimal blob tx (CALL)":
      # TODO: minimal 0x03 call: to=recipient, input=@[], access_list=@[],
      # one versioned hash, minimal fees
      check true

    test "4844 minimal blob tx (CONTRACT CREATE)":
      # TODO: minimal 0x03 create (only if supported by your impl)
      check true

    test "4844 blob tx recipient survives encode/decode":
      # TODO: encodeRlp(tx) -> decodeRlpTx -> assert tx2.to == recipient
      check true

  # --- EIP-7702 ---
  when declared(TransactionType7702) or compiles(Transaction): # keep it guard-y
    test "EIP-7702 tx basic construct + roundtrip":
      # TODO: construct type 0x04 per your schema; encode/decode and assert
      check true

  # --- Tx Lists / ordering ---
  test "Tx list order: 0,1,2,3,4,5,6,7,8":
    # TODO: build 9 txs, encode list, decode, assert order preserved
    check true

  test "Tx list order: 8,7,6,5,4,3,2,1,0":
    # TODO: same as above reversed
    check true

  test "Tx list order: 0,5,8,7,6,4,3,2,1":
    # TODO: same with custom permutation
    check true

  # --- EIP-155 signature (explicit parity test) ---
  test "EIP-155 parity and bounds (r,s) and yParity":
    # TODO: sign legacy tx; unpack signature; check 0<r<N, 0<s<=N/2; yParity in {0,1}
    check true

  # --- sign transaction (happy path) ---
  test "Sign transaction and verify sender recovery":
    # TODO: sign a tx; recover sender; assert it matches expected 'from'
    check true

# --- END: Stubs ---

