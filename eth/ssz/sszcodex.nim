import std/[strutils, sequtils, options]
import stint
import ssz_serialization
import ".."/common/[addresses, base, hashes]
import "."/[transaction_ssz, signatures]
# - rlpFromBytes/read() from your RLP lib
# - Rlp* transaction record types from your RLP transaction module

template u256*(x: int | uint64): UInt256 = UInt256.fromInt(x.int)
template isZero*(x: UInt256): bool = (x == UInt256.zero)

proc hasSignature*(t: Transaction): bool =
  (not t.R.isZero) or (not t.S.isZero)

proc isCreate*(t: Transaction): bool =
  when compiles(t.to.isNone):
    t.to.isNone
  else:
    false

# EIP-155 helpers:
proc deriveChainIdFromV*(v: uint64): Option[uint64] =
  ## EIP-155 legacy only: v = 35 | 36 | 2*chainId + 35 | 2*chainId + 36
  if v >= 35'u64:
    let cid = (v - 35'u64) div 2'u64
    if (2'u64 * cid + 35'u64 == v) or (2'u64 * cid + 36'u64 == v):
      return some(cid)
  none(uint64)

proc yParityFromV*(v: uint64): Option[uint64] =
  ## 0 or 1 (EIP-155 legacy and EIP-2718 typed)
  if v == 27'u64: return some(0'u64)
  if v == 28'u64: return some(1'u64)
  if v >= 35'u64: return some((v + 1'u64) mod 2'u64)  # 35->0, 36->1, 37->0, etc
  if v <= 1'u64:  return some(v)
  none(uint64)

proc eip155V*(chainId: uint64; yParity: uint64): uint64 =
  2'u64 * chainId + 35'u64 + yParity

# ---- JSON -> Transaction -----------------------------------------------------
# Intentionally hand-rolled mapping points (so you can wire your own JSON lib).
# The idea: map every tx entry in your JSON "transactions" array into Transaction.

type JsonAccessTuple = object
  address: string
  storageKeys: seq[string]

type JsonTx = object
  `type`: string             # "0x0", "0x1", "0x2", "0x3", "0x4"
  chainId: string            # may be "null" in the source; pass empty when null
  nonce: string
  gasPrice: string
  gas: string
  to: string                 # empty => create
  value: string
  input: string
  accessList: seq[JsonAccessTuple]
  v: string
  r: string
  s: string
  # 4844
  maxFeePerBlobGas: string
  blobVersionedHashes: seq[string]
  # 1559
  maxPriorityFeePerGas: string
  maxFeePerGas: string
  # 7702
  authorizationList: seq[string]  # adapt to your actual JSON shape

type JsonBlock = object
  # header fields present but not needed here; we only care about txs
  transactions: seq[JsonTx]

proc parseHexU64(s: string): uint64 =
  if s.len == 0: return 0
  let t = s.strip()
  if t.startsWith("0x") or t.startsWith("0X"):
    return parseHexUInt(t[2..^1])
  parseUInt(t)

proc parseHexU256(s: string): UInt256 =
  if s.len == 0: return UInt256.zero
  let t = s.strip()
  if t == "null": return UInt256.zero
  if t.startsWith("0x") or t.startsWith("0X"):
    return UInt256.fromHex(t)
  # decimal fallback
  UInt256.fromDecimal(t)

proc parseBytesHex(s: string): seq[byte] =
  if s.len == 0: return @[]
  let t = s.strip()
  if t.startsWith("0x") or t.startsWith("0X"):
    return hexToSeqByte(t[2..^1])  # define hexToSeqByte in utils if not present
  @[]

proc parseMaybeAddress(s: string): Opt[Address] =
  when compiles(Address):
    if s.len == 0:
      return none(Address)
    let t = s.strip()
    if t == "0x" or t == "0x0" or t == "":
      return none(Address)
    # expect 20-byte hex
    let bs = parseBytesHex(t)
    if bs.len == 20:
      var a: Address
      # assuming Address = distinct Bytes20 with .data or cast; adapt if needed
      when compiles(a.data):
        for i in 0..<20: a.data[i] = bs[i]
      else:
        a = Address(bs) # if your Address distinct/alias supports this
      return some(a)
    none(Address)
  else:
    none(typeof(Address))

proc jsonTxToUnified*(jt: JsonTx): Transaction =
  var tx: Transaction
  # txType
  let tStr = jt.`type`.strip()
  tx.txType =
    if tStr.len == 0: 0x00'u8
    else: cast[uint8](parseHexU64(tStr))
  # chainId (legacy can be null; we still fill 0 unless you want to backfill from v)
  if jt.chainId.len > 0 and jt.chainId != "null":
    tx.chainId = ChainId(u256(parseHexU64(jt.chainId)))  # ChainId is UInt256 usually
  else:
    tx.chainId = ChainId(UInt256.zero)

  tx.nonce    = parseHexU64(jt.nonce)
  tx.gasPrice = u256(parseHexU64(jt.gasPrice))
  tx.gasLimit = u256(parseHexU64(jt.gas))

  tx.to       = parseMaybeAddress(jt.to)
  tx.value    = parseHexU256(jt.value)
  tx.payload  = parseBytesHex(jt.input)

  # EIP-2930 access list (wire when needed)
  tx.accessList = @[] # TODO: map jt.accessList -> AccessList

  # EIP-1559
  tx.maxPriorityFeePerGas = u256(parseHexU64(jt.maxPriorityFeePerGas))
  tx.maxFeePerGas         = u256(parseHexU64(jt.maxFeePerGas))

  # EIP-4844
  tx.maxFeePerBlobGas = parseHexU256(jt.maxFeePerBlobGas)
  tx.versionedHashes  = @[] # TODO: map jt.blobVersionedHashes -> seq[VersionedHash]

  # EIP-7702
  tx.authorizationList = @[] # TODO: map jt.authorizationList -> seq[Authorization]

  # Signature
  tx.V = parseHexU64(jt.v)
  tx.R = parseHexU256(jt.r)
  tx.S = parseHexU256(jt.s)

  # If legacy with chainId==0 but V>=35, you can backfill chainId from V:
  if tx.txType == 0x00'u8 and tx.chainId.uint == 0:
    let cid = deriveChainIdFromV(tx.V)
    if cid.isSome: tx.chainId = ChainId(u256(cid.get))

  tx

proc decodeJsonBlockTransactions*(jsonStr: string): seq[Transaction] =
  ## Parse the JSON test vector block -> tx list in unified form
  # Use your preferred JSON lib; here we do minimal parsing:
  # Replace this with json_serialization/JsonNode if already used in your codebase.
  # --- BEGIN: replace with your own JSON parser ---
  {.warning: "Wire decodeJsonBlockTransactions() to your JSON parser.".}
  result = @[]
  discard jsonStr         # placeholder: put your actual parsing here
  # For now, leave as-is; you already showed the JSON shape above.
  # --- END: replace with your own JSON parser ---
  # TIP: loop over block.transactions, call jsonTxToUnified() per item.
