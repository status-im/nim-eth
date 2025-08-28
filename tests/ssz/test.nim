# RLP -> SSZ recast tests
import unittest2,
../../eth/common/[transactions_rlp, transaction_utils],  
../../eth/ssz/[transaction_ssz, codec],
# We reuse the txns definitions as per the already written tests
../test_transaction_ssz,
stint

suite "RLP -> SSZ recast: Transactions":

  testRlpToSszTx("Legacy CALL (replayable -> RlpLegacyReplayableBasic)",
                 RlpLegacyReplayableBasicTransaction, tx0(1)):
    check obj.payload.gas == 1'u64
    check obj.payload.to == recipient

  testRlpToSszTx("Legacy CREATE (replayable -> RlpLegacyReplayableCreate)",
                 RlpLegacyReplayableCreateTransaction, tx1(2)):
    discard

  # --- 2930 CALL with non-empty access list ---
  # tx2: TxEip2930 + to + non-empty AL => AccessList BASIC
  testRlpToSszTx("2930 CALL (non-empty AL -> RlpAccessListBasic)",
                 RlpAccessListBasicTransaction, tx2(3)):
    check obj.payload.access_list.len == 1
    check obj.payload.input == hexToSeqByte("abcdef")

  # --- 2930 CALL with empty access list ---
  # tx3: TxEip2930 + to + empty AL => AccessList BASIC
  testRlpToSszTx("2930 CALL (empty AL -> RlpAccessListBasic)",
                 RlpAccessListBasicTransaction, tx3(4)):
    check obj.payload.access_list.len == 0

  # --- 2930 CREATE with access list ---
  # tx4: TxEip2930 + create + non-empty AL => AccessList CREATE
  testRlpToSszTx("2930 CREATE (non-empty AL -> RlpAccessListCreate)",
                 RlpAccessListCreateTransaction, tx4(5)):
    check obj.payload.access_list.len == 1

  # --- 1559 dynamic fee (CALL/CREATE depends on 'to') ---
  # tx5 doesn't set `to` in your builder -> CREATE arm
  testRlpToSszTx("1559 CREATE (-> RlpCreateTransaction)",
                 RlpCreateTransaction, tx5(6)):
    check obj.payload.gas == 123_457'u64
    check obj.payload.max_priority_fees_per_gas.regular == 42.u256
    check obj.payload.max_fees_per_gas.regular == 10.u256

  # --- 4844 blob tx (NetworkBlob/Minimal Blob) ---
  # tx6/tx7: 4844 without recipient (creation semantics in RLP)
  testRlpToSszTx("4844 blob tx (no recipient -> RlpBlobTransaction)",
                 RlpBlobTransaction, tx6(7)):
    check obj.payload.blob_versioned_hashes.len == 1

  testRlpToSszTx("4844 minimal blob tx (no recipient -> RlpBlobTransaction)",
                 RlpBlobTransaction, tx7(8)):
    check obj.payload.blob_versioned_hashes.len == 1

  # tx8: 4844 with recipient; assert 'to' survives the recast
  testRlpToSszTx("4844 blob tx recipient survives RLP->SSZ recast",
                 RlpBlobTransaction, tx8(9)):
    check obj.payload.to == recipient

  # --- 7702 SetCode ---
  testRlpToSszTx("7702 SetCode minimal (-> RlpSetCodeTransaction)",
                 RlpSetCodeTransaction, txEip7702(10)):
    check obj.payload.access_list.len == 1

  # --- Signature mapping TODOs ---
  test "RLP->SSZ signature mapping TODO":
    checkpoint "TODO: map (yParity, r, s) into Secp256k1ExecutionSignature, and add signing/recovery checks"
    check true
