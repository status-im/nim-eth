{.push raises: [].}

import
  std/[os, strutils],
  ../../../eth/common/eth_types_rlp,
  ../fuzzing_helpers

template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
const inputsDir = sourceDir / "corpus"

proc generate() {.raises: [CatchableError].} =
  const
    recipient = address"095e7baea6a6c7c4c2dfeb977efac326af552d87"
    source = address"0000000000000000000000000000000000000001"
    accesses = @[AccessPair(address: source, storageKeys: @[default(Bytes32)])]
    authList = @[Authorization(
      chainId: chainId(1), address: source, nonce: 2, yParity: 1,
      r: 4.u256, s: 5.u256)]
    versionedHash =
      hash32"01624652859a6e98ffc1608e2af0147ca4e86e1ce27672d8d3f3c9d4ffd6ef7e"

  let
    txs = @[
      Transaction(
        txType: TxLegacy, nonce: 1, gasPrice: 2, gasLimit: 21000,
        to: Opt.some(recipient), value: 3.u256, payload: @[byte 1, 2, 3],
        V: 37, R: 4.u256, S: 5.u256),
      Transaction(
        txType: TxLegacy, nonce: 1, gasPrice: 2, gasLimit: 53000,
        payload: @[byte 0x60, 0x00], V: 27, R: 4.u256, S: 5.u256),
      Transaction(
        txType: TxEip2930, chainId: chainId(1), nonce: 1, gasPrice: 2,
        gasLimit: 21000, to: Opt.some(recipient), accessList: accesses,
        V: 1, R: 4.u256, S: 5.u256),
      Transaction(
        txType: TxEip1559, chainId: chainId(1), nonce: 1,
        maxPriorityFeePerGas: 2, maxFeePerGas: 3, gasLimit: 21000,
        to: Opt.some(recipient), accessList: accesses,
        V: 1, R: 4.u256, S: 5.u256),
      Transaction(
        txType: TxEip4844, chainId: chainId(1), nonce: 1,
        maxPriorityFeePerGas: 2, maxFeePerGas: 3, gasLimit: 21000,
        to: Opt.some(recipient), accessList: accesses,
        maxFeePerBlobGas: 4.u256, versionedHashes: @[versionedHash],
        V: 1, R: 4.u256, S: 5.u256),
      Transaction(
        txType: TxEip7702, chainId: chainId(1), nonce: 1,
        maxPriorityFeePerGas: 2, maxFeePerGas: 3, gasLimit: 21000,
        to: Opt.some(recipient), accessList: accesses,
        authorizationList: authList, V: 1, R: 4.u256, S: 5.u256)]
    logs = @[Log(address: source, topics: @[default(Bytes32)], data: @[byte 1])]
    receipts = @[
      Receipt(receiptType: LegacyReceipt, status: true, cumulativeGasUsed: 21000, logs: logs),
      Receipt(receiptType: Eip4844Receipt, isHash: true, cumulativeGasUsed: 21000)]
    storedReceipts = @[
      StoredReceipt(receiptType: Eip1559Receipt, status: true, cumulativeGasUsed: 21000, logs: logs)]
    header = Header(
      number: 1, gasLimit: 30_000_000, extraData: @[byte 1],
      baseFeePerGas: Opt.some(7.u256), withdrawalsRoot: Opt.some(default(Hash32)),
      blobGasUsed: Opt.some(0'u64), excessBlobGas: Opt.some(0'u64),
      parentBeaconBlockRoot: Opt.some(default(Hash32)),
      requestsHash: Opt.some(default(Hash32)))
    withdrawals = @[Withdrawal(index: 1, validatorIndex: 2, address: source, amount: 3)]
    bal: BlockAccessList = @[AccountChanges(
      address: source,
      storageChanges: @[(1.u256, @[(1.BlockAccessIndex, 2.u256)])],
      storageReads: @[3.u256],
      balanceChanges: @[(1.BlockAccessIndex, 4.u256)],
      nonceChanges: @[(1.BlockAccessIndex, 5'u64)],
      codeChanges: @[(1.BlockAccessIndex, @[byte 0x60, 0x00])])]

  for i, tx in txs:
    rlp.encode(tx).toFile(inputsDir / "tx" & $i)
  rlp.encode(txs).toFile(inputsDir / "txs")
  rlp.encode(accesses).toFile(inputsDir / "access_list")
  rlp.encode(authList).toFile(inputsDir / "authorization_list")
  rlp.encode(receipts).toFile(inputsDir / "receipts")
  rlp.encode(storedReceipts).toFile(inputsDir / "stored_receipts")
  rlp.encode(header).toFile(inputsDir / "header")
  rlp.encode(Block(
    header: header, transactions: txs, withdrawals: Opt.some(withdrawals)
  )).toFile(inputsDir / "block")
  rlp.encode(bal).toFile(inputsDir / "block_access_list")
  rlp.encode(("abc", 7'u32)).toFile(inputsDir / "tuple")

discard existsOrCreateDir(inputsDir)
generate()
