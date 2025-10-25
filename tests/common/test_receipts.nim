# Nimbus
# Copyright (c) 2023-2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.
{.used.}

import
  unittest2,
  ../../eth/common/[receipts_rlp]

template roundTrip(v: untyped) =
  let bytes = rlp.encode(v)
  let v2 = rlp.decode(bytes, v.type)
  let bytes2 = rlp.encode(v2)
  check bytes == bytes2

suite "Receipts":
  test "EIP-4844":
    let rec = Receipt(
      receiptType: Eip4844Receipt,
      isHash: false,
      status: false,
      cumulativeGasUsed: 100.GasInt)

    roundTrip(rec)

  test "EIP-7702":
    let rec = Receipt(
      receiptType: Eip7702Receipt,
      isHash: false,
      status: false,
      cumulativeGasUsed: 100.GasInt)

    roundTrip(rec)

suite "Stored Receipt":
  test "EIP-4844":
    let rec = StoredReceipt(
      receiptType: Eip4844Receipt,
      isHash: false,
      status: false,
      cumulativeGasUsed: 100.GasInt)

    roundTrip(rec)

  test "EIP-7702":
    let rec = StoredReceipt(
      receiptType: Eip7702Receipt,
      isHash: false,
      status: false,
      cumulativeGasUsed: 100.GasInt)

    roundTrip(rec)

  test "EIP-7807 StoredReceipt: Basic":
    let rec = StoredReceipt(
      receiptType: Eip7807Receipt,
      isHash: false,
      status: true,
      cumulativeGasUsed: 777.GasInt,
      eip7807ReceiptType: Eip7807Basic,
      origin: default(Address),
      txGasUsed: 555'u64
    )
    roundTrip(rec)

  test "EIP-7807 StoredReceipt: Create":
    let rec = StoredReceipt(
      receiptType: Eip7807Receipt,
      isHash: false,
      status: true,
      cumulativeGasUsed: 888.GasInt,
      logs: @[],
      eip7807ReceiptType: Eip7807Create,
      origin: default(Address),
      txGasUsed: 666'u64,
      contactAddress: default(Address)
    )
    roundTrip(rec)

  test "EIP-7807 StoredReceipt: SetCode":
    let rec = StoredReceipt(
      receiptType: Eip7807Receipt,
      isHash: false,
      status: true,
      cumulativeGasUsed: 999.GasInt,
      logs: @[],
      eip7807ReceiptType: Eip7807SetCode,
      origin: default(Address),
      txGasUsed: 333'u64,
      authorities: @[default(Address)]
    )
    roundTrip(rec)

  test "StoredReceipt seq roundtrip (mixed types)":
    let a = StoredReceipt(
      receiptType: Eip7702Receipt,
      isHash: false,
      status: false,
      cumulativeGasUsed: 1.GasInt,
      logs: @[]
    )
    let b = StoredReceipt(
      receiptType: Eip7807Receipt,
      isHash: false,
      status: true,
      cumulativeGasUsed: 2.GasInt,
      logs: @[],
      eip7807ReceiptType: Eip7807Basic,
      origin: default(Address),
      txGasUsed: 42'u64
    )
    let arr = @[a, b]
    roundTrip(arr)
