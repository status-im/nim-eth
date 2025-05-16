# eth
# Copyright (c) 2024-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import 
  ./[addresses, base, hashes, transactions],
  ../bloom

export addresses, base, hash, transactions

type
  Topic* = Bytes32
  # topic can be Hash32 or zero padded bytes array

  Log* = object
    address*:       Address
    topics*:        seq[Topic]
    data*:          seq[byte]

  # easily convertible between
  # ReceiptType and TxType
  ReceiptType* = TxType
    # LegacyReceipt  = TxLegacy
    # Eip2930Receipt = TxEip2930
    # Eip1559Receipt = TxEip1559
    # Eip4844Receipt = TxEip4844
    # Eip7702Receipt = TxEip7702
    # Eip7873Receipt = TxEip7873

  Receipt* = object
    receiptType*      : ReceiptType
    isHash*           : bool          # hash or status
    status*           : bool          # EIP-658
    hash*             : Hash32
    cumulativeGasUsed*: GasInt
    logsBloom*        : Bloom
    logs*             : seq[Log]

  StoredReceipt* = object
    receiptType*      : ReceiptType
    isHash*           : bool
    status*           : bool
    hash*             : Hash32
    cumulativeGasUsed*: GasInt
    logs*             : seq[Log]

const
  LegacyReceipt*  = TxLegacy
  Eip2930Receipt* = TxEip2930
  Eip1559Receipt* = TxEip1559
  Eip4844Receipt* = TxEip4844
  Eip7702Receipt* = TxEip7702
  Eip7873Receipt* = TxEip7873

func hasStatus*(rec: Receipt): bool {.inline.} =
  rec.isHash == false

func hasStateRoot*(rec: Receipt): bool {.inline.} =
  rec.isHash == true

func stateRoot*(rec: Receipt): Hash32 {.inline.} =
  doAssert(rec.hasStateRoot)
  rec.hash

func logsBloom(logs: openArray[Log]): BloomFilter =
  var res: BloomFilter
  for log in logs:
    res.incl log.address
    for topic in log.topics:
      res.incl topic

  res

func to*(rec: Receipt, _: type StoredReceipt): StoredReceipt =
  StoredReceipt(
    receiptType       : rec.receiptType,
    isHash            : rec.isHash,
    status            : rec.status,
    hash              : rec.hash,
    cumulativeGasUsed : rec.cumulativeGasUsed,
    logs              : rec.logs
  )

func to*(rec: StoredReceipt, _: type Receipt): Receipt =
  Receipt(
    receiptType       : rec.receiptType,
    isHash            : rec.isHash,
    status            : rec.status,
    hash              : rec.hash,
    cumulativeGasUsed : rec.cumulativeGasUsed,
    logsBloom         : logsBloom(rec.logs).value.to(Bloom),
    logs              : rec.logs
  )

func to*(list: openArray[Receipt], _: type seq[StoredReceipt]): seq[StoredReceipt] =
  var res: seq[StoredReceipt]
  for x in list:
    res.add x.to(StoredReceipt)
  res

func to*(list: openArray[StoredReceipt], _: type seq[Receipt]): seq[Receipt] =
  var res: seq[Receipt]
  for x in list:
    res.add x.to(Receipt)
  res
