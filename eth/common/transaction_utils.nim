# eth
# Copyright (c) 2024-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/typetraits,
  stint,
  ./[keys, transactions, transactions_rlp]

export keys, transactions

proc signature*(tx: Transaction): Opt[Signature] =
  var bytes {.noinit.}: array[65, byte]
  bytes[0 .. 31] = tx.R.toBytesBE()
  bytes[32 .. 63] = tx.S.toBytesBE()

  bytes[64] =
    if tx.txType != TxLegacy:
      tx.V.byte
    elif tx.V >= EIP155_CHAIN_ID_OFFSET:
      byte(1 - (tx.V and 1))
    elif tx.V == 27 or tx.V == 28:
      byte(tx.V - 27)
    else:
      return Opt.none(Signature)

  Signature.fromRaw(bytes).mapConvertErr(void)

proc `signature=`*(tx: var Transaction, param: tuple[sig: Signature, eip155: bool]) =
  let raw = param.sig.toRaw()

  tx.R = UInt256.fromBytesBE(raw.toOpenArray(0, 31))
  tx.S = UInt256.fromBytesBE(raw.toOpenArray(32, 63))

  let v = raw[64].uint64
  tx.V =
    case tx.txType
    of TxLegacy:
      if param.eip155:
        # using distinctBase with trncate will cause type mismatch
        # as of Nim 2.0.14
        let chainId = UInt256(tx.chainId).truncate(uint64)
        v + chainId * 2'u64 + 35'u64
      else:
        v + 27'u64
    else:
      v

proc sign*(tx: Transaction, pk: PrivateKey, eip155: bool): (Signature, bool) =
  let hash = tx.rlpHashForSigning(eip155)

  (sign(pk, SkMessage(hash.data)), eip155)

proc recoverKey*(tx: Transaction): Opt[PublicKey] =
  ## Recovering key / sender is a costly operation - make sure to reuse the
  ## outcome!
  ##
  ## Returns `none` if the signature is invalid with respect to the rest of
  ## the transaction data.
  let
    sig = ?tx.signature()
    txHash = tx.rlpHashForSigning(tx.isEip155())

  recover(sig, SkMessage(txHash.data)).mapConvertErr(void)

proc recoverSender*(tx: Transaction): Opt[Address] =
  ## Recovering key / sender is a costly operation - make sure to reuse the
  ## outcome!
  ##
  ## Returns `none` if the signature is invalid with respect to the rest of
  ## the transaction data.
  let key = ?tx.recoverKey()
  ok key.to(Address)

proc creationAddress*(tx: Transaction, sender: Address): Address =
  let hash = keccak256(rlp.encodeList(sender, tx.nonce))
  hash.to(Address)

proc getRecipient*(tx: Transaction, sender: Address): Address =
  tx.to.valueOr(tx.creationAddress(sender))
