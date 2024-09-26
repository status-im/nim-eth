# eth
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ./[addresses_rlp, blocks, base_rlp, hashes_rlp], ../rlp

from stew/objects import checkedEnumAssign

export addresses_rlp, blocks, base_rlp, hashes_rlp, rlp

proc append*(rlpWriter: var RlpWriter, request: DepositRequest) =
  rlpWriter.appendRawBytes([DepositRequestType.byte])
  rlpWriter.startList(5)
  rlpWriter.append(request.pubkey)
  rlpWriter.append(request.withdrawalCredentials)
  rlpWriter.append(request.amount)
  rlpWriter.append(request.signature)
  rlpWriter.append(request.index)

proc read*(rlp: var Rlp, T: type DepositRequest): T {.raises: [RlpError].} =
  if not rlp.hasData:
    raise (ref MalformedRlpError)(
      msg: "DepositRequestType expected but source RLP is empty"
    )
  let reqType = rlp.readRawByte()
  if reqType != DepositRequestType:
    raise (ref UnsupportedRlpError)(msg: "Unexpected DepositRequestType: " & $reqType)

  var res: DepositRequest
  rlp.tryEnterList()
  rlp.read(res.pubkey)
  rlp.read(res.withdrawalCredentials)
  rlp.read(res.amount)
  rlp.read(res.signature)
  rlp.read(res.index)
  if rlp.hasData:
    raise (ref MalformedRlpError)(msg: "Extra data after DepositRequest")
  res

proc append*(rlpWriter: var RlpWriter, request: WithdrawalRequest) =
  rlpWriter.appendRawBytes([WithdrawalRequestType.byte])
  rlpWriter.startList(3)
  rlpWriter.append(request.sourceAddress)
  rlpWriter.append(request.validatorPubkey)
  rlpWriter.append(request.amount)

proc read*(rlp: var Rlp, T: type WithdrawalRequest): T {.raises: [RlpError].} =
  if not rlp.hasData:
    raise (ref MalformedRlpError)(
      msg: "WithdrawalRequestType expected but source RLP is empty"
    )
  let reqType = rlp.readRawByte()
  if reqType != WithdrawalRequestType:
    raise
      (ref UnsupportedRlpError)(msg: "Unexpected WithdrawalRequestType: " & $reqType)

  var res: WithdrawalRequest
  rlp.tryEnterList()
  rlp.read(res.sourceAddress)
  rlp.read(res.validatorPubkey)
  rlp.read(res.amount)
  if rlp.hasData:
    raise (ref MalformedRlpError)(msg: "Extra data after WithdrawalRequest")
  res

proc append*(rlpWriter: var RlpWriter, request: ConsolidationRequest) =
  rlpWriter.appendRawBytes([ConsolidationRequestType.byte])
  rlpWriter.startList(3)
  rlpWriter.append(request.sourceAddress)
  rlpWriter.append(request.sourcePubkey)
  rlpWriter.append(request.targetPubkey)

proc read*(rlp: var Rlp, T: type ConsolidationRequest): T {.raises: [RlpError].} =
  if not rlp.hasData:
    raise (ref MalformedRlpError)(
      msg: "ConsolidationRequestType expected but source RLP is empty"
    )
  let reqType = rlp.readRawByte()
  if reqType != ConsolidationRequestType:
    raise
      (ref UnsupportedRlpError)(msg: "Unexpected ConsolidationRequestType: " & $reqType)

  var res: ConsolidationRequest
  rlp.tryEnterList()
  rlp.read(res.sourceAddress)
  rlp.read(res.sourcePubkey)
  rlp.read(res.targetPubkey)
  if rlp.hasData:
    raise (ref MalformedRlpError)(msg: "Extra data after ConsolidationRequest")
  res

proc append*(rlpWriter: var RlpWriter, request: Request) =
  case request.requestType
  of DepositRequestType:
    rlpWriter.append(request.deposit)
  of WithdrawalRequestType:
    rlpWriter.append(request.withdrawal)
  of ConsolidationRequestType:
    rlpWriter.append(request.consolidation)

proc append*(rlpWriter: var RlpWriter, reqs: seq[Request] | openArray[Request]) =
  rlpWriter.startList(reqs.len)
  for req in reqs:
    rlpWriter.append(rlp.encode(req))

proc read*(rlp: var Rlp, T: type Request): T {.raises: [RlpError].} =
  if not rlp.hasData:
    raise newException(MalformedRlpError, "Request expected but source RLP is empty")
  if not rlp.isSingleByte:
    raise newException(
      MalformedRlpError, "RequestType byte is out of range, must be 0x00 to 0x7f"
    )

  let reqType = rlp.getByteValue
  rlp.position += 1

  var reqVal: RequestType
  if checkedEnumAssign(reqVal, reqType):
    result = Request(requestType: reqVal)
    rlp.tryEnterList()
    case reqVal
    of DepositRequestType:
      rlp.read(result.deposit.pubkey)
      rlp.read(result.deposit.withdrawalCredentials)
      rlp.read(result.deposit.amount)
      rlp.read(result.deposit.signature)
      rlp.read(result.deposit.index)
    of WithdrawalRequestType:
      rlp.read(result.withdrawal.sourceAddress)
      rlp.read(result.withdrawal.validatorPubkey)
      rlp.read(result.withdrawal.amount)
    of ConsolidationRequestType:
      rlp.read(result.consolidation.sourceAddress)
      rlp.read(result.consolidation.sourcePubkey)
      rlp.read(result.consolidation.targetPubkey)
  else:
    raise (ref UnsupportedRlpError)(msg: "Unexpected RequestType: " & $reqType)

proc read*(
    rlp: var Rlp, T: (type seq[Request]) | (type openArray[Request])
): seq[Request] {.raises: [RlpError].} =
  if not rlp.isList:
    raise newException(
      RlpTypeMismatch, "Requests list expected, but source RLP is not a list"
    )

  var reqs: seq[Request]
  for item in rlp:
    var rr = rlpFromBytes(rlp.read(seq[byte]))
    reqs.add rr.read(Request)

  reqs
