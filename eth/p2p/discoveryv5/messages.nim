# nim-eth - Node Discovery Protocol v5
# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#
## Discovery v5 Protocol Messages as specified at
## https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md#protocol-messages
##

{.push raises: [Defect].}

import
  std/[hashes, net],
  ./enr

type
  MessageKind* = enum
    # Note:
    # This is needed only to keep the compiler happy. Without it, the
    # `MessageKind` type cannot be used as a discriminator in case objects.
    # If a message with this value is received however, it will fail at the
    # decoding step.
    unused = 0x00

    # The supported message types
    ping = 0x01
    pong = 0x02
    findNode = 0x03
    nodes = 0x04
    talkReq = 0x05
    talkResp = 0x06
    regTopic = 0x07
    ticket = 0x08
    regConfirmation = 0x09
    topicQuery = 0x0A

  RequestId* = object
    id*: seq[byte]

  PingMessage* = object
    enrSeq*: uint64

  PongMessage* = object
    enrSeq*: uint64
    ip*: IpAddress
    port*: uint16

  FindNodeMessage* = object
    distances*: seq[uint16]

  NodesMessage* = object
    total*: uint32
    enrs*: seq[Record]

  TalkReqMessage* = object
    protocol*: seq[byte]
    request*: seq[byte]

  TalkRespMessage* = object
    response*: seq[byte]

  # Not implemented, specification is not final here.
  RegTopicMessage* = object
  TicketMessage* = object
  RegConfirmationMessage* = object
  TopicQueryMessage* = object

  SomeMessage* = PingMessage or PongMessage or FindNodeMessage or NodesMessage or
    TalkReqMessage or TalkRespMessage

  Message* = object
    reqId*: RequestId
    case kind*: MessageKind
    of ping:
      ping*: PingMessage
    of pong:
      pong*: PongMessage
    of findNode:
      findNode*: FindNodeMessage
    of nodes:
      nodes*: NodesMessage
    of talkReq:
      talkReq*: TalkReqMessage
    of talkResp:
      talkResp*: TalkRespMessage
    of regTopic:
      regtopic*: RegTopicMessage
    of ticket:
      ticket*: TicketMessage
    of regConfirmation:
      regConfirmation*: RegConfirmationMessage
    of topicQuery:
      topicQuery*: TopicQueryMessage
    else:
      discard

template messageKind*(T: typedesc[SomeMessage]): MessageKind =
  when T is PingMessage: ping
  elif T is PongMessage: pong
  elif T is FindNodeMessage: findNode
  elif T is NodesMessage: nodes
  elif T is TalkReqMessage: talkReq
  elif T is TalkRespMessage: talkResp

func init*(T: type RequestId, rng: var HmacDrbgContext): T =
  var reqId = RequestId(id: newSeq[byte](8)) # RequestId must be <= 8 bytes
  rng.generate(reqId.id)
  reqId

func hash*(reqId: RequestId): Hash =
  hash(reqId.id)
