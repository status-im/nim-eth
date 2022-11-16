# nim-eth - Node Discovery Protocol v5
# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#
## IP:port address votes implemented similarly as in
## https://github.com/sigp/discv5
##
## This allows the selection of a node its own public IP based on address
## information that is received from other nodes.
## This can be used in conjunction with discovery v5 ping-pong request responses
## that provide this information.
## To select the right address, a majority count is done. This is done over a
## sort of moving window as votes expire after `IpVoteTimeout`.

{.push raises: [Defect].}

import
  std/[tables, options],
  chronos,
  ./node

export options

const IpVoteTimeout = 5.minutes ## Duration until a vote expires

type
  IpVote* = object
    votes: Table[NodeId, tuple[address: Address, expiry: chronos.Moment]]
    threshold: uint ## Minimum threshold to allow for a majority to count

func init*(T: type IpVote, threshold: uint = 10): T =
  ## Initialize IpVote.
  ##
  ## If provided threshold is lower than 2 it will be set to 2.
  if threshold < 2:
    IpVote(threshold: 2)
  else:
    IpVote(threshold: threshold)

proc insert*(ipvote: var IpVote, key: NodeId, address: Address) =
  ## Insert a vote for an address coming from a specific `NodeId`. A `NodeId`
  ## can only hold 1 vote.
  ipvote.votes[key] = (address, now(chronos.Moment) + IpVoteTimeout)

proc majority*(ipvote: var IpVote): Option[Address] =
  ## Get the majority of votes on an address. Pruning of votes older than
  ## `IpVoteTime` will be done before the majority count.
  ## Note: When there is a draw the selected "majority" will depend on whichever
  ## address comes first in the CountTable. This seems acceptable as there is no
  ## other criteria to make a selection.
  let now = now(chronos.Moment)

  var
    pruneList: seq[NodeId]
    ipCount: CountTable[Address]
  for k, v in ipvote.votes:
    if now > v.expiry:
      pruneList.add(k)
    else:
      ipCount.inc(v.address)

  for id in pruneList:
    ipvote.votes.del(id)

  if ipCount.len <= 0:
    return none(Address)

  let (address, count) = ipCount.largest()

  if uint(count) >= ipvote.threshold:
    some(address)
  else:
    none(Address)
