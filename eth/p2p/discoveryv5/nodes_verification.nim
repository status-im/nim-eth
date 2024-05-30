# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

{.push raises: [].}

import
  std/[sets, options, net],
  results, chronicles, chronos,
  ../../net/utils,
  "."/[node, enr, routing_table]

logScope:
  topics = "nodes-verification"

func validIp(sender, address: IpAddress): bool =
  let a = initTAddress(address, Port(0))
  if a.isGlobalUnicast():
    true
  else:
    let s = initTAddress(sender, Port(0))
    if a.isLoopback() and s.isLoopback():
      true
    elif a.isSiteLocal() and s.isSiteLocal():
      true
    else:
      false

proc verifyNodesRecords(
    enrs: openArray[Record], src: Node, nodesLimit: int,
    distances: Option[seq[uint16]]): seq[Node] =
  ## Verify and convert ENRs to a sequence of nodes. Only ENRs that pass
  ## verification will be added. ENRs are verified for duplicates, invalid
  ## addresses and invalid distances if those are specified.
  logScope:
    sender = src.record.toURI

  var seen: HashSet[Node]
  var count = 0
  for r in enrs:
    # Check and allow for processing of maximum `findNodeResultLimit` ENRs
    # returned. This limitation is required so no huge lists of invalid ENRs
    # are processed for no reason, and for not overwhelming a routing table
    # with nodes from a malicious actor.
    # The discovery v5 specification specifies no limit on the amount of ENRs
    # that can be returned, but clients usually stick with the bucket size limit
    # as in original Kademlia. Because of this it is chosen not to fail
    # immediately, but still process maximum `findNodeResultLimit`.
    if count >= nodesLimit:
      debug "Too many ENRs", enrs = enrs.len(), limit = nodesLimit
      break

    count.inc()

    let node = newNode(r)
    if node.isOk():
      let n = node.get()
      # Check for duplicates in the nodes reply. Duplicates are checked based
      # on node id.
      if n in seen:
        trace "Duplicate node ids", record = n.record.toURI, id = n.id
        continue
      # Check if the node has an address and if the address is public or from
      # the same local network or lo network as the sender. The latter allows
      # for local testing.
      if not n.address.isSome() or not
          validIp(src.address.get().ip, n.address.get().ip):
        trace "Invalid ip-address", record = n.record.toURI, node = n
        continue
      # Check if returned node has one of the requested distances.
      if distances.isSome():
        # TODO: This is incorrect for custom distances
        if (not distances.get().contains(logDistance(n.id, src.id))):
          debug "Incorrect distance", record = n.record.toURI
          continue

      # No check on UDP port and thus any port is allowed, also the so called
      # "well-known" ports.

      seen.incl(n)
      result.add(n)

proc verifyNodesRecords*(
    enrs: openArray[Record], src: Node, nodesLimit: int): seq[Node] =
  verifyNodesRecords(enrs, src, nodesLimit, none[seq[uint16]]())

proc verifyNodesRecords*(
    enrs: openArray[Record], src: Node, nodesLimit: int,
    distances: seq[uint16]): seq[Node] =
  verifyNodesRecords(enrs, src, nodesLimit, some[seq[uint16]](distances))
