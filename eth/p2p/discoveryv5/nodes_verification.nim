{.push raises: [Defect].}

import
  std/[sets, options],
  stew/results, stew/shims/net, chronicles, chronos,
  "."/[node, enr, routing_table]

logScope:
  topics = "nodes-verification"

proc validIp(sender, address: IpAddress): bool =
  let
    s = initTAddress(sender, Port(0))
    a = initTAddress(address, Port(0))
  if a.isAnyLocal():
    return false
  if a.isMulticast():
    return false
  if a.isLoopback() and not s.isLoopback():
    return false
  if a.isSiteLocal() and not s.isSiteLocal():
    return false
  # TODO: Also check for special reserved ip addresses:
  # https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
  # https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
  return true

proc verifyNodesRecords(enrs: openArray[Record], fromNode: Node, nodesLimit: int,
    distances: Option[seq[uint16]]): seq[Node] =
  ## Verify and convert ENRs to a sequence of nodes. Only ENRs that pass
  ## verification will be added. ENRs are verified for duplicates, invalid
  ## addresses and invalid distances if those are specified.
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
    # immediatly, but still process maximum `findNodeResultLimit`.
    if count >= nodesLimit:
      debug "Too many ENRs", enrs = enrs.len(),
        limit = nodesLimit, sender = fromNode.record.toURI
      break

    count.inc()

    let node = newNode(r)
    if node.isOk():
      let n = node.get()
      # Check for duplicates in the nodes reply. Duplicates are checked based
      # on node id.
      if n in seen:
        trace "Duplicate node ids",
          record = n.record.toURI, id = n.id, sender = fromNode.record.toURI
        continue
      # Check if the node has an address and if the address is public or from
      # the same local network or lo network as the sender. The latter allows
      # for local testing.
      if not n.address.isSome() or not
          validIp(fromNode.address.get().ip, n.address.get().ip):
        trace "Invalid ip-address",
          record = n.record.toURI, node = n, sender = fromNode.record.toURI
        continue
      # Check if returned node has one of the requested distances.
      if distances.isSome():
        # TODO: This is incorrect for custom distances
        if (not distances.get().contains(logDistance(n.id, fromNode.id))):
          debug "Incorrect distance",
            record = n.record.toURI, sender = fromNode.record.toURI
          continue

      # No check on UDP port and thus any port is allowed, also the so called
      # "well-known" ports.

      seen.incl(n)
      result.add(n)

proc verifyNodesRecords*(enrs: openArray[Record], fromNode: Node, nodesLimit: int): seq[Node] =
  verifyNodesRecords(enrs, fromNode, nodesLimit, none[seq[uint16]]())

proc verifyNodesRecords*(enrs: openArray[Record], fromNode: Node, nodesLimit: int, distances: seq[uint16]): seq[Node] =
  verifyNodesRecords(enrs, fromNode, nodesLimit, some[seq[uint16]](distances))
