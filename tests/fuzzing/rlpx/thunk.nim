import
 testutils/fuzzing, chronos,
  ../../../eth/p2p, ../../../eth/p2p/rlpx, ../../../eth/p2p/private/p2p_types,
  ../../p2p/eth_protocol,
  ../../p2p/p2p_test_helper

var
  node1: EthereumNode
  node2: EthereumNode
  peer: Peer

let rng = SecureRngContext.new()
# This is not a good example of a fuzzing test and it would be much better
# to mock more to get rid of anything sockets, async, etc.
# However, it can and has provided reasonably quick results anyhow.
init:
  node1 = setupTestNode(rng, eth)
  node2 = setupTestNode(rng, eth)

  node2.startListening()
  let res = waitFor node1.rlpxConnect(newNode(node2.toENode()))
  if res.isErr():
    quit 1
  else:
    peer = res.get()

test:
  aflLoop: # This appears to have unstable results with afl-clang-fast, probably
           # because of undeterministic behaviour due to usage of network/async.
    try:
      var (msgId, msgData) = recvMsgMock(payload)
      waitFor peer.invokeThunk(msgId.int, msgData)
    except CatchableError as e:
      debug "Test caused CatchableError", exception=e.name, trace=e.repr, msg=e.msg
