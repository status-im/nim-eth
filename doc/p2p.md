## p2p

### Introduction

This library implements the DevP2P family of networking protocols used
in the Ethereum world.

### Connecting to the Ethereum network

A connection to the Ethereum network can be created by instantiating
the `EthereumNode` type:

``` nim
proc newEthereumNode*(keys: KeyPair,
                      listeningAddress: Address,
                      networkId: uint,
                      chain: AbstractChainDB,
                      clientId = "nim-eth-p2p",
                      addAllCapabilities = true): EthereumNode =
```

#### Parameters:

`keys`:
  A pair of public and private keys used to authenticate the node
  on the network and to determine its node ID.
  See the [keys](./keys.md)
  library for utilities that will help you generate and manage
  such keys.

`listeningAddress`:
  The network interface and port where your client will be
  accepting incoming connections.

`networkId`:
  The Ethereum network ID. The client will disconnect immediately
  from any peers who don't use the same network.

`chain`:
  An abstract instance of the Ethereum blockchain associated
  with the node. This library allows you to plug any instance
  conforming to the abstract interface defined in the
  [eth_common](https://github.com/status-im/nim-eth-common)
  package.

`clientId`:
  A name used to identify the software package connecting
  to the network (i.e. similar to the `User-Agent` string
  in a browser).

`addAllCapabilities`:
  By default, the node will support all RPLx protocols imported in
  your project. You can specify `false` if you prefer to create a
  node with a more limited set of protocols. Use one or more calls
  to `node.addCapability` to specify the desired set:

  ```nim
  node.addCapability(eth)
  ```

  Each supplied protocol identifier is a name of a protocol introduced
  by the `p2pProtocol` macro discussed later in this document.

Instantiating an `EthereumNode` does not immediately connect you to
the network. To start the connection process, call `node.connectToNetwork`:

``` nim
proc connectToNetwork*(node: var EthereumNode,
                       bootstrapNodes: openArray[ENode],
                       startListening = true,
                       enableDiscovery = true)
```

The `EthereumNode` will automatically find and maintain a pool of peers
using the Ethereum node discovery protocol. You can access the pool as
`node.peers`.

### Communicating with Peers using RLPx

[RLPx](https://github.com/ethereum/devp2p/blob/master/rlpx.md) is the
high-level protocol for exchanging messages between peers in the Ethereum
network. Most of the client code of this library should not be concerned
with the implementation details of the underlying protocols and should use
the high-level APIs described in this section.

The RLPx protocols are defined as a collection of strongly-typed messages,
which are grouped into sub-protocols multiplexed over the same TCP connection.

This library represents each such message as a regular Nim function call
over the `Peer` object. Certain messages act only as notifications, while
others fit the request/response pattern.

To understand more about how messages are defined and used, let's look at
the definition of a RLPx protocol:

#### RLPx sub-protocols

The sub-protocols are defined with the `p2pProtocol` macro. It will accept
a short identifier for the protocol and the current protocol version:

Here is how the [DevP2P wire protocol](https://github.com/ethereum/devp2p/blob/master/rlpx.md#p2p-capability) might look like:

``` nim
p2pProtocol DevP2P(version = 0, rlpxName = "p2p"):
  proc hello(peer: Peer,
             version: uint,
             clientId: string,
             capabilities: openArray[Capability],
             listenPort: uint,
             nodeId: P2PNodeId) =
    peer.id = nodeId

  proc disconnect(peer: Peer, reason: DisconnectionReason)

  proc ping(peer: Peer) =
    await peer.pong()

  proc pong(peer: Peer) =
    echo "received pong from ", peer.id
```

As seen in the example above, a protocol definition determines both the
available messages that can be sent to another peer (e.g. as in `peer.pong()`)
and the asynchronous code responsible for handling the incoming messages.

#### Protocol state

The protocol implementations are expected to maintain a state and to act
like a state machine handling the incoming messages. You are allowed to
define an arbitrary state type that can be specified in the `peerState`
protocol option. Later, instances of the state object can be obtained
though the `state` pseudo-field of the `Peer` object:

``` nim
type AbcPeerState = object
  receivedMsgsCount: int

p2pProtocol abc(version = 1,
                peerState = AbcPeerState):

  proc incomingMessage(p: Peer) =
    p.state.receivedMsgsCount += 1

```

Besides the per-peer state demonstrated above, there is also support
for maintaining a network-wide state. It's enabled by specifying the
`networkState` option of the protocol and the state object can be obtained
through accessor of the same name.

The state objects are initialized to zero by default, but you can modify
this behaviour by overriding the following procs for your state types:

```nim
proc initProtocolState*(state: MyPeerState, p: Peer)
proc initProtocolState*(state: MyNetworkState, n: EthereumNode)
```

Sometimes, you'll need to access the state of another protocol.
To do this, specify the protocol identifier to the `state` accessors:

``` nim
  echo "ABC protocol messages: ", peer.state(abc).receivedMsgCount
```

While the state machine approach may be a particularly robust way of
implementing sub-protocols (it is more amenable to proving the correctness
of the implementation through formal verification methods), sometimes it may
be more convenient to use more imperative style of communication where the
code is able to wait for a particular response after sending a particular
request. The library provides two mechanisms for achieving this:

#### Waiting particular messages with `nextMsg`

The `nextMsg` helper proc can be used to pause the execution of an async
proc until a particular incoming message from a peer arrives:

``` nim
proc helloExample(peer: Peer) =
  ...
  # send a hello message
  await peer.hello(...)

  # wait for a matching hello response, might want to add a timeout here
  let response = await peer.nextMsg(p2p.hello)
  echo response.clientId # print the name of the Ethereum client
                         # used by the other peer (Geth, Parity, Nimbus, etc)
```

There are few things to note in the above example:

1. The `p2pProtocol` definition created a pseudo-variable named after the
   protocol holding various properties of the protocol.

2. Each message defined in the protocol received a corresponding type name,
   matching the message name (e.g. `p2p.hello`). This type will have fields
   matching the parameter names of the message. If the messages has `openArray`
   params, these will be remapped to `seq` types.

If the designated messages also has an attached handler, the future returned
by `nextMsg` will be resolved only after the handler has been fully executed
(so you can count on any side effects produced by the handler to have taken
place). If there are multiple outstanding calls to `nextMsg`, they will
complete together. Any other messages received in the meantime will still
be dispatched to their respective handlers.

Please also note that the `p2pProtocol` macro will make this `helloExample` proc
`async`. Practically see it as `proc helloExample(peer: Peer) {.async.}`, and
thus never use `waitFor`, but rather `await` inside this proc.

For implementing protocol handshakes with `nextMsg` there are specific helpers
which are explained [below](https://github.com/status-im/nim-eth/blob/master/doc/p2p.md#implementing-handshakes-and-reacting-to-other-events).

#### `requestResponse` pairs

``` nim
p2pProtocol les(version = 2):
  ...

  requestResponse:
    proc getProofs(p: Peer, proofs: openArray[ProofRequest])
    proc proofs(p: Peer, BV: uint, proofs: openArray[Blob])

  ...
```

Two or more messages within the protocol may be grouped into a
`requestResponse` block. The last message in the group is assumed
to be the response while all other messages are considered requests.

When a request message is sent, the return type will be a `Future`
that will be completed once the response is received. Please note
that there is a mandatory timeout parameter, so the actual return
type is `Future[Option[MessageType]]`. The `timeout` parameter can
be specified for each individual call and the default value can be
overridden on the level of individual message, or the entire protocol:

``` nim
p2pProtocol abc(version = 1,
                useRequestIds = false,
                timeout = 5000): # value in milliseconds
  requestResponse:
    proc myReq(dataId: int, timeout = 3000)
    proc myRes(data: string)
```

By default, the library will take care of inserting a hidden `reqId`
parameter as used in the [LES protocol](https://github.com/zsfelfoldi/go-ethereum/wiki/Light-Ethereum-Subprotocol-%28LES%29),
but you can disable this behavior by overriding the protocol setting
`useRequestIds`.

#### Implementing handshakes and reacting to other events

Besides message definitions and implementations, a protocol specification may
also include handlers for certain important events such as newly connected
peers or misbehaving or disconnecting peers:

``` nim
p2pProtocol foo(version = fooVersion):
  onPeerConnected do (peer: Peer):
    let m = await peer.status(fooVersion,
                              timeout = chronos.milliseconds(5000))

    if m.protocolVersion == fooVersion:
      debug "Foo peer", peer, fooVersion
    else:
      raise newException(UselessPeerError, "Incompatible Foo version")

  onPeerDisconnected do (peer: Peer, reason: DisconnectionReason):
    debug "peer disconnected", peer

  handshake:
    proc status(peer: Peer,
                protocolVersion: uint)
```

For handshake messages, where the same type of message needs to be send to and
received from the peer, a `handshake` helper is introduced, as you can see in
the code example above.

Thanks to the `handshake` helper the `status` message will both be send, and be
awaited for receival from the peer, with the defined timeout. In case no `status`
message is received within the defined timeout, an error will be raised which
will result in a disconnect from the peer.


**Note:** Be aware that if currently one of the subprotocol `onPeerConnected`
calls fails, the client will be disconnected as `UselessPeer` but no
`onPeerDisconnect` calls are run.

#### Checking the other peer's supported sub-protocols

Upon establishing a connection, RLPx will automatically negotiate the list of
mutually supported protocols by the peers. To check whether a particular peer
supports a particular sub-protocol, use the following code:

``` nim
if peer.supports(les): # `les` is the identifier of the light clients sub-protocol
  peer.getReceipts(nextReqId(), neededReceipts())

```

