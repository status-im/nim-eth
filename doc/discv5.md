# Discovery v5
## Introduction
This `eth/p2p/discoveryv5` directory holds a Nim implementation of the
discovery v5 protocol specified
[here](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md).

This specification is still in DRAFT and thus subject to change. In fact, it is
likely that the current packet format will change, see
https://github.com/ethereum/devp2p/issues/152.

This implementation does not support "Topic Advertisement" yet.

The implementation relies on other modules in the `eth` package, namely: `keys`,
`rlp`, `async_utils` and `trie/db`. The latter is likely to change, see
https://github.com/status-im/nim-eth/issues/242

## How to use

```Nim
let
  rng = keys.newRng
  privKey = PrivateKey.random(rng[])
  (ip, tcpPort, udpPort) = setupNat(config) # Or fill in external IP/ports manually
  ddb = DiscoveryDB.init(newMemoryDB())
  d = newProtocol(privKey, ddb, ip, tcpPort, udpPort, rng = rng)

d.open() # Start listening
```

This will initialize the `Protocol` and start listening. However, as no
bootstrap nodes were passed in the `newProtocol` call, the created ENR will need
to be advertised somehow ("out of band"), so that the node can become known to
other nodes in the network.

To initialize with a bootnode or a set of bootnodes, the ENRs need to be passed
as parameter in `newProtocol`.
```Nim
d = newProtocol(privKey, ddb, ip, tcpPort, udpPort,
      bootstrapRecords = bootnodes)
d.open() # Start listening and add bootstrap nodes to the routing table.
```

Now there are two ways to run the protocol.

One can call `d.start()` and two loops will be started:
1. Random lookup loop
2. Revalidation loop

The first loop will at specific interval do a lookup with a random `NodeId`.
This lookup will add discovered nodes to the routing table.
The second loop will at random ranged interval send a ping to the least recently
seen node in a random bucket. This is to keep the routing table cleared of
unreachable/dead nodes.

Or, one can decide to do this manually within its application by using the
available calls:
- `lookupRandom` and `lookup` for discovering more peers.
- `revalidateNode` or directly `ping` for revalidating nodes.

In the future, the random lookup loop might be altered to only run in case no
lookup was done in the last x minutes. This way `d.start()` could still be run
while maintaining control over the lookups.

Of course, in either scenario, lookups can still be done for actually finding a
specific node. There is a `resolve` call that can help with this, it will first
look in the local routing table and if it finds the node it will try to contact
the node directly to check if the ENR is up to date. If any of this fail a
`lookup` will be done.

## Test suite
To run the test suite specifically for discovery v5 related (discovery v5 + its
nim-eth dependencies) tests, one can run following command:
```sh
# Install required modules
nimble install
# Run only discovery v5 related test suite
nimble tests_discv5
```

## dcli
This is a small command line application that allows you to run a discovery
node. It also has the options to do a `ping` or `findNode` request to a specific
node, by providing its ENR.

### Example usage
```sh
# Build dcli
nim c -d:chronicles_log_level:trace -d:release eth/p2p/discoveryv5/dcli
# See all options
./eth/p2p/discoveryv5/dcli --help
# Ping another node
./eth/p2p/discoveryv5/dcli ping enr:<base64 encoding of ENR>
# Run discovery node
./eth/p2p/discoveryv5/dcli --log-level:debug --bootnode:enr:<base64 encoding of ENR>
```

### Metrics
Metrics are available for `routing_table_nodes`, which holds the amount of nodes
in the routing table.

To compile in an HTTP endpoint for accessing the metrics add the `insecure`
compile time flag:
```sh
# Build dcli with metrics
nim c -d:insecure -d:chronicles_log_level:trace -d:release eth/p2p/discoveryv5/dcli
# Run dcli with metrics
./eth/p2p/discoveryv5/dcli --metrics --bootnode:enr:<base64 encoding of ENR>
```

You can now see the metrics at http://localhost:8008/metrics. Or use e.g.
Prometheus to grab the data.
