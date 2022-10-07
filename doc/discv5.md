# Node Discovery Protocol v5
## Introduction
The `eth/p2p/discoveryv5` directory holds a Nim implementation of the
[Node Discovery Protocol v5.1](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md).

The implemented specification is Protocol version v5.1.

This implementation does not support "Topic Advertisement" yet as this part of
the specification is not complete.

The implementation depends on other modules in the `eth` package, namely: `keys`
and `rlp`.

## How to use

```Nim
let
  rng = keys.newRng
  privKey = PrivateKey.random(rng[])
  (ip, tcpPort, udpPort) = setupNat(config) # Or fill in external IP/ports manually
  d = newProtocol(privKey, ip, tcpPort, udpPort, rng = rng)

d.open() # Start listening
```

This will initialize the `Protocol` and start listening. However, as no
bootstrap nodes were passed in the `newProtocol` call, the created ENR will need
to be advertised somehow ("out of band"), so that the node can become known to
other nodes in the network.

To initialize with a bootnode or a set of bootnodes, the ENRs need to be passed
as parameter in `newProtocol`.
```Nim
d = newProtocol(privKey, ip, tcpPort, udpPort,
      bootstrapRecords = bootnodes)
d.open() # Start listening and add bootstrap nodes to the routing table.
```

Next there are two ways to run the protocol.

One can call `d.start()` and two loops will be started:
1. Refresh loop
2. Revalidation loop

The first loop will at specific interval do a query with a random `NodeId` if no
manual queries were done for more than that interval period.
This query will add discovered nodes to the routing table.
The second loop will at random ranged interval send a ping to the least recently
seen node in a random bucket. This is to keep the routing table cleared of
unreachable/dead nodes.

Now within the application, manual queries or lookups can be done, for which
the discovered nodes can be used. Nodes discovered during this process will be
attempted to be added to the routing table. One can use the `query`, `queryRandom`
or `lookup` calls for this. `randomNodes` can also be used to find nodes,
but this will only look into the current routing table and not actively
search for nodes on the network.

Or, one can decide not to run `d.start()` and do this manually within its
application by using the available calls:
- `query`, `queryRandom` or `lookup` for discovering more peers.
- `revalidateNode` or directly `ping` for revalidating nodes.

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
nimble test_discv5_full
```

## dcli
This is a small command line application that allows you to run a discovery
node. It also has the options to do a `ping` or `findNode` request to a specific
node, by providing its ENR.

### Example usage
```sh
# Install required modules
# Make sure you have the latest modules, do NOT trust nimble on this.
nimble install
# Build dcli
nim c -d:chronicles_log_level:trace -d:release --threads:on eth/p2p/discoveryv5/dcli
# See all options
./eth/p2p/discoveryv5/dcli --help
# Ping another node
./eth/p2p/discoveryv5/dcli ping enr:<base64 encoding of ENR>
# Run discovery node
./eth/p2p/discoveryv5/dcli --log-level:debug --bootnode:enr:<base64 encoding of ENR>
```

### Metrics
To run dcli with metrics enabled provide the `metrics` flag:

```sh
# Run dcli with metrics
./eth/p2p/discoveryv5/dcli --metrics --bootnode:enr:<base64 encoding of ENR>
```

You can now see the metrics at http://localhost:8008/metrics. Or use e.g.
Prometheus to grab the data.
