# Portal Network Wire Protocol
## Introduction
The `eth/p2p/portal` directory holds a Nim implementation of the
[Portal Network Wire Protocol](https://github.com/ethereum/stateless-ethereum-specs/blob/master/state-network.md#wire-protocol).

Both specification, at above link, and implementations are still WIP.

The protocol builds on top of the Node Discovery v5.1 protocol its `talkreq` and
`talkresp` messages.

For further information on the Nim implementation of the Node Discovery v5.1
protocol check out the [discv5](../../../doc/discv5.md) page.

## Test suite
To run the test suite specifically for the Portal wire protocol, run following
command:
```sh
# Install required modules
nimble install
# Run only Portal tests
nimble test_portal
```

## portalcli
This is a small command line application that allows you to run a
Discovery v5.1 + Portal node.

*Note:* Its objective is only to test the protocol wire component, not to actually
serve content. This means it will always return empty lists on content requests.
Perhaps in the future some hardcoded data could added and maybe some test vectors
can be created in such form.

The `portalcli` application allows you to either run a node, or to specifically
send one of the message types, wait for the response, and then shut down.

### Example usage
```sh
# Install required modules
# Make sure you have the latest modules, do NOT trust nimble on this.
nimble install
# Build portalcli
nimble build_portalcli
# See all options
./eth/p2p/portal/portalcli --help
# Example command: Ping another node
./eth/p2p/portal/portalcli ping enr:<base64 encoding of ENR>
# Example command: Run discovery + portal node
./eth/p2p/portal/portalcli --log-level:debug --bootnode:enr:<base64 encoding of ENR>
