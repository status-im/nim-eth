import
  private/p2p_types

const tracingEnabled* = defined(p2pdump)

when tracingEnabled:
  import
    macros,
    serialization, json_serialization/writer,
    chronicles, chronicles_tail/configuration

  export
    # XXX: Nim visibility rules get in the way here.
    # It would be nice if the users of this module don't have to
    # import json_serializer, but this won't work at the moment,
    # because the `encode` call inside `logMsgEvent` has its symbols
    # mixed in from the module where `logMsgEvent` is called
    # (instead of from this module, which will be more logical).
    init, writeValue, getOutput
    # TODO: File this as an issue

  logStream p2pMessages[json[file(p2p_messages.json,truncate)]]
  p2pMessages.useTailPlugin "p2p_tracing_ctail_plugin.nim"

  template logRecord(eventName: static[string], args: varargs[untyped]) =
    p2pMessages.log LogLevel.NONE, eventName, topics = "p2pdump", args

  proc initTracing*(baseProtocol: ProtocolInfo,
                    userProtocols: seq[ProtocolInfo]) =
    once:
      var w = init StringJsonWriter

      proc addProtocol(p: ProtocolInfo) =
        w.writeFieldName p.name
        w.beginRecord()
        for msg in p.messages:
          w.writeField $msg.id, msg.name
        w.endRecordField()

      w.beginRecord()
      addProtocol baseProtocol
      for userProtocol in userProtocols:
        addProtocol userProtocol
      w.endRecord()

      logRecord "p2p_protocols", data = JsonString(w.getOutput)

  proc logMsgEventImpl(eventName: static[string],
                       peer: Peer,
                       protocol: ProtocolInfo,
                       msgId: int,
                       json: string) =
    # this is kept as a separate proc to reduce the code bloat
    logRecord eventName, port = int(peer.network.address.tcpPort),
                         peer = $peer.remote,
                         protocol = protocol.name,
                         msgId, data = JsonString(json)

  proc logMsgEvent[Msg](eventName: static[string], peer: Peer, msg: Msg) =
    mixin msgProtocol, protocolInfo, msgId

    logMsgEventImpl(eventName, peer,
                    Msg.msgProtocol.protocolInfo,
                    Msg.msgId,
                    StringJsonWriter.encode(msg))

  proc logSentMsgFields*(peer: NimNode,
                         protocolInfo: NimNode,
                         msgId: int,
                         fields: openarray[NimNode]): NimNode =
    ## This generates the tracing code inserted in the message sending procs
    ## `fields` contains all the params that were serialized in the message
    var tracer = ident("tracer")

    result = quote do:
      var `tracer` = init StringJsonWriter
      beginRecord(`tracer`)

    for f in fields:
      result.add newCall(bindSym"writeField", tracer, newLit($f), f)

    result.add quote do:
      endRecord(`tracer`)
      logMsgEventImpl("outgoing_msg", `peer`,
                      `protocolInfo`, `msgId`, getOutput(`tracer`))

  template logSentMsg*(peer: Peer, msg: auto) =
    logMsgEvent("outgoing_msg", peer, msg)

  template logReceivedMsg*(peer: Peer, msg: auto) =
    logMsgEvent("incoming_msg", peer, msg)

  template logConnectedPeer*(p: Peer) =
    logRecord "peer_connected",
              port = int(p.network.address.tcpPort),
              peer = $p.remote

  template logAcceptedPeer*(p: Peer) =
    logRecord "peer_accepted",
              port = int(p.network.address.tcpPort),
              peer = $p.remote

  template logDisconnectedPeer*(p: Peer) =
    logRecord "peer_disconnected",
              port = int(p.network.address.tcpPort),
              peer = $p.remote

else:
  template initTracing*(baseProtocol: ProtocolInfo,
                        userProtocols: seq[ProtocolInfo])= discard
  template logSentMsg*(peer: Peer, msg: auto) = discard
  template logReceivedMsg*(peer: Peer, msg: auto) = discard
  template logConnectedPeer*(peer: Peer) = discard
  template logAcceptedPeer*(peer: Peer) = discard
  template logDisconnectedPeer*(peer: Peer) = discard

