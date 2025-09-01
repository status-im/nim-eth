# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

{.push raises: [].}

import
  ./nat,
  toml_serialization,
  toml_serialization/lexer

proc writeValue*(w: var TomlWriter, val: NatConfig) {.raises: [IOError].} =
  if val.hasExtIp:
    w.writeValue($val.extIp)
    return

  case val.nat
  of NatAny:
    w.writeValue("any")
  of NatUpnp:
    w.writeValue("upnp")
  of NatPmp:
    w.writeValue("pmp")
  of NatNone:
    w.writeValue("none")

proc readValue*(r: var TomlReader, val: var NatConfig)
       {.gcsafe, raises: [IOError, SerializationError].} =
  try: val =
    NatConfig.parseCmdArg(r.parseAsString())
  except ValueError as exc:
    r.lex.raiseUnexpectedValue(exc.msg)
