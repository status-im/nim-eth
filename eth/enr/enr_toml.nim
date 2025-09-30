# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

{.push raises: [].}

import
  ./enr,
  toml_serialization,
  toml_serialization/lexer

proc writeValue*(w: var TomlWriter, val: enr.Record) {.raises: [IOError].} =
  w.writeValue(val.toURI)

proc readValue*(r: var TomlReader, val: var enr.Record)
       {.gcsafe, raises: [IOError, SerializationError].} =
  val = fromURI(enr.Record, r.parseAsString()).valueOr:
    r.lex.raiseUnexpectedValue($error)
