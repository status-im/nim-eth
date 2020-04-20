## rlp

### Introduction

A Nim implementation of the Recursive Length Prefix encoding (RLP) as specified
in the Ethereum's [Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf)
and [Wiki](https://github.com/ethereum/wiki/wiki/RLP).


### Reading RLP data

The `Rlp` type provided by this library represents a cursor over an RLP-encoded
byte stream.
``` nim
proc rlpFromBytes*(data: openArray[byte]): Rlp
```

### Streaming API

Once created, the `Rlp` object will offer procs such as `isList`, `isBlob`,
`getType`, `listLen`, `blobLen` to determine the type of the value under
the cursor. The contents of blobs can be extracted with procs such as
`toString`, `toBytes` and `toInt` without advancing the cursor.

Lists can be traversed with the standard `items` iterator, which will advance
the cursor to each sub-item position and yield the `Rlp` object at that point.
As an alternative, `listElem` can return a new `Rlp` object adjusted to a
particular sub-item position without advancing the original cursor.
Keep in mind that copying `Rlp` objects is cheap and you can create as many
cursors pointing to different positions in the RLP stream as necessary.

`skipElem` will advance the cursor to the next position in the current list.
`hasData` will indicate that there are no more bytes in the stream that can
be consumed.

Another way to extract data from the stream is through the universal `read`
proc that accepts a type as a parameter. You can pass any supported type
such as `string`, `int`, `seq[T]`, etc, including composite user-defined
types (see [Object Serialization](#object-serialization)). The cursor
will be advanced just past the end of the consumed object.

The `toXX` and `read` family of procs may raise a `RlpTypeMismatch` in case
of type mismatch with the stream contents under the cursor. A corrupted
RLP stream or an attemp to read past the stream end will be signaled
with the `MalformedRlpError` exception. If the RLP stream includes data
that cannot be processed on the current platform (e.g. an integer value
that is too large), the library will raise an `UnsupportedRlpError` exception.

### DOM API

Calling `Rlp.toNodes` at any position within the stream will return a tree
of `RlpNode` objects representing the collection of values starting at that
position:

``` nim
type
  RlpNodeType* = enum
    rlpBlob
    rlpList

  RlpNode* = object
    case kind*: RlpNodeType
    of rlpBlob:
      bytes*: seq[byte]
    of rlpList:
      elems*: seq[RlpNode]
```

As a short-cut, you can also call `decode` directly on a byte sequence to
avoid creating a `Rlp` object when obtaining the nodes.
For debugging purposes, you can also create a human readable representation
of the Rlp nodes by calling the `inspect` proc:

``` nim
proc inspect*(self: Rlp, indent = 0): string
```

### Creating RLP data

The `RlpWriter` type can be used to encode RLP data. Instances are created
with the `initRlpWriter` proc. This should be followed by one or more calls
to `append` which is overloaded to accept arbitrary values. Finally, you can
call `finish` to obtain the final `seq[byte]`.

If the end result should be a RLP list of particular length, you can replace
the initial call to `initRlpWriter` with `initRlpList(n)`. Calling `finish`
before writing the sufficient number of elements will then result in an assertion failure.

As an alternative short-cut, you can also call `encode` on an arbitrary value
(including sequences and user-defined types) to execute all of the steps at
once and directly obtain the final RLP bytes. `encodeList(varargs)` is another
short-cut for creating RLP lists.

### Object serialization

As previously explained, generic procs such as `read`, `append`, `encode` and
`decode` can be used with arbitrary used-defined object types. By default, the
library will serialize all of the fields of the object using the `fields`
iterator, but you can also include only a subset of the fields or modify the
order of serialization or by employing the `rlpIgnore` pragma or by using the
`rlpFields` macro:

``` nim
macro rlpFields*(T: typedesc, fields: varargs[untyped])

## example usage:

type
  Transaction = object
    amount: int
    time: DateTime
    sender: string
    receiver: string

rlpFields Transaction,
  sender, receiver, amount

...

var t1 = rlp.read(Transaction)
var bytes = encode(t1)
var t2 = bytes.decode(Transaction)
```

By default, sub-fields within objects are wrapped in RLP lists. You can avoid this
behavior by adding the custom pragma `rlpInline` on a particular field. In rare
circumstances, you may need to serialize the same field type differently depending
on the enclosing object type. You can use the `rlpCustomSerialization` pragma to
achieve this.

### Contributing / Testing

To test the correctness of any modifications to the library, please execute
`nimble test_rlp` at the root of the repo.

