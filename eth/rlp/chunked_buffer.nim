import
  stew/[arraybuf, assign2, bitops2, shims/macros]

type
  # a 200-byte chunk matches the block length of keccak(1600bits)v
  # TODO: use some compile time technique to abstract out the size(200)
  BufferChunk = array[200, byte]
  RefBufferChunk = ref BufferChunk

  ChunkedBuffer* = object
    fillLevel: int
    chunks: seq[RefBufferChunk]

func `$`(chunk: RefBufferChunk): string =
  $(chunk[])

func initChunkedBuffer(): ChunkedBuffer =
  let newChunk = new(RefBufferChunk)
  result.chunks.add(newChunk)
  result.fillLevel = 0

func curChunkIdx(buffer: ChunkedBuffer): int = 
  return (buffer.fillLevel mod len(BufferChunk))

func isCurChunkFull(buffer: ChunkedBuffer): bool =
  (len(buffer.chunks) * len(BufferChunk)) == buffer.fillLevel 

func curChunkRemaining(buffer: ChunkedBuffer): int = 
  return len(BufferChunk) - (buffer.fillLevel mod len(BufferChunk))

func append*(buffer: var ChunkedBuffer, data: openArray[byte]) =
  var remainingBytes = len(data)

  # debugEcho buffer.fillLevel, (len(buffer.chunks) * len(BufferChunk))

  if buffer.isCurChunkFull:
    let newChunk = new(RefBufferChunk)
    buffer.chunks.add(newChunk)

  while remainingBytes > 0:
    let startIdx = len(data) - remainingBytes
    let numBytes = if buffer.curChunkRemaining < remainingBytes: buffer.curChunkRemaining else: remainingBytes
    let endIdx = startIdx + numBytes - 1
    let chunkIdx = buffer.fillLevel div len(BufferChunk)

    # debugEcho startIdx, " ", endIdx, " ", chunkIdx, " ", buffer.curChunkRemaining

    assign(
      buffer.chunks[chunkIdx][].toOpenArray(buffer.curChunkIdx, buffer.curChunkIdx + numBytes - 1), 
      data[startIdx..endIdx]
    )

    buffer.fillLevel += numBytes
    remainingBytes -= numBytes

    if remainingBytes > 0:
      let newChunk = new(RefBufferChunk)
      buffer.chunks.add(newChunk)


# TODO: idx shouldn't only be type int. Technically it should be able to accomodate SomeOrdinal
func `[]`*(buffer: ChunkedBuffer, idx: int): byte =
  buffer.chunks[idx div len(BufferChunk)][idx mod len(BufferChunk)]

# TODO: idx shouldn't only be type int. Technically it should be able to accomodate SomeOrdinal
func `[]=`*(buffer: var ChunkedBuffer, idx: int, value: byte) =
  buffer.chunks[idx div len(BufferChunk)][idx mod len(BufferChunk)] = value

func append*(buffer: var ChunkedBuffer, data: byte) =
  if buffer.isCurChunkFull:
    let newChunk = new(RefBufferChunk)
    buffer.chunks.add(newChunk)

  buffer[buffer.fillLevel] = data
  buffer.fillLevel += 1

func consume*(buffer: var ChunkedBuffer): BufferChunk =
  let chunk = buffer.chunks[0][] # this will copy the chunk
  buffer.chunks.delete(0)
  buffer.fillLevel -= len(BufferChunk)
  chunk

func addGapChunk*(buffer: var ChunkedBuffer) =
  let newChunk = new(RefBufferChunk)
  buffer.chunks.add(newChunk)
  buffer.fillLevel = len(buffer.chunks) * len(BufferChunk)
