# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronos

# Internal Utp data structure to track send window and properly block when there is
# no free space when trying to send more bytes
type SendBufferTracker* = ref object
  # number of payload bytes in-flight (i.e not counting header sizes)
  # packets that have not yet been sent do not count, packets
  # that are marked as needing to be re-sent (due to a timeout)
  # don't count either
  currentWindow*: uint32

  # remote receive window updated based on packed wndSize field
  maxRemoteWindow*: uint32

  # maximum window size, in bytes, calculated by local congestion controller
  maxWindow*: uint32

  # configuration option for maxium number of bytes in snd buffer
  maxSndBufferSize*: uint32
  waiters: seq[(uint32, Future[void])]

proc new*(
  T: type SendBufferTracker,
  currentWindow: uint32,
  maxRemoteWindow: uint32,
  maxSndBufferSize: uint32,
  maxWindow: uint32): T =
  return (
    SendBufferTracker(
      currentWindow: currentWindow,
      maxRemoteWindow: maxRemoteWindow,
      maxSndBufferSize: maxSndBufferSize,
      maxWindow: maxWindow,
      waiters: @[]
    )
  )

proc currentFreeBytes*(t: SendBufferTracker): uint32 =
  let maxSend = min(min(t.maxRemoteWindow, t.maxSndBufferSize), t.maxWindow)
  if (maxSend <= t.currentWindow):
    return 0
  else:
    return maxSend - t.currentWindow

proc checkWaiters(t: SendBufferTracker) =
  var i = 0
  while i < len(t.waiters):
    let freeSpace = t.currentFreeBytes()
    let (required, fut) = t.waiters[i]
    if (required <= freeSpace):
      # in case future was cancelled
      if (not fut.finished()):
        t.currentWindow = t.currentWindow + required
        fut.complete()
      t.waiters.del(i)
    else:
      # we do not have place for next waiter, just finish processing
      return

proc updateMaxRemote*(t: SendBufferTracker, newRemoteWindow: uint32) =
  t.maxRemoteWindow = newRemoteWindow
  t.checkWaiters()

proc updateMaxWindowSize*(t: SendBufferTracker, newRemoteWindow: uint32, maxWindow: uint32) =
  t.maxRemoteWindow = newRemoteWindow
  t.maxWindow = maxWindow
  t.checkWaiters()

proc decreaseCurrentWindow*(t: SendBufferTracker, value: uint32, notifyWaiters: bool) =
  doAssert(t.currentWindow >= value)
  t.currentWindow = t.currentWindow - value
  if (notifyWaiters):
    t.checkWaiters()

proc reserveNBytesWait*(t: SendBufferTracker, n: uint32): Future[void] =
  let fut = newFuture[void]("SendBufferTracker.reserveNBytesWait")
  let free = t.currentFreeBytes()
  if (n <= free):
    t.currentWindow = t.currentWindow + n
    fut.complete()
  else:
    t.waiters.add((n, fut))
  fut

proc reserveNBytes*(t: SendBufferTracker, n: uint32): bool =
  let free = t.currentFreeBytes()
  if (n <= free):
    t.currentWindow = t.currentWindow + n
    return true
  else:
    return false

proc currentBytesInFlight*(t: SendBufferTracker): uint32 = t.currentWindow
