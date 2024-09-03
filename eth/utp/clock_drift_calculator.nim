# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronos

const
  # how long do we collect samples before calculating average
  averageTime = seconds(5)

# calculates 5s rolling average of incoming delays, which represent clock drift.
type ClockDriftCalculator* = object
  # average of all delay samples compared to initial one. Average is done over
  # 5s
  averageDelay: int32
  # sum of all recent delay samples. All samples are relative to first sample
  # averageDelayBase
  currentDelaySum: int64
  # number if samples in sum
  currentDelaySamples: int
  # set to first sample, all further samples are taken in relative to this one
  averageDelayBase: uint32
  # next time we should average samples
  averageSampleTime: Moment
  # estimated clock drift in microseconds per 5 seconds
  clockDrift*: int32

  # last calculated drift
  lastClockDrift*: int32

proc init*(T: type ClockDriftCalculator, currentTime: Moment): T =
  T(
    averageSampleTime: currentTime + averageTime
  )

## This is a port from the clock drift calculation implemented in libutp:
## https://github.com/bittorrent/libutp/blob/2b364cbb0650bdab64a5de2abb4518f9f228ec44/utp_internal.cpp#L2026
##
## We limit actualDelay to int32.max to avoid overflow in calculations later on,
## more specifically at the drift calculation. This might/will influence the
## actual result, however, dealing which such high values bears the question
## if we should not just drop the connection in the first place.
##
## It also does not resolve faulty(?) behaviour in the algorithm, where
## currentDelaySum can go negative even when the actualDelay keeps increasing.
##
## TODO: With the above issues in mind and the current complexity of the algorithm,
## we should reconsider if this is still required and if so, whether a simpler
## algorithm would suffice.
proc addSample*(c: var ClockDriftCalculator, actualDelay: uint32, currentTime: Moment) =
  if (actualDelay == 0):
    return

  let delay = min(actualDelay, uint32(int32.high))
  # this is our first sample, initialise our delay base
  if c.averageDelayBase == 0:
    c.averageDelayBase = delay

  let distDown = c.averageDelayBase - delay

  let distUp = delay - c.averageDelayBase

  let averageDelaySample =
    if (distDown > distUp):
      # averageDelayBase is smaller that delay, sample should be positive
      int64(distUp)
    else:
       # averageDelayBase is bigger or equal to delay, sample should be negative
      -int64(distDown)

  c.currentDelaySum = c.currentDelaySum + averageDelaySample
  inc c.currentDelaySamples

  if (currentTime > c.averageSampleTime):
    # it is time to average our samples
    var prevAverageDelay = c.averageDelay
    c.averageDelay = int32(c.currentDelaySum div c.currentDelaySamples)
    c.averageSampleTime = c.averageSampleTime + averageTime
    c.currentDelaySum = 0
    c.currentDelaySamples = 0

    # normalize average samples
    let minSample = min(prevAverageDelay, c.averageDelay)
    let maxSample = max(prevAverageDelay, c.averageDelay)

    var adjust = 0

    if (minSample > 0):
      adjust = -minSample
    elif (maxSample < 0):
      adjust = -maxSample

    if (adjust != 0):
      c.averageDelayBase = c.averageDelayBase - uint32(adjust)
      c.averageDelay = c.averageDelay + int32(adjust)
      prevAverageDelay = prevAverageDelay + int32(adjust)

    let drift = c.averageDelay - prevAverageDelay
    # rolling average
    c.clockDrift = int32((int64(c.clockDrift) * 7 + drift) div 8)
    c.lastClockDrift = drift
