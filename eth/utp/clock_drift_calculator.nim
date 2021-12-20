# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

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

proc addSample*(c: var ClockDriftCalculator, actualDelay: uint32, currentTime: Moment) =
  if (actualDelay == 0):
    return

  # this is our first sample, initialise our delay base
  if c.averageDelayBase == 0:
    c.averageDelayBase = actualDelay

  let distDown = c.averageDelayBase - actualDelay

  let distUp = actualDelay - c.averageDelayBase

  let averageDelaySample =
    if (distDown > distUp):
      # averageDelayBase is smaller that actualDelay, sample should be positive
      int64(distUp)
    else:
       # averageDelayBase is bigger or equal to actualDelay, sample should be negative
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
