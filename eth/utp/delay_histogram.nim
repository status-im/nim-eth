# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronos,
  ./utp_utils

const
  currentDelaySize = 3
  delayBaseHistory = 13
  delayBaseUpdateInterval = minutes(1)

type
  DelayHistogram* = object
    delayBase*: uint32
    currentDelayHistory: array[currentDelaySize, uint32]
    currentDelayIdx: int
    delayBaseHistory: array[delayBaseHistory, uint32]
    delayBaseIdx: int
    delayBaseTime: Moment

proc init*(T: type DelayHistogram, currentTime: Moment): T =
  DelayHistogram(
    delayBaseTime: currentTime
  )

proc shift*(h: var DelayHistogram, offset: uint32) =
  for sample in h.delayBaseHistory.mitems():
    sample = sample + offset
  h.delayBase = h.delayBase + offset

proc addSample*(h: var DelayHistogram, sample: uint32, currentTime: Moment) =
  # if delay base is zero it means it is our first sample. Initialize necessary parts
  if h.delayBase == 0:
    h.delayBase = sample
    for i in h.delayBaseHistory.mitems():
      i = sample

  if wrapCompareLess(sample, h.delayBaseHistory[h.delayBaseIdx]):
    h.delayBaseHistory[h.delayBaseIdx] = sample

  if wrapCompareLess(sample, h.delayBase):
    h.delayBase = sample

  let delay = sample - h.delayBase

  h.currentDelayHistory[h.currentDelayIdx] = delay
  h.currentDelayIdx = (h.currentDelayIdx + 1) mod currentDelaySize

  if (currentTime - h.delayBaseTime > delayBaseUpdateInterval):
    h.delayBaseTime = currentTime
    h.delayBaseIdx = (h.delayBaseIdx + 1) mod delayBaseHistory
    h.delayBaseHistory[h.delayBaseIdx] = sample
    h.delayBase = h.delayBaseHistory[0]

    for delaySample in h.delayBaseHistory.items():
      if (wrapCompareLess(delaySample, h.delayBase)):
        h.delayBase = delaySample

proc getValue*(h: DelayHistogram): Duration =
  var value = uint32.high
  # this will return zero if not all samples are collected
  for sample in h.currentDelayHistory:
      value = min(sample, value)

  microseconds(value)
