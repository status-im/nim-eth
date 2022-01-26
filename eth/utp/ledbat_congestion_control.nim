# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronos,
  ./utp_utils

const targetDelay = milliseconds(100)

# explanation from reference impl:
# number of bytes to increase max window size by, per RTT. This is
# scaled down linearly proportional to off_target. i.e. if all packets
# in one window have 0 delay, window size will increase by this number.
# Typically it's less. TCP increases one MSS per RTT, which is 1500
const maxCwndIncreaseBytesPerRtt = 3000

const minWindowSize* = 10

proc applyCongestionControl*(
  currentMaxWindowSize: uint32,
  currentSlowStart: bool,
  currentSlowStartTreshold: uint32,
  maxSndBufferSize: uint32,
  currentPacketSize: uint32,
  actualDelay: Duration,
  numOfAckedBytes: uint32,
  minRtt: Duration,
  calculatedDelay: Duration,
  clockDrift: int32
): (uint32, uint32, bool) =
  if (actualDelay.isZero() or minRtt.isZero() or numOfAckedBytes == 0):
    return (currentMaxWindowSize, currentSlowStartTreshold, currentSlowStart)

  let ourDelay = min(minRtt, calculatedDelay)

  let target = targetDelay

  # Rationale from C reference impl:
  # this is here to compensate for very large clock drift that affects
  # the congestion controller into giving certain endpoints an unfair
  # share of the bandwidth. We have an estimate of the clock drift
  # (clock_drift). The unit of this is microseconds per 5 seconds.
  # empirically, a reasonable cut-off appears to be about 200000
  # (which is pretty high). The main purpose is to compensate for
  # people trying to "cheat" uTP by making their clock run slower,
  # and this definitely catches that without any risk of false positives
  # if clock_drift < -200000 start applying a penalty delay proportional
  # to how far beoynd -200000 the clock drift is
  let clockDriftPenalty: int64 =
    if (clockDrift < -200000):
      let penalty = (-clockDrift - 200000) div 7
      penalty
    else:
      0

  let offTarget = target.microseconds() - (ourDelay.microseconds() + clockDriftPenalty)

  # calculations from reference impl:
  # double window_factor = (double)min(bytes_acked, max_window) / (double)max(max_window, bytes_acked);
  # double delay_factor = off_target / target;
  # double scaled_gain = MAX_CWND_INCREASE_BYTES_PER_RTT * window_factor * delay_factor;

  let windowFactor = float64(min(numOfAckedBytes, currentMaxWindowSize)) / float64(max(currentMaxWindowSize, numOfAckedBytes))

  let delayFactor = float64(offTarget) / float64(target.microseconds())

  let scaledGain = maxCwndIncreaseBytesPerRtt * windowFactor * delayFactor

  let scaledWindow = float64(currentMaxWindowSize) + scaledGain

  let ledbatCwnd: uint32 =
    if scaledWindow < minWindowSize:
      uint32(minWindowSize)
    else:
      uint32(scaledWindow)

  var newSlowStart = currentSlowStart
  var newMaxWindowSize = currentMaxWindowSize
  var newSlowStartTreshold = currentSlowStartTreshold

  if currentSlowStart:
    let slowStartCwnd = currentMaxWindowSize + uint32(windowFactor * float64(currentPacketSize))

    if (slowStartCwnd > currentSlowStartTreshold):
      newSlowStart = false
    elif float64(ourDelay.microseconds()) > float64(target.microseconds()) * 0.9:
      # we are just a litte under target delay, discontinute slows start
      newSlowStart = false
      newSlowStartTreshold = currentMaxWindowSize
    else:
      newMaxWindowSize = max(slowStartCwnd, ledbatCwnd)
  else:
    newMaxWindowSize = ledbatCwnd

  newMaxWindowSize = clamp(newMaxWindowSize, minWindowSize, maxSndBufferSize)

  (newMaxWindowSize, newSlowStartTreshold, newSlowStart)
