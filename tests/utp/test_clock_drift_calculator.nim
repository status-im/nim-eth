# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  chronos,
  unittest2,
  ../../eth/utp/clock_drift_calculator

suite "Clock drift calculator":

  test "Initial clock drift should be 0":
    let currentTime = Moment.now()
    let calculator = ClockDriftCalculator.init(currentTime)

    check:
      calculator.clockDrift == 0

  test "Adding samples should not update averages if 5s did not pass":
    let currentTime = Moment.now()
    var calculator = ClockDriftCalculator.init(currentTime)

    calculator.addSample(10, currentTime + seconds(1))
    calculator.addSample(10, currentTime + seconds(2))

    check:
      calculator.clockDrift == 0
      calculator.lastClockDrift == 0

  test "Clock drift should be calculated in relation to first sample":
    let currentTime = Moment.now()
    var calculator = ClockDriftCalculator.init(currentTime)

    # first sample which will be treated as a base sample
    calculator.addSample(10, currentTime + seconds(3))

    # second sample in the first interval it will be treated in relation to first one
    # so correct first drift should be: (50 - 10) / 2 == 20
    calculator.addSample(50, currentTime + seconds(6))

    check:
      calculator.clockDrift == 2
      calculator.lastClockDrift == 20

  test "Clock drift should properly calculated when clock drifts to two sides":
    let currentTime = Moment.now()
    var calculator1 = ClockDriftCalculator.init(currentTime)
    var calculator2 = ClockDriftCalculator.init(currentTime)


    # first sample which will be treated as a base sample
    calculator1.addSample(10, currentTime + seconds(3))

    # second sample in the first inteval it will be treated in relation to first one
    # so correct first drift should be: (50 - 10) / 2 == 20
    calculator1.addSample(50, currentTime + seconds(6))

    # first sample which will be treated as a base sample
    calculator2.addSample(50, currentTime + seconds(3))

    # second sample in the first inteval it will be treated in relation to first one
    # so correct first drift should be: (10 - 50) / 2 == -20
    calculator2.addSample(10, currentTime + seconds(6))

    check:
      calculator1.clockDrift == -calculator2.clockDrift
      calculator1.lastClockDrift == -calculator2.lastClockDrift
