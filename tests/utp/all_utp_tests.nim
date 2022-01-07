# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  ./test_packets,
  ./utp_packet_test_vectors,
  ./test_protocol,
  ./test_discv5_protocol,
  ./test_buffer,
  ./test_utp_socket,
  ./test_utp_socket_sack,
  ./test_utp_router,
  ./test_clock_drift_calculator
