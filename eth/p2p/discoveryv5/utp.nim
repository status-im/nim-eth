import times

const
  UTP_PROTOCOL = "utp"
  HEADER_SIZE = 20
  MAX_DISCV5_PACKET_SIZE = 1280
  MIN_PACKET_SIZE = 150
  MIN_DISCV5_PACKET_SIZE = 63

  CCONTROL_TARGET = 100 * 1000
  MAX_CWND_INCREASE_BYTES_PER_RTT = 3000
  MIN_WINDOW_SIZE = 10
  VERSION = 1

type
  UTPStates = enum
    UTP_STATE_CONNECT = 1,
    UTP_STATE_WRITABLE = 2,
    UTP_STATE_EOF = 3,
    UTP_STATE_DESTROYING = 4

  ConnectionState = enum
    ST_DATA = 0
    ST_FIN = 1
    ST_STATE = 2
    ST_RESET = 3
    ST_SYN = 4
    ST_NUM_STATES

  PacketHeader = object
    packet_type: ConnectionState
    type_ver: uint8
    connection_id: uint16
    timestamp: uint32
    timestamp_diff: uint32
    wnd_size: uint32
    seq_nr: uint16
    ack_nr: uint16
    extensions: string
    data: string

  UTPProtocol = object
    state: ConnectionState
    seq_nr: uint16
    ack_nr: uint16
    conn_id_recv: uint16
    conn_id_send: uint16
    max_window: uint32
  
  ConnectionKey = object 
    node_id: NodeId #From discovery 5
    conn_id_recv: uint16
  
  MicroTransportProtocol = object
    state: ConnectionState
    seq_nr: uint16
    ack_nr: uint16
    conn_id_recv: uint16
    conn_id_send: uint16
    max_window: uint32
    incoming_buffer: #BTreeMap<u16, Packet>,
    unsent_queue: #VecDeque<Packet>,
    enr: #Enr,
    discovery: #Arc<Discovery>,
    cur_window: uint32
    remote_wnd_size: uint32
    send_window: #HashMap<u16, Packet>,
    duplicate_acks: uint8
    last_ack: uint16
    rtt: int32
    rtt_var: int32
    base_delay: #Vec<u32>
    timeout: uint64
    last_rollover: uint32
    current_delay: #Vec<(u32, u32)>


proc decode_packet(data: PacketHeader): uTPPacket =
  # TODO
  PacketHeader {

  }
  return uTPPacket()


proc encode_packet(data: uTPPacket): uTPPacket = 
  # TODO
  return uTPPacket()


proc get_timestamp(): uint32 =
  return (getTime() * 10000000) & 0xffffffff

proc get_version(data: PacketHeader): uint8 = 
  return data.type_ver

proc set_version(data: PacketHeader, new_type: uint8) =
  data.type_ver = new_type

proc get_type(data: PacketHeader) =
  return data.type_ver

proc set_type(data: PacketHeader, i: uint8) =
  data.type_ver = (data.type_ver & 0xf) | (i << 4)

type Packet = array[10, uint8]

proc new_packet(data: PacketHeader, payload: &uint8): Packet =
  return Packet

proc new_packet_with_payload(data: PacketHeader, payload: &uint8): Packet =
  return

proc new(bytes: &uint8): PacketHeader =
  return

proc get_header(data: PacketHeader) =
  return

proc get_payload(data: PacketHeader): &uint8 =
  return

proc set_selective_ack(data: PacketHeader, incoming_buffer: BTreeMap<uint16, Packet>, ack_nr: uint16) = 
  return



proc get_timestamp_diff(response_time: uint32): uint32 =
  let current_time = get_timestamp()

  if current_time > response_time:
    return current_time - response_time
  else:
    return response_time - current_time

  return 0






