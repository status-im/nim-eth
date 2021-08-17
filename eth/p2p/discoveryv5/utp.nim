import times, math
import nim-stew/stew/endians2
import endians

const
  uTP_PROTOCOL = "utp"
  HEADER_SIZE = 20
  MAX_DISCV5_PACKET_SIZE = 1280
  MIN_PACKET_SIZE = 150
  MIN_DISCV5_PACKET_SIZE = 63

  CCONTROL_TARGET = 100 * 1000
  MAX_CWND_INCREASE_BYTES_PER_RTT = 3000
  MIN_WINDOW_SIZE = 10
  VERSION = 1

type
  UTPStates* = enum #* just means its public
    UTP_STATE_CONNECT = 1, 
    UTP_STATE_WRITABLE = 2,
    UTP_STATE_EOF = 3,
    UTP_STATE_DESTROYING = 4

  ConnectionState* = enum
    ST_DATA = 0
    ST_FIN = 1
    ST_STATE = 2
    ST_RESET = 3
    ST_SYN = 4
    ST_NUM_STATES

  PacketHeader = ref object
    type_ver: uint8
    extensions: uint8
    connection_id: uint16
    timestamp: uint32
    timestamp_diff: uint32
    wnd_size: uint32
    seq_nr: uint16
    ack_nr: uint16

  UTPProtocol = ref object
    state: ConnectionState
    seq_nr: uint16
    ack_nr: uint16
    conn_id_recv: uint16
    conn_id_send: uint16
    max_window: uint32
  
  ValueBytes = array[0..7, uint8]


  #[ConnectionKey = ref object 
    node_id: NodeId #From discovery 5
    conn_id_recv: uint16
  
  MicroTransportProtocol = ref object
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
    ]#

proc new_packet(): PacketHeader =

    return PacketHeader(type_ver: 1,
                        extensions: 0,
                        connection_id: 0,
                        timestamp: 0,
                        timestamp_diff: 0,
                        wnd_size: 0xf000,
                        seq_nr: 0,
                        ack_nr: 0)

proc decode_packet(bytes: seq[byte]): PacketHeader =

  return PacketHeader(type_ver: bytes[0],
                      extensions: bytes[1],
                      connection_id: uint16.fromBytesBE([bytes[2], bytes[3]]),
                      timestamp: uint32.fromBytesBE([bytes[4], bytes[5], bytes[6], bytes[7]]), #read from bytes, convert back to uint...
                      timestamp_diff: uint32.fromBytesBE([bytes[8],bytes[9], bytes[10], bytes[11]]),
                      wnd_size: uint32.fromBytesBE([bytes[12], bytes[13], bytes[14], bytes[15]]),
                      seq_nr: uint16.fromBytesBE([bytes[16], bytes[17]]),
                      ack_nr: uint16.fromBytesBE([bytes[18], bytes[19]]))
#[  
  return PacketHeader(type_ver: cast[ValueBytes](data.type_ver), #fromBytesBE(data.type_ver),
                      extensions: fromBytesBE(data.extensions),
                      connection_id: fromBytesBE(data.connection_id),
                      timestamp: fromBytesBE(data.timestamp),
                      timestamp_diff: fromBytesBE(data.timestamp_diff),
                      wnd_size: fromBytesBE(data.wnd_size),
                      seq_nr: fromBytesBE(data.seq_nr),
                      ack_nr: fromBytesBE(data.ack_nr))
]#

proc encode_packet(data: PacketHeader): seq[byte] = 

  let buf = newSeq[byte](20) 

  #buf.add(data.type_ver.toBytes)
  #buf.add([data.extensions])
  buf.add(toBytesBE(data.connection_id))
  buf.add(toBytesBE(data.timestamp))
  buf.add(toBytesBE(data.timestamp_diff))
  buf.add(toBytesBE(data.wnd_size))
  buf.add(toBytesBE(data.seq_nr))
  buf.add(toBytesBE(data.ack_nr))

  return buf
  #[  return PacketHeader(type_ver: toBytes(data.type_ver, bigEndian),
                      extensions: toBytes(data.extensions, bigEndian),
                      connection_id: toBytes(data.connection_id, bigEndian),
                      timestamp:  toBytes(data.timestamp, bigEndian),
                      timestamp_diff: toBytes(data.timestamp_diff, bigEndian),
                      wnd_size: toBytes(data.wnd_size, bigEndian),
                      seq_nr: toBytes(dcur  ata.seq_nr, bigEndian),
                      ack_nr: toBytes(data.ack_nr, bigEndian))]#



proc get_timestamp(): uint32 =
  return (getTime() * 10000000) & 0xffffffff

proc get_version(data: PacketHeader): uint8 = 
  return data.type_ver

proc set_version(data: PacketHeader, new_type: uint8) =
  data.type_ver = new_type

proc get_type(data: PacketHeader) =
  return data.type_ver

proc set_type(data: PacketHeader, i: uint8) = #need to pass var uint8 if we want to mutate it
  data.type_ver = (data.type_ver & 0xf) | (i << 4)

proc set_connection_id(data: PacketHeader, connection_id: uint16) = 
  data.connection_id = connection_id

proc set_timestamp(data: PacketHeader, timestamp: uint32) =
  data.timestamp = timestamp

proc set_timestamp_difference(data: PacketHeader, timestamp_diff: uint32) = 
  data.timestamp_diff = timestamp_diff

proc set_wnd_size(data: PacketHeader, wnd_size: uint32) = 
  data.wnd_size = wnd_size

proc set_seq_nr(data: PacketHeader, seq_nr: uint16) =
  data.seq_nr = seq_nr

proc set_ack_nr(data: PacketHeader, ack_nr: uint16) =
  data.ack_nr = ack_nr






type Packet = array[10, uint8] #seq? sequences can be mutable with var def, must all be the same type tho

proc new_packet(data: PacketHeader, payload: &uint8): Packet =
  return Packet

proc new_packet_with_payload(data: PacketHeader, payload: &uint8): Packet =
  return

proc new(bytes: &uint8): PacketHeader =
  return

proc get_header(bytes: seq[bytes]): PacketHeader =
  return decode_packet(bytes)


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


proc extension(data: PacketHeader): uint8 =
  data.get_header().extensions

proc version(data: PacketHeader): uint8 =
  data.get_header().version 

proc connection_id(data: PacketHeader): uint16 =
  data.get_header().connection_id

proc timestamp(data: PacketHeader): uint32 =
  data.get_header().timestamp

proc timestamp_diff(data: PacketHeader): uint32 =
  data.get_header().timestamp_diff 

proc wnd_size(data: PacketHeader): uint32 = 
  data.get_header().wnd_size 

proc seq_nr(data: PacketHeader): uint16 =
  data.get_header().seq_nr

proc ack_nr(data: PacketHeader): uint16 =
  data.get_header().ack_nr


