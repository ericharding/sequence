use byteorder::{BigEndian,ByteOrder};
use std::fmt;
use std::convert::TryInto;

//
// EthernetFrame

pub struct EthernetFrame<'a> {
    data : &'a [u8]
}
pub type MacAddr<'a> = &'a [u8; 6];

#[allow(dead_code)]
impl<'a> EthernetFrame<'a> {
    pub fn new(data : &[u8]) -> Option<EthernetFrame> {
        if data.len() < 14 { None }
        else {
            Some(EthernetFrame { data: data })
        }
    }
    pub fn size(&self) -> usize { 14 }
    pub fn destination(&self) -> MacAddr {
        self.data[..6].try_into().unwrap()
    }
    pub fn source(&self) -> MacAddr {
        self.data[6..12].try_into().unwrap()
    }
    pub fn protocol(&self) -> IPPacket {
        let t = BigEndian::read_u16(&self.data[12..14]);
        match t {
            0x806 => IPPacket::Arp,
            0x86DD => IPPacket::IPv6,
            0x800 => 
                if let Some(packet) = IPv4Packet::new(&self.data[self.size()..]) {
                    IPPacket::IPv4(packet)
                }
                else {
                    IPPacket::Unknown
                },
            _ => IPPacket::Unknown,
        }
    }
}

impl<'a> fmt::Debug for EthernetFrame<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "src: {:X?} dest: {:X?}", self.source(), self.destination())
    }
}

//
// LInux 'cooked' capture frame
pub struct LinuxCooked<'a> {
    data : &'a [u8]
}
#[derive(Debug)]
pub enum PacketType {
    Unknown,
    Multicast
}
#[allow(dead_code)]
impl<'a> LinuxCooked<'a> {
    pub fn new(data: &[u8]) -> Option<LinuxCooked> {
        if data.len() < 16 { None }
        else {
            Some (LinuxCooked { data : data })
        }
    }
    pub fn packet_type(&self) -> PacketType {
        match BigEndian::read_u16(&self.data[..2]) {
            2 => PacketType::Multicast,
            _ => PacketType::Unknown
        }
    }
    pub fn size(&self) -> usize { 16 }
    pub fn protocol(&self) -> IPPacket {
        // Note: copy/paste from EthernetFrame
        let t = BigEndian::read_u16(&self.data[14..16]);
        match t {
            0x806 => IPPacket::Arp,
            0x86DD => IPPacket::IPv6,
            0x800 => 
                if let Some(packet) = IPv4Packet::new(&self.data[self.size()..]) {
                    IPPacket::IPv4(packet)
                }
                else {
                    IPPacket::Unknown
                },
            _ => IPPacket::Unknown,
        }
    }
    pub fn source(&self) -> MacAddr {
        self.data[6..12].try_into().unwrap()
    }
}
impl<'a> fmt::Debug for LinuxCooked<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "src: {:X?} type: {:X?}", self.source(), self.packet_type())
    }
}

#[derive(Debug)]
pub enum IPPacket<'a> {
    Unknown,
    Arp,
    IPv4(IPv4Packet<'a>),
    IPv6,
}

//
// IPv4Packet

pub struct IPv4Packet<'a> {
    data: &'a [u8]
}

#[allow(dead_code)]
impl<'a> IPv4Packet<'a> {
    pub fn new(data : &[u8]) -> Option<IPv4Packet> {
        let version = data[0] >> 4;
        let header_size = (data[0] & 0xf) as usize;
        if version == 4 && data.len() >= (4*header_size) {
            Some (IPv4Packet { data: data })
        }
        else {
            None
        }
    }
    pub fn ihl(&self) -> usize {
        // IHL = number of 32 bit words
        ((self.data[0] & 0xf) * 4) as usize
    }
    pub fn total_length(&self) -> usize {
        BigEndian::read_u16(&self.data[2..4]) as usize
    }
    pub fn protocol(&self) -> ProtocolPacket {
        match &self.data[9] {
            0x1 => ProtocolPacket::ICMP,
            0x2 => ProtocolPacket::IGMP,
            0x6 => ProtocolPacket::TCP,
            0x11 =>
                match UdpPacket::new(&self.data[self.ihl()..]) {
                    Some(p) => ProtocolPacket::UDP(p),
                    None => ProtocolPacket::Error(String::from("Could not parse UDP packet")),
                }
            _ => ProtocolPacket::Other
        }
    }
    pub fn source(&self) -> IPv4Addr {
        IPv4Addr {
            data: self.data[12..16].try_into().unwrap()
        }
    }
    pub fn dest(&self) -> IPv4Addr {
        IPv4Addr {
            data: self.data[16..20].try_into().unwrap()
        }
    }
}
impl<'a> fmt::Debug for IPv4Packet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IPv4 {:?} packet src: {} dest: {} ", self.protocol(), self.source(), self.dest())
    }
}

//
// ProtocolPacket

pub enum ProtocolPacket<'a> {
#[allow(non_snake_case)]
    ICMP,
#[allow(non_snake_case)]
    IGMP,
#[allow(non_snake_case)]
    TCP,
#[allow(non_snake_case)]
    UDP(UdpPacket<'a>),
    Error(String),
    Other
}

impl<'a> fmt::Debug for ProtocolPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProtocolPacket::ICMP => write!(f, "ICMP"),
            ProtocolPacket::IGMP => write!(f, "IGMP"),
            ProtocolPacket::TCP => write!(f, "TCP"),
            ProtocolPacket::UDP(_) => write!(f, "UDP"),
            ProtocolPacket::Other => write!(f, "Other"),
            ProtocolPacket::Error(s) => write!(f, "Error: {}", s),
        }
    }
}

//
// IPv4Addr

#[derive(Copy,Clone,PartialEq,Eq,Hash,Debug)]
pub struct IPv4Addr {
    data : [u8;4]
}
#[allow(dead_code)]
impl IPv4Addr {
    pub fn from_bytes(a:u8, b:u8, c:u8, d:u8) -> IPv4Addr {
        IPv4Addr { data: [a,b,c,d] }
    }
}
impl fmt::Display for IPv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", 
            &self.data[0],
            &self.data[1],
            &self.data[2],
            &self.data[3])
    }
}

//
// UdpPacket

pub struct UdpPacket<'a> {
    // u16 src, dest, length, checksum
    data : &'a [u8]
}

#[allow(dead_code)]
impl<'a> UdpPacket<'a> {
    pub fn new(data : &[u8]) -> Option<UdpPacket> {
        if data.len() > 4 {
            let packet = UdpPacket { data: data };
            // println!("packet: {} >= {}", data.len(), packet.len());
            if data.len() >= (packet.len()+8) {
                return Some(packet);
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        // subtract packet header
        (BigEndian::read_u16(&self.data[4..]) - 8) as usize
    }
    pub fn src_port(&self) -> u16 {
        BigEndian::read_u16(&self.data[0..])
    }
    pub fn dst_port(&self) -> u16 {
        BigEndian::read_u16(&self.data[2..])
    }
    pub fn checksum(&self) -> u16 {
        BigEndian::read_u16(&self.data[6..8])
    }
    pub fn data(&self) -> &[u8] {
        &self.data[8..]
    }
}
impl<'a> fmt::Debug for UdpPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}->{} len:{} checksum:{}", self.src_port(), self.dst_port(), self.len(), self.checksum())
    }
}
