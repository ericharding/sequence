use byteorder::{BigEndian,ByteOrder};
use super::SequenceRange;

pub fn get_sequence(data : &[u8]) -> SequenceRange {
    let seq_num = BigEndian::read_u32(&data[2..]);
    let msg_count = BigEndian::read_u16(&data[6..]);
    SequenceRange { begin: seq_num as u64, count: msg_count }
}