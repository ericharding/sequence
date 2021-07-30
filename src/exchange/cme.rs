use byteorder::{BigEndian,ByteOrder};
use super::Range;

pub fn get_sequence(data : &[u8]) -> Range {
    let seq_num = BigEndian::read_u32(&data);
    Range { begin: seq_num as u64, count: 1 }
}
