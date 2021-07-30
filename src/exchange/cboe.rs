use super::Range;
use byteorder::{BigEndian, ByteOrder};

pub fn get_sequence(data: &[u8]) -> Range {
    if data.len() < 8 {
        // Packet smaller than  header, should 'never' happen
        // if it does return 0 sequence numbers. If this as a corrupted packet
        // this will, appropriately, show up as a gap.
        return Range { begin: 0, count: 0 };
    }
    let count = data[2];
    let seq_num = BigEndian::read_u32(&data[4..]);
    if seq_num == 0 {
        return Range { begin: 0, count: 0 };
    }
    Range {
        begin: seq_num as u64,
        count: count as u64,
    }
}