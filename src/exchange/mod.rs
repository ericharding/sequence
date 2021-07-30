pub struct Range {
    pub begin : u64,
    pub count : u64
}

pub type SequenceDecoder = dyn Fn(&[u8])->Range;

pub mod cboe;
pub mod cme;