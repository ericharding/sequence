#![allow(dead_code)]
use clap::{App, Arg};
mod decode;
mod exchange;
use exchange::{SequenceDecoder, Range};

fn decode_udp(p: decode::UdpPacket, decoder: &SequenceDecoder) {
    // let range = decoder.get_sequence(p.data());
    let range = decoder(p.data());
    print!("{}->{}", range.begin, range.count);
}

fn decode_ip(p: decode::IPPacket, decoder: &SequenceDecoder) -> i32 {
    if let decode::IPPacket::IPv4(packet) = p {
        if let decode::ProtocolPacket::UDP(udp) = packet.protocol() {
            decode_udp(udp, decoder);
        }
    }
    0
}

fn decode_ethernet(data: &[u8], decoder: &SequenceDecoder) -> i32 {
    if let Some(frame) = decode::EthernetFrame::new(data) {
        return decode_ip(frame.protocol(), decoder);
    }
    return 0;
}
fn decode_linux_cooked(data: &[u8], decoder: &SequenceDecoder) -> i32 {
    if let Some(frame) = decode::LinuxCooked::new(data) {
        return decode_ip(frame.protocol(), decoder);
    }
    0
}

pub enum Exchange {
    CME,
    CBOE,
    ICE,
}

pub struct Config {
    output : String,
    begin: u64,
    end: u64,
}

fn get_config(dest : Option<&str>, begin : u64, end_opt : Option<u64>, count_opt : Option<u64>) -> Result<Option<Config>, &str> {
    if dest.is_none() { return Ok(None); }
    if end_opt.is_some() && count_opt.is_some() { return Err("Must specify either --end or --count"); }
    let end = end_opt.unwrap_or(begin + count_opt.unwrap());
    Ok (Some (Config { output : String::from(dest.unwrap()), begin : begin, end : end }))
}

fn get_exchange(cme: bool, cboe: bool, ice: bool) -> Option<Exchange> {
    match (cme, cboe, ice) {
        (true, false, false) => Some(Exchange::CME),
        (false, true, false) => Some(Exchange::CBOE),
        (false, false, true) => Some(Exchange::ICE),
        _ => None,
    }
}

struct StreamContext {
    last_seq : u64,
    missing : Vec<Range>
}

struct Context<'a> {
    pub decoder : &'a SequenceDecoder
    // map of ip,port destination to 
}

fn main_impl(source : &str, exchange: Exchange, config: Option<Config>) {
    // create the apropriate sequence decoder
    let decoder : &SequenceDecoder =
        match exchange {
            Exchange::CBOE => &exchange::cboe::get_sequence,
            Exchange::CME => &exchange::cme::get_sequence,
            _ => &|_data| exchange::Range { begin: 0, count: 0 }
        };
    
    // parse each packet and determine it's ip range and 
}

fn main() {
    let matches = App::new("Sequence")
        .version("0.1.0")
        .author("Eric Harding <eric@digitalsorcery.net")
        .about("Checks a pcap file for gaps in CME or CBOE market data")
        .arg(Arg::with_name("source")
                 .short("s")
                 .long("souce")
                 .takes_value(true)
                 .required(true)
                 .help("pcap file to read from"))
        .arg(Arg::with_name("cboe")
                 .long("cboe")
                 .takes_value(false)
                 .help("Packets are in CBOE/CFE multicast format"))
        .arg(Arg::with_name("cme")
                 .long("cme")
                 .takes_value(false)
                 .help("Packets are in CME MDP3 multicast format"))
        .arg(Arg::with_name("destination")
                 .short("o")
                 .long("output")
                 .takes_value(true)
                 .help("Write selected packet range to <output>. Select range with -b(egin), -e(nd) and -c(ount)"))
        .arg(Arg::with_name("begin")
                 .short("b")
                 .long("begin")
                 .takes_value(true)
                 .help("Select packets starting at sequence number <begin>"))
        .arg(Arg::with_name("end")
                 .short("e")
                 .long("end")
                 .takes_value(true)
                 .help("Select packets ending at sequence number <end>"))
        .arg(Arg::with_name("count")
                 .short("c")
                 .long("count")
                 .takes_value(true)
                 .help("Select <count> packets from -b(egin)"))
        .get_matches();

    let source_file = matches.value_of("source").unwrap();
    let is_cboe = matches.is_present("cboe");
    let is_cme = matches.is_present("cme");
    let is_ice = matches.is_present("ice");
    let exchange = get_exchange(is_cme, is_cboe, is_ice);
    if exchange.is_none() {
        println!("Error: Please specify one exchange cme, cboe or ice");
        return;
    }
    let begin = matches.value_of("begin").and_then(|value : &str| value.parse::<u64>().ok()).unwrap_or(0);
    let end = matches.value_of("end").and_then(|value : &str| value.parse::<u64>().ok());
    let count = matches.value_of("count").and_then(|value : &str| value.parse::<u64>().ok());
    let dest = matches.value_of("destination");
    let config = 
        match get_config(dest, begin, end, count) {
            Ok(x) => x,
            Err(msg) => {
                println!("Error: {}", msg);
                return;
            }
        };

    main_impl(source_file, exchange.unwrap(), config);
}