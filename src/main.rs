use pcap::{Activated, Capture, Device, Offline, Packet, PacketHeader};
use pktparse::{
    ethernet::{parse_ethernet_frame, EtherType, EthernetFrame},
    ipv4::parse_ipv4_header,
    ipv6::parse_ipv6_header,
    tcp::parse_tcp_header,
    udp::{parse_udp_header, UdpHeader},
};

use getopt::Opt;

// use pktparse::ip::IPProtocol::{TCP, UDP};
use pktparse::ipv4::IPv4Header;
use pktparse::ipv6::IPv6Header;

use pktparse::tcp::TcpHeader;

use std::{env, path::Path, process::exit};

#[derive(Debug)]
enum IPlayer {
    V4(IPv4Header),
    V6(IPv6Header),
}
#[derive(Debug)]
enum AppLayer {
    TCP(TcpHeader),
    UDP(UdpHeader),
}

impl AppLayer {
    fn get_app_info(self) -> String {
        match self {
            AppLayer::TCP(value) => format!("TCP    {} -> {}", value.source_port, value.dest_port),
            AppLayer::UDP(value) => format!("UDP    {} -> {}", value.source_port, value.dest_port),
        }
    }
}

impl IPlayer {
    fn get_source_destination(self) -> String {
        match self {
            IPlayer::V4(value) => format!("{}   {}", value.source_addr, value.dest_addr),
            IPlayer::V6(value) => format!("{}   {}", value.source_addr, value.dest_addr),
        }
    }
}

struct CapturedFrame {
    pub packet_header: PacketHeader,
    pub ethernet: Option<EthernetFrame>,
    pub internet: Option<IPlayer>,
    pub application: Option<AppLayer>,
}

impl CapturedFrame {
    fn print_status_line(self) {
        println!(
            "{} {}  {}  {}      {:?}",
            self.packet_header.len,
            self.packet_header.ts.tv_sec,
            IPlayer::get_source_destination(self.internet.unwrap()),
            AppLayer::get_app_info(self.application.unwrap()),
            self.ethernet
        )
    }
}

fn read_capture_file<P>(path: P) -> Capture<Offline>
where
    P: AsRef<Path>,
{
    Capture::from_file(path).unwrap()
}

fn process_packet(packet: Packet) {
    let (remaining, ethernet_frame) = parse_ethernet_frame(&packet.data).unwrap();

    let (remaining, internet_frame) = match ethernet_frame.ethertype {
        EtherType::IPv4 => {
            let (a, b) = parse_ipv4_header(&remaining).unwrap();
            (Some(a), Some(IPlayer::V4(b)))
        }
        EtherType::IPv6 => {
            let (a, b) = parse_ipv6_header(&remaining).unwrap();
            (Some(a), Some(IPlayer::V6(b)))
        }
        _ => (None, None),
    };

    if internet_frame.is_none() {
        return;
    }

    let internet_frame_val = internet_frame.unwrap();

    let app_protocol = match internet_frame_val {
        IPlayer::V4(iframe) => iframe.protocol,
        IPlayer::V6(iframe) => iframe.next_header,
    };

    let app_frame = match app_protocol {
        pktparse::ip::IPProtocol::TCP => {
            let (_a, b) = parse_tcp_header(&remaining.unwrap()).unwrap();
            Some(AppLayer::TCP(b))
        }
        pktparse::ip::IPProtocol::UDP => {
            let (_a, b) = parse_udp_header(&remaining.unwrap()).unwrap();
            Some(AppLayer::UDP(b))
        }
        _ => None,
    };

    if app_frame.is_none() {
        return;
    }

    let cap_frame = CapturedFrame {
        packet_header: *packet.header,
        ethernet: Some(ethernet_frame),
        internet: Some(internet_frame_val),
        application: Some(app_frame.unwrap()),
    };

    cap_frame.print_status_line();
}

struct PcapOptions {
    file: Option<String>,
    interface: Option<String>,
    savefile: Option<String>,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut opts = getopt::Parser::new(&args, "f:i:o:");

    let mut capt: Capture<dyn Activated>;

    let mut pcap_options: PcapOptions = PcapOptions {
        file: None,
        interface: None,
        savefile: None,
    };

    loop {
        match opts.next().transpose().unwrap() {
            None => {
                break;
            }
            Some(opt) => match opt {
                Opt('f', Some(arg)) => pcap_options.file = Some(arg),
                Opt('i', Some(arg)) => pcap_options.interface = Some(arg),
                Opt('o', Some(arg)) => pcap_options.savefile = Some(arg),
                _ => unreachable!(),
            },
        };
    }

    if pcap_options.file.is_none() && pcap_options.interface.is_none() {
        println!("Help string");
        exit(0);
    }

    if pcap_options.file.is_some() {
        capt = read_capture_file(pcap_options.file.unwrap()).into();
    } else {
        let dev_list = Device::list().unwrap();

        let dev = dev_list
            .iter()
            .find(|&dev| dev.name == pcap_options.interface.clone().unwrap())
            .unwrap();

        capt = dev.clone().open().unwrap().into()
    }

    while let Ok(packet) = capt.next_packet() {
        process_packet(packet);
    }

    let savefile = if pcap_options.savefile.is_some() {
        let savefile_mut = capt.savefile(pcap_options.savefile.unwrap()).unwrap();
        &mut Some(savefile_mut)
    } else {
        &mut None
    };

    while let Ok(packet) = capt.next_packet() {
        match savefile {
            Some(file) => file.write(&packet),
            None => (),
        }
    }
}
