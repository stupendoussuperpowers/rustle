use pcap::{Device, PacketHeader};
use pktparse::{
    ethernet::{self, parse_ethernet_frame, EtherType, EthernetFrame},
    ipv4::parse_ipv4_header,
    ipv6::parse_ipv6_header,
    tcp::parse_tcp_header,
    udp::UdpHeader,
};

use pktparse::ip::IPProtocol::{TCP, UDP};
use pktparse::ipv4::IPv4Header;
use pktparse::ipv6::IPv6Header;

use pktparse::tcp::TcpHeader;

use std::env;

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
            _ => format!(""),
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
            "{} {}  {}  {}",
            self.packet_header.len,
            self.packet_header.ts.tv_sec,
            IPlayer::get_source_destination(self.internet.unwrap()),
            AppLayer::get_app_info(self.application.unwrap())
        )
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let interface = &args[1];

    let dev_list = Device::list().unwrap();

    let dev = dev_list.iter().find(|&dev| dev.name == *interface).unwrap();

    let mut capture = dev.clone().open().unwrap();

    let savefile = if args.len() > 2 {
        let savefile_mut = capture.savefile(&args[2]).unwrap();
        &mut Some(savefile_mut)
    } else {
        &mut None
    };

    while let Ok(packet) = capture.next_packet() {
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
            continue;
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
            _ => None,
        };

        if app_frame.is_none() {
            continue;
        }

        let cap_frame = CapturedFrame {
            packet_header: *packet.header,
            ethernet: Some(ethernet_frame),
            internet: Some(internet_frame_val),
            application: Some(app_frame.unwrap()),
        };

        cap_frame.print_status_line();

        match savefile {
            Some(file) => file.write(&packet),
            None => (),
        }
    }
}
