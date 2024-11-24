use pcap::Device;
use std::env;

struct Ethernet {
    source: [u8; 6],
    destination: [u8; 6],
    packet_type: [u8; 2],
}

impl Ethernet {
    fn from_slice(src: &[u8]) -> Result<Self, ()> {
        if src.len() < 14 {
            return Err(());
        }

        let mut destination = [0u8; 6];
        let mut source = [0u8; 6];
        let mut packet_type = [0u8; 2];

        destination.copy_from_slice(&src[0..6]);
        source.copy_from_slice(&src[6..12]);
        packet_type.copy_from_slice(&src[12..14]);

        Ok(Self {
            source,
            destination,
            packet_type,
        })
    }
}

#[derive(Debug)]
struct IPv4 {
    source: [u8; 4],
    destination: [u8; 4],
}

impl IPv4 {
    fn from_slice(src: &[u8]) -> Result<Self, ()> {
        let mut source = [0u8; 4];
        let mut destination = [0u8; 4];

        source.copy_from_slice(&src[12..16]);
        destination.copy_from_slice(&src[16..20]);

        return Ok(Self {
            source,
            destination,
        });
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("Args: {:#?}", args);

    let interface = &args[1];
    let save_file_path = if args.len() > 2 { Some(&args[2]) } else { None };

    let dev_list = Device::list().unwrap();

    let dev = dev_list.iter().find(|&dev| dev.name == *interface).unwrap();

    let mut capture = dev.clone().open().unwrap();

    while let Ok(packet) = capture.next_packet() {
        let ethernet_header = Ethernet::from_slice(&packet.data).unwrap();

        println!(
            "Ethernet Packet:\n Destination: {:x?} \n Source: {:x?} \n Type: {:x?}",
            ethernet_header.destination, ethernet_header.source, ethernet_header.packet_type
        );

        // IPv4...
        if ethernet_header.packet_type == [8, 0] {
            let ipv4_header = IPv4::from_slice(&packet.data[14..]).unwrap();
            println!("{:#?}", ipv4_header);

            break;
        }
    }

    if save_file_path.is_some() {
        println!("Saving to {}", save_file_path.unwrap());
        capture.savefile(save_file_path.unwrap()).unwrap();
    }
}
