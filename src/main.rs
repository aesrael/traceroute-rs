use std::{net, str::FromStr};

use clap::{Arg, Command};
use dns_lookup::lookup_host;
use pnet::{
    packet::icmp::echo_request::MutableEchoRequestPacket,
    packet::icmp::IcmpTypes,
    packet::ip::IpNextHeaderProtocols,
    packet::ipv4::MutableIpv4Packet,
    packet::MutablePacket,
    transport::{icmp_packet_iter, transport_channel, TransportChannelType::Layer3},
    util,
};
use std::error::Error;
use url::Url;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

// create constat strings
const IPV4_HEADER_LEN: usize = 20;
const ICMP_HEADER_LEN: usize = 8;
const ICMP_DATA_LEN: usize = 8;
const ICMP_TOTAL_LEN: usize = IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_DATA_LEN;
const ICMP_PAYLOAD_LEN: usize = ICMP_TOTAL_LEN - IPV4_HEADER_LEN;
const IP_VERSION: u8 = 4;

fn main() -> Result<()> {
    let args = parse_cli().unwrap();
    let hostname = args.hostname;

    let protocol = Layer3(IpNextHeaderProtocols::Icmp);
    let (mut sender, mut receiver) = transport_channel(1024, protocol)?;

    let dest_addr = get_ipv4_address(&hostname)?;

    let mut recv = icmp_packet_iter(&mut receiver);
    let mut prev_hop_addr = None;

    for ttl in 0..args.hops {
        let mut buffer_ip = vec![0; ICMP_TOTAL_LEN];
        let mut buffer_icmp = vec![0; ICMP_TOTAL_LEN];

        let icmp_packet = create_packet(dest_addr, ttl, &mut buffer_ip, &mut buffer_icmp)?;

        sender.send_to(icmp_packet, net::IpAddr::V4(dest_addr))?;

        if let Ok((_, addr)) = recv.next() {
            //  if the host hit is a repeat, we have a loop, destination reached,
            if Some(addr) == prev_hop_addr {
                println!("Reached address: {}", addr.to_string());
                return Ok(());
            }

            prev_hop_addr = Some(addr);
            println!("TTL: {} - {}", ttl, addr.to_string());
        }
    }
    Ok(())
}

#[derive(Debug)]
struct AppArgs {
    hostname: String,
    hops: u8,
}

fn create_packet<'a>(
    dest: net::Ipv4Addr,
    ttl: u8,
    buffer_ip: &'a mut [u8],
    buffer_icmp: &'a mut [u8],
) -> Result<MutableIpv4Packet<'a>> {
    let mut ipv4_packet = MutableIpv4Packet::new(buffer_ip).unwrap();

    ipv4_packet.set_version(IP_VERSION);
    ipv4_packet.set_header_length(IPV4_HEADER_LEN as u8);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN) as u16);
    ipv4_packet.set_destination(dest);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);

    let mut icmp_packet = MutableEchoRequestPacket::new(buffer_icmp).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);

    let checksum = util::checksum(icmp_packet.packet_mut(), 2);
    icmp_packet.set_checksum(checksum);
    ipv4_packet.set_payload(icmp_packet.packet_mut());

    Ok(ipv4_packet)
}

fn parse_cli() -> Result<AppArgs> {
    let matches = Command::new("traceroute")
        .version("0.0.1")
        .arg(
            Arg::new("hostname")
                .help("Hostname to trace")
                .required(true)
                .index(1)
                .value_hint(clap::ValueHint::Url),
        )
        .arg(
            Arg::new("hops")
                .help("Number of hops to trace")
                .required(true)
                .index(2),
        )
        .get_matches();

    let app_args = {
        let hostname = matches.value_of("hostname").unwrap().to_string();
        let hops = matches
            .value_of("hops")
            .unwrap_or("64")
            .parse::<u8>()
            .unwrap();

        AppArgs { hostname, hops }
    };
    Ok(app_args)
}

fn get_ipv4_address(hostname: &str) -> Result<net::Ipv4Addr> {
    let host = Url::parse(hostname).unwrap();
    let host = host.host_str().unwrap();
    let ips: Vec<std::net::IpAddr> = lookup_host(host).unwrap();

    let ipv4_addr = ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .expect("No IPv4 address found");

    let dest_addr =
        net::Ipv4Addr::from_str(&ipv4_addr.to_string()).expect("Could not parse IPv4 address");

    Ok(dest_addr)
}
