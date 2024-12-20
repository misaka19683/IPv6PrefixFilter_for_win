use pnet::packet::icmpv6::Icmpv6Types;
use windivert_sys::WinDivertClose;
use windivert_sys::{self, WinDivertFlags, WinDivertLayer, WinDivertOpen, WinDivertRecv};
use std::ffi::CString;
use windivert_sys::address::WINDIVERT_ADDRESS;
use pnet::packet::{ipv6::Ipv6Packet,icmpv6::Icmpv6Packet};
use pnet::packet::Packet;

pub fn the_process() -> Result<(), String> {
    let filter_cstr=CString::new("icmp6.Type==134").expect("CString::new failed");
    let filter=filter_cstr.as_ptr();
    let layer=WinDivertLayer::Network;
    let flags=WinDivertFlags::new().set_sniff();
    let w=unsafe {
        WinDivertOpen(filter, layer, 0i16, flags)
    };
    // 初始化 `WINDIVERT_ADDRESS`
    let mut address = <WINDIVERT_ADDRESS as std::default::Default>::default(); 

    let mut packet_buffer=vec![0u8; 65535];
    let mut packet_len=0u32;



    // 设置 Ctrl+C 退出处理
    ctrlc::set_handler({
        let handle = w;
        move || {
            println!("Ctrl+C detected, cleaning up...");
            unsafe {
                WinDivertClose(handle);
            }
            println!("WinDivert handle closed. Exiting.");
            std::process::exit(0);
        }
    })
    .map_err(|_| "Failed to set Ctrl+C handler")?;
    loop {
        unsafe {
            let result=WinDivertRecv(
                w,
                packet_buffer.as_mut_ptr() as *mut _,
                packet_buffer.len() as u32,
                &mut packet_len,
                &mut address,
            );
            if result==false {
                eprintln!("Failed to receive packet.");
                continue;
            }

        }
        let packet_data=&packet_buffer[..packet_len as usize];
        if let Some(ipv6_packet) = Ipv6Packet::new(packet_data) {
            if let Some(icmpv6_packet) = Icmpv6Packet::new(ipv6_packet.payload()) {
                if icmpv6_packet.get_icmpv6_type()==Icmpv6Types::RouterAdvert{
                    println!("Received Router Advertisement Packet: {:?}", icmpv6_packet);
                    
                }
            }
            
        }
    }

}







fn main() {
    println!("Hello, world!");
    let _=the_process();
}
