use std::ffi::CStr;

use nix::errno::Errno;

pub mod bindings;

use bindings::{
    hci_get_route, hci_inquiry, hci_open_dev, hci_read_class_of_dev, hci_read_inquiry_mode,
    hci_read_local_name, hci_read_inquiry_scan_type,
    hci_read_remote_name, inquiry_info, IREQ_CACHE_FLUSH,
};

const MAX_NAME_LENGTH: i32 = 250;
const MAX_INQUIRIES: i32 = 255;

fn main() {
    println!("Hello, world!");

    let bt_device_id = unsafe { hci_get_route(std::ptr::null_mut()) };
    dbg!(bt_device_id);
    let bt_socket = unsafe { hci_open_dev(bt_device_id) };
    dbg!(bt_socket);

    if bt_device_id < 0 || bt_socket < 0 {
        eprintln!(
            "Failed to open default bluetooth device: {}",
            Errno::last().desc()
        );
        return;
    }

    let mut read_mode: u8 = 0;
    dbg!(unsafe { hci_read_inquiry_mode(bt_socket, &mut read_mode, 1_000) });
    dbg!(read_mode);

    let mut class: [u8; 3] = [0; 3];
    let p_class = class.as_mut_ptr();
    dbg!(unsafe { hci_read_class_of_dev(bt_socket, p_class, 1_000) });
    println!("{:#04x?}", class);

    let mut local_name = vec![0; MAX_NAME_LENGTH as _];
    let p_local_name = local_name.as_mut_ptr();
    dbg!(unsafe{ hci_read_local_name(bt_socket, MAX_NAME_LENGTH, p_local_name, 1_000) });
    let local_name = Vec::from_iter(local_name.iter().map(|i| *i as u8));
    dbg!(CStr::from_bytes_until_nul(&local_name).unwrap());

    return;

    // write page scan type - interlaced scan
    // write inquiry scan type - interlaced scan
    // write class of device - 0x400204
    // ...
    // write class of device - 0x000448
    // change local name - Wii
    // write scan enable - no scans enabled
    // write scan enable - Scan Enable: Inquiry Scan disabled/Page Scan enabled (0x02)
    // inquiry - LAP: 0x9e8b00 ; length = 3

    let mut infos = Vec::with_capacity(MAX_INQUIRIES as _);
    for _ in 0..MAX_INQUIRIES {
        unsafe {
            infos.push(std::mem::zeroed::<inquiry_info>());
        }
    }
    let lap: [u8; 3] = [0x9e, 0x8b, 0x00];
    let device_count = unsafe {
        hci_inquiry(
            bt_device_id,
            6,   // scan seconds
            255, // max inquiries
            // std::ptr::null(), // lap (??)
            lap.as_ptr(), // lap (??)
            &mut infos.as_mut_ptr(),
            IREQ_CACHE_FLUSH as _,
        )
    };
    dbg!(device_count);

    for info in infos.iter().take(device_count as _) {
        let mut name = [0u8; (MAX_NAME_LENGTH + 1) as _];
        if unsafe {
            hci_read_remote_name(
                bt_socket,
                &info.bdaddr,
                MAX_NAME_LENGTH,
                name.as_mut_ptr().cast(),
                0,
            )
        } < 0
        {
            continue;
        }
        let name_length = name.iter().position(|&c| c == 0).unwrap();
        let name = String::from_utf8_lossy(&name[..name_length]);
        dbg!(name);
    }

    nix::unistd::close(bt_socket).unwrap();
}
