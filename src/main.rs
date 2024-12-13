use nix::errno::Errno;

pub mod bindings;

use bindings::{
    hci_get_route,
    hci_open_dev,
    hci_read_inquiry_mode,
    hci_read_class_of_dev,
    hci_inquiry,
    inquiry_info,
    IREQ_CACHE_FLUSH};

fn main() {
    println!("Hello, world!");

    let bt_device_id = unsafe {
        hci_get_route(std::ptr::null_mut())
    };
    dbg!(bt_device_id);
    let bt_socket = unsafe {
        hci_open_dev(bt_device_id)
    };
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

    // return;

    // write page scan type - interlaced scan
    // write inquiry scan type - interlaced scan
    // write class of device - 0x400204
    // ...
    // write class of device - 0x000448
    // change local name - Wii
    // write scan enable - no scans enabled
    // write scan enable - Scan Enable: Inquiry Scan disabled/Page Scan enabled (0x02)
    // inquiry - LAP: 0x9e8b00 ; length = 3

    const MAX_INQUIRIES: i32 = 255;
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
            6, // scan seconds
            255, // max inquiries
            // std::ptr::null(), // lap (??)
            lap.as_ptr(), // lap (??)
            &mut infos.as_mut_ptr(),
            IREQ_CACHE_FLUSH as _,
        )
    };
    dbg!(device_count);
    nix::unistd::close(bt_socket).unwrap();
}
