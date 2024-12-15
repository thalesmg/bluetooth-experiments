use std::ffi::CStr;

use libc::uint8_t;
use nix::errno::Errno;

pub mod bindings;

use bindings::{
    hci_get_route, hci_inquiry, hci_open_dev, hci_read_class_of_dev, hci_read_inquiry_mode, hci_read_inquiry_scan_type, hci_read_local_name, hci_read_remote_name, hci_request, hci_send_req, hci_write_class_of_dev, hci_write_inquiry_mode, hci_write_inquiry_scan_type, hci_write_local_name, inquiry_info, IREQ_CACHE_FLUSH, OCF_READ_PAGE_SCAN_TYPE, OCF_RESET, OCF_SET_EVENT_FLT, OCF_WRITE_PAGE_SCAN_TYPE, OCF_WRITE_SCAN_ENABLE, OGF_HOST_CTL
};

const MAX_NAME_LENGTH: i32 = 248;
const MAX_INQUIRIES: i32 = 255;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct ReadPageScanTypeRp {
    status: u8,
    type_: u8,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct WritePageScanTypeCp {
    type_: u8,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct WritePageScanTypeRp {
    status: u8,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct WriteScanEnableCp {
    type_: u8,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct WriteScanEnableRp {
    status: u8,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SetEventFilterCp {
    type_: u8,
    condition: u8,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SetEventFilterRp {
    status: u8,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct ResetRp {
    status: u8,
}

type bt_socket = i32;
type timeout = i32;

unsafe fn hci_read_page_scan_type(
    bt_socket: bt_socket,
    timeout: timeout,
) -> Option<ReadPageScanTypeRp> {
    let mut rp = std::mem::zeroed::<ReadPageScanTypeRp>();
    let p_rp = &mut rp as *mut _ as *mut _;
    let mut req = std::mem::zeroed::<hci_request>();
    req = hci_request {
        ogf: OGF_HOST_CTL as _,
        ocf: OCF_READ_PAGE_SCAN_TYPE as _,
        rparam: p_rp,
        rlen: size_of::<ReadPageScanTypeRp>() as _,
        ..req
    };
    if hci_send_req(bt_socket, &mut req, timeout) < 0 || rp.status == nix::Error::EIO as _ {
        None
    } else {
        Some(rp)
    }
}

unsafe fn hci_write_page_scan_type(
    bt_socket: bt_socket,
    type_: u8,
    timeout: timeout,
) -> Option<()> {
    let mut cp = WritePageScanTypeCp { type_ };
    let p_cp = &mut cp as *mut _ as *mut _;
    let mut rp = std::mem::zeroed::<WritePageScanTypeRp>();
    let p_rp = &mut rp as *mut _ as *mut _;
    let mut req = std::mem::zeroed::<hci_request>();
    req = hci_request {
        ogf: OGF_HOST_CTL as _,
        ocf: OCF_WRITE_PAGE_SCAN_TYPE as _,
        cparam: p_cp,
        // clen: size_of::<WritePageScanTypeCp> as _,
        clen: 1,
        rparam: p_rp,
        rlen: size_of::<WritePageScanTypeRp>() as _,
        ..req
    };
    if dbg!(hci_send_req(bt_socket, &mut req, timeout)) < 0 || rp.status == nix::Error::EIO as _ {
        None
    } else {
        Some(())
    }
}

unsafe fn hci_write_scan_enable(bt_socket: bt_socket, type_: u8, timeout: timeout) -> Option<()> {
    let mut cp = WriteScanEnableCp { type_ };
    let p_cp = &mut cp as *mut _ as *mut _;
    let mut rp = std::mem::zeroed::<WriteScanEnableRp>();
    let p_rp = &mut rp as *mut _ as *mut _;
    let mut req = std::mem::zeroed::<hci_request>();
    req = hci_request {
        ogf: OGF_HOST_CTL as _,
        ocf: OCF_WRITE_SCAN_ENABLE as _,
        cparam: p_cp,
        // clen: size_of::<WriteScanEnableCp> as _,
        clen: 1,
        rparam: p_rp,
        rlen: size_of::<WriteScanEnableRp>() as _,
        ..req
    };
    if dbg!(hci_send_req(bt_socket, &mut req, timeout)) < 0 || rp.status == nix::Error::EIO as _ {
        None
    } else {
        Some(())
    }
}

unsafe fn hci_set_event_filter(bt_socket: bt_socket, type_: u8, condition: u8, timeout: timeout) -> Option<()> {
    let mut cp = SetEventFilterCp { type_, condition };
    let p_cp = &mut cp as *mut _ as *mut _;
    let mut rp = std::mem::zeroed::<SetEventFilterRp>();
    let p_rp = &mut rp as *mut _ as *mut _;
    let mut req = std::mem::zeroed::<hci_request>();
    req = hci_request {
        ogf: OGF_HOST_CTL as _,
        ocf: OCF_SET_EVENT_FLT as _,
        cparam: p_cp,
        // clen: size_of::<SetEventFilterCp> as _,
        clen: 2,
        rparam: p_rp,
        rlen: size_of::<SetEventFilterRp>() as _,
        ..req
    };
    if dbg!(hci_send_req(bt_socket, &mut req, timeout)) < 0 || rp.status == nix::Error::EIO as _ {
        None
    } else {
        Some(())
    }
}

unsafe fn hci_reset(bt_socket: bt_socket, timeout: timeout) -> Option<()> {
    let mut rp = std::mem::zeroed::<ResetRp>();
    let p_rp = &mut rp as *mut _ as *mut _;
    let mut req = std::mem::zeroed::<hci_request>();
    req = hci_request {
        ogf: OGF_HOST_CTL as _,
        ocf: OCF_RESET as _,
        cparam: std::ptr::null_mut(),
        // clen: size_of::<SetEventFilterCp> as _,
        clen: 0,
        rparam: p_rp,
        rlen: size_of::<ResetRp>() as _,
        ..req
    };
    if dbg!(hci_send_req(bt_socket, &mut req, timeout)) < 0 || rp.status == nix::Error::EIO as _ {
        None
    } else {
        Some(())
    }
}

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

    let mut inquiry_mode: u8 = 0;
    dbg!(unsafe { hci_read_inquiry_mode(bt_socket, &mut inquiry_mode, 1_000) });
    dbg!(inquiry_mode);

    let mut class: [u8; 3] = [0; 3];
    let p_class = class.as_mut_ptr();
    dbg!(unsafe { hci_read_class_of_dev(bt_socket, p_class, 1_000) });
    println!("{:#04x?}", class);

    let mut local_name = vec![0; MAX_NAME_LENGTH as _];
    let p_local_name = local_name.as_mut_ptr();
    dbg!(unsafe { hci_read_local_name(bt_socket, MAX_NAME_LENGTH, p_local_name, 1_000) });
    let local_name = Vec::from_iter(local_name.iter().map(|i| *i as u8));
    dbg!(CStr::from_bytes_until_nul(&local_name).unwrap());

    let m_page_scan_type = unsafe { hci_read_page_scan_type(bt_socket, 1_000) };
    dbg!(m_page_scan_type);

    let mut inquiry_scan_type: u8 = 0;
    dbg!(unsafe { hci_read_inquiry_scan_type(bt_socket, &mut inquiry_scan_type, 1_000) });
    dbg!(inquiry_scan_type);



    // dbg!(unsafe { hci_reset(bt_socket, 1_000) });

    dbg!(unsafe { hci_write_inquiry_mode(bt_socket, 0x01, 1_000) });

    let write_page_scan_type_ret = unsafe { hci_write_page_scan_type(bt_socket, 1, 2_000) };
    dbg!(write_page_scan_type_ret);

    let write_inquiry_scan_type_ret = unsafe { hci_write_inquiry_scan_type(bt_socket, 1, 2_000) };
    dbg!(write_inquiry_scan_type_ret);

    let new_class = 0x000448;
    let write_class_of_dev_ret = unsafe { hci_write_class_of_dev(bt_socket, new_class, 2_000) };
    dbg!(write_class_of_dev_ret);

    let mut new_local_name = vec![0; MAX_NAME_LENGTH as _];
    new_local_name[0] = 'W' as _;
    new_local_name[1] = 'i' as _;
    new_local_name[2] = 'i' as _;
    let p_new_local_name = new_local_name.as_mut_ptr();
    let write_local_name_ret = unsafe { hci_write_local_name(bt_socket, p_new_local_name, 2_000) };
    dbg!(write_local_name_ret);

    let write_scan_enable_ret = unsafe { hci_write_scan_enable(bt_socket, 0x00, 2_000) };
    dbg!(write_scan_enable_ret);

    let write_scan_enable_ret = unsafe { hci_write_scan_enable(bt_socket, 0x02, 2_000) };
    dbg!(write_scan_enable_ret);

    let set_event_filter_ret = unsafe { hci_set_event_filter(bt_socket, 0x01, 0x00, 1_000) };
    dbg!(set_event_filter_ret);


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
    // let lap: [u8; 3] = [0x9e, 0x8b, 0x00];
    // let lap = vec![0x9e, 0x8b, 0x00];
    let lap = vec![0x00, 0x8b, 0x9e];
    dbg!(lap.as_ptr());
    let device_count = unsafe {
        hci_inquiry(
            bt_device_id,
            3,   // scan seconds
            // 255, // max inquiries
            // 0, // max inquiries
            MAX_INQUIRIES,
            // std::ptr::null(), // lap (??)
            lap.as_ptr(), // lap (??)
            &mut infos.as_mut_ptr(),
            IREQ_CACHE_FLUSH as _,
            // 0x00,
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
            dbg!("error reading remote name");
            continue;
        }
        let name_length = name.iter().position(|&c| c == 0).unwrap();
        let name = String::from_utf8_lossy(&name[..name_length]);
        dbg!(name);
    }

    dbg!(unsafe { hci_write_inquiry_scan_type(bt_socket, inquiry_scan_type, 1_000) });
    if let Some(ReadPageScanTypeRp {
        type_: page_scan_type,
        ..
    }) = m_page_scan_type
    {
        dbg!(unsafe { hci_write_page_scan_type(bt_socket, page_scan_type, 1_000) });
    }

    nix::unistd::close(bt_socket).unwrap();
}
