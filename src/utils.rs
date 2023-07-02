use libbpf_rs::PrintLevel;
use log::{debug, info, warn};

pub fn print_hexdump(data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("{:08x}  ", i * 16);
        for byte in chunk {
            print!("{:02x} ", byte);
        }
        for byte in chunk {
            if *byte >= 0x20 && *byte <= 0x7e {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!();
    }
}

pub fn libbpf_print_cb(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => debug!("{}", msg),
        PrintLevel::Info => info!("{}", msg),
        PrintLevel::Warn => warn!("{}", msg),
    };
}
