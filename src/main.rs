use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::{set_print, PrintLevel};
use log::LevelFilter;
use simple_logger::SimpleLogger;
use std::time::Duration;

mod libs;
mod utils;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.debug {
        0 => SimpleLogger::new().with_level(LevelFilter::Error).init(),
        1 => SimpleLogger::new().with_level(LevelFilter::Warn).init(),
        2 => SimpleLogger::new().with_level(LevelFilter::Info).init(),
        _ => SimpleLogger::new().with_level(LevelFilter::Debug).init(),
    }
    .context("Failed to initialize logger")?;

    set_print(Some((PrintLevel::Debug, utils::libbpf_print_cb)));

    let mut libs: Vec<libs::Libs> = Vec::new();

    let openssl_libs = libs::find_libs("libssl.so").context("Looking to OpenSSL shared objects")?;
    for lib in openssl_libs.iter() {
        let lib = libs::openssl::OpenSSL::new(lib)
            .with_context(|| format!("Failed to load eBPF program for: {}", lib.as_str()))?;
        libs.push(libs::Libs::OpenSSL(lib));
    }

    let mut builder = RingBufferBuilder::new();

    for lib in libs.iter_mut() {
        match lib {
            libs::Libs::OpenSSL(lib) => {
                let lib_path = lib.path.clone();
                lib.attach_uprobes()
                    .with_context(|| format!("Failed to attach uprobes for: {}", lib_path))?;
                lib.set_ringbuf_cb(&mut builder).with_context(|| {
                    format!("Failed to set ring buffer callback for: {}", lib_path)
                })?;
            }
        }
    }

    let ringbuf = builder.build().context("Failed to build ring buffer")?;

    while ringbuf.poll(Duration::MAX).is_ok() {}

    Ok(())
}
