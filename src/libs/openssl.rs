use anyhow::Result;
use libbpf_rs::Link;
use phf::phf_map;
use plain::Plain;
use std::collections::HashMap;
use std::vec;

use crate::utils::print_hexdump;

#[path = "../bpf/.output/openssl.skel.rs"]
mod openssl_skel;
use openssl_skel::{openssl_bss_types, OpensslSkel, OpensslSkelBuilder};

type DataEvent = openssl_bss_types::ssl_data_event;
unsafe impl Plain for DataEvent {}
type CloseEvent = openssl_bss_types::ssl_close_event;
unsafe impl Plain for CloseEvent {}

struct Probe<'a> {
    func: &'a str,
    ret: bool,
}

static OPENSSL_PROBS: phf::Map<&'static str, Probe> = phf_map! {
    "SSL_write" => Probe {
        func: "SSL_write",
        ret: false,
    },
    "SSL_read" => Probe {
        func: "SSL_read",
        ret: false,
    },
    "SSL_read_ret" => Probe {
        func: "SSL_read",
        ret: true,
    },
    "SSL_shutdown" => Probe {
        func: "SSL_shutdown",
        ret: false,
    },
    "SSL_clear" => Probe {
        func: "SSL_clear",
        ret: false,
    },
    "SSL_free" => Probe {
        func: "SSL_free",
        ret: false,
    },
};

struct Session {
    pub pid: i32,
    pub comm: String,
    pub write_buf: Vec<u8>,
    pub read_buf: Vec<u8>,
}

pub struct OpenSSL<'a> {
    pub path: String,
    skel: OpensslSkel<'a>,
    links: vec::Vec<Link>,
    sessions: HashMap<u64, Session>,
}

impl<'a> OpenSSL<'a> {
    pub fn new(path: &str) -> Result<Self> {
        let skel_builder = OpensslSkelBuilder::default();
        let open_skel = skel_builder.open()?;
        let skel = open_skel.load()?;

        Ok(Self {
            path: path.to_string(),
            skel: skel,
            links: vec![],
            sessions: HashMap::new(),
        })
    }

    pub fn attach_uprobes(&mut self) -> Result<()> {
        for prog in self.skel.obj.progs_iter_mut() {
            let prob = OPENSSL_PROBS.get(prog.name()).unwrap();
            let offset = super::get_offset(&self.path, prob.func);
            let path = &self.path;
            let link = prog.attach_uprobe(prob.ret, -1, path, offset?).unwrap();
            self.links.push(link);
        }

        Ok(())
    }

    pub fn set_ringbuf_cb<'b>(
        &'b mut self,
        builder: &mut libbpf_rs::RingBufferBuilder<'b>,
    ) -> Result<()> {
        let sessions = &mut self.sessions;
        builder.add(self.skel.maps().events(), move |data| {
            OpenSSL::event_handler(data, sessions)
        })?;

        Ok(())
    }

    fn event_handler(data: &[u8], sessions: &mut HashMap<u64, Session>) -> ::std::os::raw::c_int {
        let mut event = DataEvent::default();
        match plain::copy_from_bytes(&mut event, data) {
            Ok(_) => match sessions.get_mut(&event.ctx) {
                Some(session) => {
                    if event.direction == openssl_bss_types::e_ssl_direction::SSL_WRITE {
                        session
                            .write_buf
                            .extend_from_slice(&event.buf[..event.size as usize]);
                    } else {
                        session
                            .read_buf
                            .extend_from_slice(&event.buf[..event.size as usize]);
                    }
                }
                None => {
                    let mut session = Session {
                        pid: event.pid,
                        comm: unsafe { std::ffi::CStr::from_ptr(event.comm.as_ptr()) }
                            .to_string_lossy()
                            .to_string(),
                        write_buf: vec![],
                        read_buf: vec![],
                    };
                    if event.direction == openssl_bss_types::e_ssl_direction::SSL_WRITE {
                        session
                            .write_buf
                            .extend_from_slice(&event.buf[..event.size as usize]);
                    } else {
                        session
                            .read_buf
                            .extend_from_slice(&event.buf[..event.size as usize]);
                    }
                    sessions.insert(event.ctx, session);
                }
            },
            Err(_) => {
                let mut event = CloseEvent::default();
                match plain::copy_from_bytes(&mut event, data) {
                    Ok(_) => match sessions.get(&event.ctx) {
                        Some(session) => {
                            if session.write_buf.len() > 0 {
                                println!("OUTGOING - {}[{}]", session.comm, session.pid,);
                                print_hexdump(&session.write_buf);
                            }
                            if session.read_buf.len() > 0 {
                                println!("INCOMING - {}[{}]", session.comm, session.pid,);
                                print_hexdump(&session.read_buf);
                            }
                            sessions.remove(&event.ctx);
                        }
                        None => {}
                    },
                    Err(_) => {
                        return 1;
                    }
                }
            }
        }

        return 0;
    }
}
