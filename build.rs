use libbpf_cargo::SkeletonBuilder;
use std::fs::{create_dir_all, read_dir, write};
use std::io;
use std::path::Path;
use std::process::Command;

const BPF_OUT: &str = "./src/bpf/.output";

fn main() -> io::Result<()> {
    create_dir_all(BPF_OUT)?;

    let vmlinux = Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()
        .expect("failed to execute process");

    write(Path::new(BPF_OUT).join("vmlinux.h"), vmlinux.stdout)?;

    let libraries_path = Path::new("./src/bpf");
    if libraries_path.is_dir() {
        for library in read_dir(libraries_path)? {
            let library = library?;
            let library_path = library.path();

            if library.path().is_file() {
                let skel_name = library_path.file_stem().unwrap();
                let skel = Path::new(BPF_OUT).join(skel_name).with_extension("skel.rs");

                SkeletonBuilder::new()
                    .source(&library_path)
                    .build_and_generate(&skel)
                    .expect("bpf compilation failed");

                println!("cargo:rerun-if-changed={}", library_path.to_str().unwrap());
            }
        }
    }

    Ok(())
}
