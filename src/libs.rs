use anyhow::Result;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use std::collections::HashSet;
use std::fs::read_dir;

pub mod openssl;

pub enum Libs<'a> {
    OpenSSL(openssl::OpenSSL<'a>),
}

const LIB_PATHS: [&str; 2] = ["/usr/lib32", "/usr/lib64"];

pub fn find_libs(name: &str) -> Result<HashSet<String>> {
    let mut libs = HashSet::new();

    for path in LIB_PATHS.iter() {
        let dir = match read_dir(path) {
            Ok(path) => path,
            Err(_) => continue,
        };

        for entry in dir {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(_) => continue,
            };

            if !path.is_symlink() && path.is_file() {
                let path = path.to_str().unwrap();
                if path.contains(name) {
                    libs.insert(path.to_string());
                }
            }
        }
    }

    Ok(libs)
}

pub fn get_offset(lib_path: &str, fn_name: &str) -> Result<usize> {
    let path = std::path::PathBuf::from(lib_path);
    let file_data = std::fs::read(path)?;
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice)?;

    let common = file.find_common_data()?;
    let (dynsyms, strtab) = (common.dynsyms.unwrap(), common.dynsyms_strs.unwrap());
    let hash_table = common.gnu_hash.unwrap();

    let (_sym_idx, sym) = hash_table
        .find(fn_name.as_bytes(), &dynsyms, &strtab)?
        .unwrap();

    Ok(sym.st_value as usize)
}
