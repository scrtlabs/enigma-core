use sgx_types::{sgx_attributes_t, sgx_launch_token_t, sgx_misc_attribute_t, SgxResult};
use sgx_urts::SgxEnclave;
use std::{fs, io::Read, path, io::Write};
use std::path::{PathBuf, Path};
use failure::Error;

pub fn storage_dir<P: AsRef<Path>>(dir_name: P) -> Result<PathBuf, Error> {
    let mut path = dirs::home_dir().ok_or_else(|| {
        format_err!("Missing home directory")
    })?;
    trace!("Home dir is {}", path.display());
    path.push(dir_name);
    Ok(path)
}

pub fn init_enclave(token_path: &path::PathBuf, enclave_location: &str)
    -> SgxResult<(SgxEnclave)> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;

    match fs::File::open(&token_path) {
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::NotFound => info!("Enclave launch token does not exist. Will create one."),
                _ => warn!("Cannot open enclave launch token file: {}.", e)
            }
        },
        Ok(mut f) => {
            match f.read(&mut launch_token) {
                Ok(1024) => info!("Enclave launch token found."),
                _ => warn!("Enclave launch token invalid, will create a new one."),
            }
        }
    }

    // Call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t { secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 }, misc_select: 0 };
    let enclave = SgxEnclave::create(enclave_location, debug, &mut launch_token, &mut launch_token_updated, &mut misc_attr)?;

    if launch_token_updated != 0 {
        // Save the launch token if it is updated
        match fs::File::create(&token_path) {
            Ok(mut f) => match f.write_all(&launch_token) {
                Ok(_) => info!("Saved updated enclave launch token"),
                Err(e) => warn!("Failed to save updated enclave launch token: {}", e),
            },
            Err(e) => warn!("Failed to save updated enclave launch token: {}", e)
        }
        info!("Enclave launch token was updated");
    }
    Ok(enclave)
}
