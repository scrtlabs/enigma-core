use sgx_types::{sgx_attributes_t, sgx_launch_token_t, sgx_misc_attribute_t, SgxResult};
use sgx_urts::SgxEnclave;
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

pub fn init_enclave(enclave_location: &str)
    -> SgxResult<(SgxEnclave)> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;

    // Call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t { secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 }, misc_select: 0 };

    // `launch_token` and `launch_token_updated` are deprecated according to https://download.01.org/intel-sgx/linux-2.6/docs/Intel_SGX_Developer_Reference_Linux_2.6_Open_Source.pdf
    // see https://github.com/apache/incubator-teaclave-sgx-sdk/pull/163
    let enclave = SgxEnclave::create(enclave_location, debug, &mut launch_token, &mut launch_token_updated, &mut misc_attr)?;
    Ok(enclave)
}
