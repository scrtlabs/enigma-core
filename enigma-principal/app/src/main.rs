extern crate sgx_types;
extern crate sgx_urts;
extern crate base64;
extern crate rlp;
extern crate enigma_tools_u;
extern crate failure;
extern crate serde_json;

//web3 
extern crate web3;
extern crate rustc_hex;
//tokio
extern crate tokio_core;
// enigma modules
mod esgx;
use sgx_types::{uint8_t, uint32_t};
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use esgx::equote;
mod boot_network;
pub use esgx::general::ocall_get_home;

extern { fn ecall_get_signing_pubkey(eid: sgx_enclave_id_t, pubkey: &mut [u8; 64]) -> sgx_status_t; }
extern { fn ecall_get_random_seed(eid: sgx_enclave_id_t, retval: &mut sgx_status_t, rand_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> sgx_status_t; }


/// Returns a 32 bytes signed random seed.
/// # Examples
/// ```
/// let enclave = esgx::general::init_enclave().unwrap();
/// let (rand_seed, sig) = get_signed_random(enclave.geteid());
/// ```
fn get_signed_random(eid: sgx_enclave_id_t) -> ([u8; 32], [u8; 65]) {
    let mut rand_out: [u8; 32] = [0; 32];
    let mut sig_out: [u8; 65] = [0; 65];
    let mut retval = sgx_status_t::default();
    unsafe { ecall_get_random_seed(eid, &mut retval, &mut rand_out, &mut sig_out); }
    assert_eq!(retval, sgx_status_t::SGX_SUCCESS); // TODO: Replace with good Error handling.
    (rand_out, sig_out)
}


#[allow(unused_variables, unused_mut)]
fn main() {

    
    /* this is an example of initiating an enclave */

    let enclave = match esgx::general::init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };
    let eid = enclave.geteid();
    boot_network::registration::run(eid);
// //    let spid = String::from("3DDB338BD52EE314B01F1E4E1E84E8AA");
//     let spid = String::from("1601F95C39B9EA307FEAABB901ADC3EE");
//     let tested_encoded_quote = equote::produce_quote(&enclave, &spid);
//     println!("{:?}", &tested_encoded_quote);

//     let mut pubme: [u8; 64] = [0; 64];
//     unsafe {ecall_get_signing_pubkey(enclave.geteid(), &mut pubme)};
//     println!("Returned Pub: {:?}", &pubme[..]);

//     let (rand_seed, sig) = get_signed_random(enclave.geteid());
//     println!("Random Outside Enclave:{:?}", &rand_seed[..]);
//     println!("Signature Outside Enclave: {:?}\n", &sig[..]);
     enclave.destroy();
}


#[cfg(test)]
mod tests {
    use esgx::general::init_enclave;
    use sgx_types::{sgx_enclave_id_t, sgx_status_t};
    extern { fn ecall_run_tests(eid: sgx_enclave_id_t) -> sgx_status_t; }

    #[test]
    pub fn test_enclave_internal() {
        // initiate the enclave
        let enclave = match init_enclave() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            },
            Err(x) => {
                println!("[-] Init Enclave Failed {}!", x.as_str());
                assert_eq!(0,1);
                return;
            },
        };
        let ret = unsafe { ecall_run_tests(enclave.geteid()) };
        assert_eq!(ret,sgx_status_t::SGX_SUCCESS);
        enclave.destroy();
    }
}
