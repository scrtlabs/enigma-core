use base64;
use common_u::errors;
use failure::Error;
use hex::FromHex;
use sgx_types::*;
use std::thread::sleep;
use std::{self, time};

extern "C" {
    pub fn ecall_get_registration_quote(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                                        target_info: *const sgx_target_info_t, report: *mut sgx_report_t) -> sgx_status_t;

    pub fn sgx_init_quote(p_target_info: *mut sgx_target_info_t, p_gid: *mut sgx_epid_group_id_t) -> sgx_status_t;

    pub fn sgx_calc_quote_size(p_sig_rl: *const uint8_t, sig_rl_size: uint32_t, p_quote_size: *mut uint32_t) -> sgx_status_t;

    pub fn sgx_get_quote(p_report: *const sgx_report_t, quote_type: sgx_quote_sign_type_t,
                         p_spid: *const sgx_spid_t, p_nonce: *const sgx_quote_nonce_t, p_sig_rl: *const uint8_t,
                         sig_rl_size: uint32_t, p_qe_report: *mut sgx_report_t, p_quote: *mut sgx_quote_t,
                         quote_size: uint32_t) -> sgx_status_t;
}

pub fn retry_quote(eid: sgx_enclave_id_t, spid: &str, times: usize) -> Result<String, Error> {
    let mut quote = String::new();
    for _ in 0..times {
        quote = match produce_quote(eid, spid) {
            Ok(q) => q,
            Err(e) => {
                println!("problem with quote, trying again: {:?}", e);
                continue;
            }
        };

        if !quote.chars().all(|cur_c| cur_c == 'A') {
            return Ok(quote);
        } else {
            sleep(time::Duration::new(5, 0));
        }
    }
    Err(errors::QuoteErr { message: quote }.into())
}

fn check_busy<T, F>(func: F) -> (sgx_status_t, T)
where F: Fn() -> (sgx_status_t, T) {
    loop {
        let (status, rest) = func();
        if status != sgx_status_t::SGX_ERROR_BUSY {
            return (status, rest);
        }
        sleep(time::Duration::new(1, 500_000_000));
    }
}

#[logfn(TRACE)]
pub fn produce_quote(eid: sgx_enclave_id_t, spid: &str) -> Result<String, Error> {
    let spid = spid.from_hex()?;
    let mut id = [0; 16];
    id.copy_from_slice(&spid);
    let spid: sgx_spid_t = sgx_spid_t { id };

    // create quote
    let (status, (target_info, _gid)) = check_busy(|| {
        let mut target_info = sgx_target_info_t::default();
        let mut gid = sgx_epid_group_id_t::default();
        let status = unsafe { sgx_init_quote(&mut target_info, &mut gid) };
        (status, (target_info, gid))
    });
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(errors::SgxError { status, function: "sgx_init_quote" }.into());
    }

    // create report
    let (status, (report, retval)) = check_busy(move || {
        let mut report = sgx_report_t::default();
        let mut retval = sgx_status_t::SGX_SUCCESS;
        let status = unsafe { ecall_get_registration_quote(eid, &mut retval, &target_info, &mut report) };
        (status, (report, retval))
    });
    if status != sgx_status_t::SGX_SUCCESS || retval != sgx_status_t::SGX_SUCCESS {
        return Err(errors::SgxError { status, function: "ecall_get_registration_quote" }.into());
    }


    // calc quote size
    let (status, quote_size) = check_busy(|| {
        let mut quote_size: u32 = 0;
        let status = unsafe { sgx_calc_quote_size(std::ptr::null(), 0, &mut quote_size) };
        (status, quote_size)
    });
    if status != sgx_status_t::SGX_SUCCESS || quote_size == 0 {
        return Err(errors::SgxError { status, function: "sgx_calc_quote_size" }.into());
    }

    // get the actual quote
    let (status, the_quote) = check_busy(|| {
        let mut the_quote = vec![0u8; quote_size as usize].into_boxed_slice();
        // all of this is according to this: https://software.intel.com/en-us/sgx-sdk-dev-reference-sgx-get-quote
        // the `p_qe_report` is null together with the nonce because we don't have an ISV enclave that needs to verify this
        // and we don't care about replay attacks because the signing key will stay the same and that's what's important.
        let status = unsafe {
            sgx_get_quote(&report,
                          sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
                          &spid,
                          std::ptr::null(),
                          std::ptr::null(),
                          0,
                          std::ptr::null_mut(),
                          the_quote.as_mut_ptr() as *mut sgx_quote_t,
                          quote_size,
            )
        };
        (status, the_quote)
    });
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(errors::SgxError { status, function: "sgx_get_quote" }.into());
    }

    let encoded_quote = base64::encode(&the_quote);
    Ok(encoded_quote)
}
