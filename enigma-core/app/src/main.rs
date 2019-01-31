extern crate enigma_core_app;
pub use enigma_core_app::*;

use futures::Future;

pub use esgx::ocalls_u::{ocall_get_deltas, ocall_get_deltas_sizes, ocall_get_home, ocall_get_state, ocall_get_state_size,
                                ocall_new_delta, ocall_save_to_memory, ocall_update_state};

use networking::{constants, ipc_listener, IpcListener};

fn main() {
    let enclave = match esgx::general::init_enclave_wrapper() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };
    let server = IpcListener::new(constants::CONNECTION_STR);
    server.run(move |multi| ipc_listener::handle_message(multi, enclave.geteid())).wait().unwrap();
}

#[cfg(test)]
mod tests {

    use enigma_core_app::esgx::general::init_enclave_wrapper;
    use enigma_core_app::sgx_types::*;
    extern "C" {
        fn ecall_run_tests(eid: sgx_enclave_id_t) -> sgx_status_t;
    }

    #[test]
    pub fn test_enclave_internal() {
        // initiate the enclave
        let enclave = match init_enclave_wrapper() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            }
            Err(x) => {
                println!("[-] Init Enclave Failed {}!", x.as_str());
                assert_eq!(0, 1);
                return;
            }
        };
        let ret = unsafe { ecall_run_tests(enclave.geteid()) };

        assert_eq!(ret, sgx_status_t::SGX_SUCCESS);
        enclave.destroy();
    }
}