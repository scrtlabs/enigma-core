use failure::Error;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use web3::types::{Bytes, H256, U256};

use common_u::errors::EnclaveFailError;
use enigma_tools_u::web3_utils::provider_types::{ encode, EpochSeed, InputWorkerParams};
use enigma_types::EnclaveReturn;

extern {
    fn ecall_set_worker_params(eid: sgx_enclave_id_t, retval: &mut EnclaveReturn,
                               worker_params_rlp: *const u8, worker_params_rlp_len: usize,
                               rand_out: &mut [u8; 32], nonce_out: &mut [u8; 32],
                               sig_out: &mut [u8; 65]) -> sgx_status_t;
}

/// Returns an EpochSeed object 32 bytes signed random seed and an incremented account nonce.
/// # Examples
/// ```
/// let enclave = esgx::general::init_enclave().unwrap();
/// let worker_params = web3.get_worker_params(block_number);
/// let sig = set_worker_params(enclave.geteid(), worker_params).unwrap();
/// ```
pub fn set_worker_params(eid: sgx_enclave_id_t, worker_params: InputWorkerParams) -> Result<EpochSeed, Error> {
    let mut retval: EnclaveReturn = EnclaveReturn::Success;
    let mut nonce_out: [u8; 32] = [0; 32];
    let mut rand_out: [u8; 32] = [0; 32];
    let mut sig_out: [u8; 65] = [0; 65];
    // Serialize the receipt into RLP
    let worker_params_rlp = encode(&worker_params);
    let mut sig_out: [u8; 65] = [0; 65];
    let status = unsafe {
        ecall_set_worker_params(
            eid,
            &mut retval,
            worker_params_rlp.as_ptr() as *const u8,
            worker_params_rlp.len(),
            &mut rand_out,
            &mut nonce_out,
            &mut sig_out,
        )
    };
    if retval != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        return Err(EnclaveFailError { err: retval, status }.into());
    }
    Ok(EpochSeed {
        seed: U256::from_big_endian(&rand_out),
        nonce: U256::from_big_endian(&nonce_out),
        sig: Bytes(sig_out.to_vec())
    })
}

#[cfg(test)]
pub mod tests {
    #![allow(dead_code, unused_assignments, unused_variables)]

    use ethabi::Uint;
    use rustc_hex::ToHex;
    use sgx_urts::SgxEnclave;
    use web3::types::{Bytes, Address};
    use esgx::general::init_enclave_wrapper;

    use super::*;

    // From Truffle
    // TODO: This won't pass seed verification
    const EXAMPLE_RECEIPT: &'static str = r#"{"transactionHash":"0x33c3c14e3cd8764911d243e67c229adf7279b3e920a3dbb317ff989946ad47bb","transactionIndex":"0x0","blockHash":"0x0c296afc063c64e6d439e68aee7e21711acae300b8c463b72a9eaa2fa6f01953","blockNumber":"0x6c","from":"0x9dc9f269cea8b616df485d3da206df08175493fa","to":"0xefa854bef1878fef38c9fa9eda734bca4461703b","gasUsed":"0xc7d32","cumulativeGasUsed":"0xc7d32","contractAddress":"0xeFA854beF1878feF38c9fa9EDa734BcA4461703B","logs":[{"logIndex":"0x0","transactionIndex":"0x0","transactionHash":"0x33c3c14e3cd8764911d243e67c229adf7279b3e920a3dbb317ff989946ad47bb","blockHash":"0x0c296afc063c64e6d439e68aee7e21711acae300b8c463b72a9eaa2fa6f01953","blockNumber":"0x6c","address":"0xeFA854beF1878feF38c9fa9EDa734BcA4461703B","data":"0x000000000000000000000000000000000000000000000000000000000000b084000000000000000000000000000000000000000000000000000000000000006c00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000b4e4d9c2234d712d9bf6c9445f1cc402106bb02b0000000000000000000000005fa80853fab1c9b171968b7ea26172c981d870e3000000000000000000000000669b6a7969da392875bb58e17a83f712adac476e000000000000000000000000e8d52b919b9cf20e96b378166d94a7aac7cd0423000000000000000000000000bec594fffd4546544309f67eb4121606c5cfca3d000000000000000000000000761751ad640d7b9741a93acd755f6ba83be88e8e000000000000000000000000b25f28b6e9b316ef95060a47ed5ee80990fcc7840000000000000000000000002c4d2745716d18a3f4e8f7592ace4ba6bcf2448d000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000014f46b040000000000000000000000000000000000000000000000000000000002540be400000000000000000000000000000000000000000000000000000000003b9aca00000000000000000000000000000000000000000000000000000000007735940000000000000000000000000000000000000000000000000000000002540be40000000000000000000000000000000000000000000000000000000004a817c80000000000000000000000000000000000000000000000000000000000ee6b280000000000000000000000000000000000000000000000000000000002540be400","topics":["0xcdfdbdd264b9f454c9c98dc0d0b5c0a0f683c704db2233ff53b4d4f826c790cb"],"type":"mined","id":"log_bc15b82f"}],"status":"0x01","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000","v":"0x1c","r":"0xb43597804dd468ed6a941c204ca34908e7ab1c82899534114aa80fc73c32f5ba","s":"0x1df8fbbf2f0c393f3111b243cfca6b0b44d0cf0cf6a6ebb8908a1890bba78cf8"}"#;
    const EXAMPLE_BLOCK: &'static str = r#"{"number":"0x6c","hash":"0x0c296afc063c64e6d439e68aee7e21711acae300b8c463b72a9eaa2fa6f01953","parentHash":"0x88e10ea2b9be2e3285e96ce427d4fb6de93ab334279d5ded8c71302dcbc6b6aa","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000","transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","stateRoot":"0x59e01b2b2508581d30d755200675f35fc53d1a73e9fc0d9563c63b49adc0b8aa","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","miner":"0x0000000000000000000000000000000000000000","difficulty":"0x0","totalDifficulty":"0x0","extraData":"0x","size":"0x3e8","gasLimit":"0x6691b7","gasUsed":"0xc7d32","timestamp":"0x5c2fcf74","transactions":["0x33c3c14e3cd8764911d243e67c229adf7279b3e920a3dbb317ff989946ad47bb"],"uncles":[]}"#;

    fn init_enclave() -> SgxEnclave {
        let enclave = match init_enclave_wrapper() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            }
            Err(x) => {
                panic!("[-] Init Enclave Failed {}!", x.as_str());
            }
        };
        enclave
    }

    pub(crate) fn set_mock_worker_params(eid: sgx_enclave_id_t) -> (EpochSeed) {
        let worker_params = InputWorkerParams{
            block_number: U256::from(1),
            workers: vec![Address::from("f25186B5081Ff5cE73482AD761DB0eB0d25abfBF")],
            stakes: vec![U256::from(1)]
        };
        set_worker_params(eid, worker_params).unwrap()
    }


    #[test]
    fn test_set_mock_worker_params() {
        let enclave = init_enclave();
        let epoch_seed = set_mock_worker_params(enclave.geteid());
        println!("Got epoch seed params: {:?}", epoch_seed);
        assert_eq!(epoch_seed.nonce, Uint::from(0));

        enclave.destroy();
    }
}
