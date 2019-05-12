pub mod rlp;
use self::rlp::decode_args;
use enigma_crypto::{asymmetric::KeyPair, symmetric::decrypt};
use enigma_types::DhKey;
use crate::common::errors_t::{EnclaveError, EnclaveError::*, FailedTaskError::*};
use rustc_hex::FromHex;
use std::string::String;
use std::string::ToString;
use std::vec::Vec;

pub fn get_key() -> [u8; 32] {
    let _my_priv_key: Vec<u8> = "2987699a6d3a5ebd07f4caf422fad2809dcce942cd9db266ed8e2be02cf95ee9".from_hex().unwrap();
    let mut my_priv_key = [0u8; 32];
    my_priv_key.clone_from_slice(&_my_priv_key);
    let my_keys = KeyPair::from_slice(&my_priv_key).unwrap();
    let _client_pub_key: Vec<u8> = "5587fbc96b01bfe6482bf9361a08e84810afcc0b1af72a8e4520f98771ea1080681e8a2f9546e5924e18c047fa948591dba098bffaced50f97a41b0050bdab99".from_hex().unwrap();
    let mut client_pub_key = [0u8; 64];
    client_pub_key.clone_from_slice(&_client_pub_key);
    my_keys.derive_key(&client_pub_key).unwrap()
}

pub fn get_types(function: &str) -> Result<(String, String), EnclaveError> {
    let start_arg_index;
    let end_arg_index;

    match function.find('(') {
        Some(x) => start_arg_index = x,
        None => return Err(FailedTaskError(InputError { message: "'callable' signature is illegal".to_string() })),
    }

    match function.find(')') {
        Some(x) => end_arg_index = x,
        None => return Err(FailedTaskError(InputError { message: "'callable' signature is illegal".to_string() })),
    }

    Ok((function[start_arg_index + 1..end_arg_index].to_string(), String::from(&function[..start_arg_index])))
}

pub fn get_args(callable_args: &[u8], types: &[String], key: &[u8; 32]) -> Result<Vec<String>, EnclaveError> {
    decode_args(callable_args, types, key)
}

// decrypt the arguments which all are sent encrypted and return the solidity abi serialized data
pub fn decrypt_args(callable_args: &[u8], key: &DhKey) -> Result<Vec<u8>, EnclaveError>{
    // if args is empty we don't want to try decrypting the slice- it will lead to an error
    if callable_args.is_empty() {
        Ok(callable_args.to_vec())
    }
    else {
        Ok(decrypt(callable_args, key)?)
    }
}

pub fn decrypt_callable(callable: &[u8], key: &DhKey) -> Result<Vec<u8>, EnclaveError> {
    if callable.is_empty(){
        Err(FailedTaskError(InputError { message: "called function representation is empty".to_string()}))
    } else {
        Ok(decrypt(callable, key)?)
    }
}

pub fn extract_types(types: &str) -> Vec<String>{
    let mut types_vector: Vec<String> = vec![];
    let types_iterator = types.split(',');
    for each_type in types_iterator {
        types_vector.push(each_type.to_string());
    }
    types_vector
}
