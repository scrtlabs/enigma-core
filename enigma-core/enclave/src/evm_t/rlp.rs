
use rlp::{RlpStream, UntrustedRlp};
use hexutil::read_hex;
use std::str::from_utf8;
use std::string::ToString;
use rlp::DecoderError;
use std::vec::Vec;
use std::string::String;
use cryptography_t::symmetric::{decrypt, encrypt};
use common::utils_t::{ToHex, FromHex};
use evm_t::get_key;
use common::errors_t::EnclaveError;

fn convert_undecrypted_value_to_string(rlp: &UntrustedRlp, is_uint: bool) -> String{
    let result: String;
    let string_result: Result<String, DecoderError> = rlp.as_val();
    result = match string_result{
        Ok(v) => {
            if is_uint {
                complete_to_u256(v.clone())
            }
            else {
                v.clone()
            }
        },
        Err(_e) => {
            let num_result: Result<u32, DecoderError> = rlp.as_val();
            match num_result{
                Ok(v) => v.to_string(),
                Err(_e) => "".to_string(),
            }
        },
    };
    result
}

pub fn complete_to_u256(num: String) -> String{
    let mut result: String = "".to_string();
    for i in num.len()..64 {
        result.push('0');
    }
    result.push_str(&num);
    result
}

fn decrypt_rlp(rlp: &UntrustedRlp, result: & mut String, key: &[u8], is_uint: bool) {
    if rlp.is_list(){
        result.push_str("[");
        let iter = rlp.iter();
        for item in iter{
            decrypt_rlp(&item, result, key, is_uint);
            result.push_str(",");
        }
        //Replace the last ',' with ']'
        result.pop();
        result.push_str("]");
    }
    else{
        let as_val: Result<Vec<u8>, DecoderError> = rlp.as_val();
        let value: String = match as_val{
            Ok(v) => {
                let encrypted_value = read_hex(from_utf8(&v).unwrap()).unwrap();
                let decrypted_value = decrypt(&encrypted_value,key);
                match decrypted_value{
                    Ok(v)=> {
                        let iter = v.into_iter();
                        let mut decrypted_str = "".to_string();
                        for item in iter{
                            decrypted_str.push(item as char);
                        }
                        if is_uint {
                            decrypted_str = complete_to_u256(decrypted_str);
                        }
                        decrypted_str
                    },
                    Err(e) => {
                        convert_undecrypted_value_to_string(rlp, is_uint)
                    },
                }
            },
            Err(_e) => {
                convert_undecrypted_value_to_string(rlp, is_uint)
            },
        };
        result.push_str(&value);
    }
}

pub fn decode_args(encoded: &[u8], types: &Vec<String>) -> Result<Vec<String>,EnclaveError> {
    let key = get_key();
    let rlp = UntrustedRlp::new(encoded);

    let mut result: Vec<String> = vec![];
    let iter = rlp.iter();
    let mut types_iter = types.iter();
    for item in iter {
        let mut str: String = "".to_string();
        let next_type = match types_iter.next(){
            Some(v) => v,
            None => return Err(EnclaveError::InputError{message: "Arguments and callable signature do not match".to_string()}),
        };
        let is_uint: bool = next_type.starts_with("uint");
        decrypt_rlp(&item, & mut str, &key, is_uint);
        result.push(str);
    }
   Ok(result)
}
