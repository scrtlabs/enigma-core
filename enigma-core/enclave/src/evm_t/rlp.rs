
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


fn convert_undecrypted_value_to_string(rlp: &UntrustedRlp) -> String{
    let result: String;
    let string_result: Result<String, DecoderError> = rlp.as_val();
    result = match string_result{
        Ok(v) => v.clone(),
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

fn decrypt_rlp(rlp: &UntrustedRlp, result: & mut String, key: &[u8]) {
    if rlp.is_list(){
        result.push_str("[");
        let iter = rlp.iter();
        for item in iter{
            decrypt_rlp(&item, result, key);
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
                        decrypted_str
                    },
                    Err(e) => {
                        convert_undecrypted_value_to_string(rlp)
                    },
                }
            },
            Err(_e) => {
                convert_undecrypted_value_to_string(rlp)
            },
        };
        result.push_str(&value);
    }
}

pub fn decode_args(encoded: &[u8]) -> Vec<String> {
    let key = get_key();
    let rlp = UntrustedRlp::new(encoded);

    let mut result: Vec<String> = vec![];
    let iter = rlp.iter();
    for item in iter {
        let mut str: String = "".to_string();
        decrypt_rlp(&item, & mut str, &key);
        result.push(str);
    }
    result
}
