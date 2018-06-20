
use rlp::{RlpStream, UntrustedRlp};
use hexutil::read_hex;
use std::str::from_utf8;
use std::string::ToString;
use rlp::DecoderError;
use std::vec::Vec;
use std::string::String;
use cryptography_t::symmetric::{decrypt, encrypt};
use common::utils_t::{ToHex, FromHex};
use ring::digest;



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
        }
        result.pop();
        result.push_str("]");
    }
    else{
        let as_val: Result<Vec<u8>, DecoderError> = rlp.as_val();
        let value: String = match as_val{
            Ok(v) => {
                let encrypted_value = read_hex(from_utf8(&v).unwrap()).unwrap();
                let decrypted_value = decrypt(&encrypted_value,key);
                let iter = decrypted_value.into_iter();
                let mut s = "".to_string();
                for item in iter{
                    s.push(item as char);
                }
                s
            },
            Err(_e) => {
                convert_undecrypted_value_to_string(rlp)
            },
        };
        result.push_str(&value);
        result.push_str(",");
    }
}


pub fn decode_args(encoded: &[u8]) -> String{
    let key = digest::digest(&digest::SHA256, b"EnigmaMPC");
/*    let arg1 = b"1".to_vec();
    let arg2 = b"2".to_vec();
    let iv = Some( [0,1,2,3,4,5,6,7,8,9,10,11] );
    let enc1 = encrypt(&arg1, key.as_ref(), &iv);
    let enc2 = encrypt(&arg2, key.as_ref(), &iv);
    let mut stream = RlpStream::new_list(2);
    stream.append(&enc1.to_hex());
    stream.append(&enc2.to_hex());
    let out = stream.out();*/
    let rlp = UntrustedRlp::new(encoded);

    let mut result: String = "".to_string();
    decrypt_rlp(&rlp, &mut result, key.as_ref());
    if result.len()>=2{
        if &result[0..1] == "["{
            result.pop();
            result.remove(0);
        }
    }
    result
}

//pub fn decode() -> &str{
//This is how it should work with test reading from file. Here the key is hardcoded, but the implementation of encrypt in python does not match the decryption here
/*    let args = read_hex(from_utf8(encoded).unwrap()).unwrap();

    let rlp = Rlp::new(&args);
    let i1: Vec<u8> = rlp.at(0).as_val();

    let r =  read_hex(from_utf8(&i1).unwrap()).unwrap();
    println!("{:?}", r);

   // let cypher = "44bbfaf7d0dc7ae4eaea2fe2e42dec6d03303030303030303030303030".from_hex().unwrap();
    let key = "31313131313131313131313131313131".from_hex().unwrap();
    println!("{:?}", key);

    decrypt(&cypher, &key);*/


  /*  let enc_arg1: Vec<u8> = rlp.at(0).as_val();
    let enc_hex1 =  read_hex(from_utf8(&enc_arg1).unwrap()).unwrap();
    println!("{:?}", enc_hex1);
    let enc_arg2: Vec<u8> = rlp.at(1).as_val();
    let enc_hex2 =  read_hex(from_utf8(&enc_arg2).unwrap()).unwrap();

    println!("WAAAAA");
    println!("{:?}", &enc1);
    println!("{:?}", &enc_arg1);
    let dec_arg1 = decrypt(&enc_hex1, key);

    println!("{:?}", dec_arg1);
*/


    /*
        // [ [], [[]], [ [], [[]] ] ]
        let data = vec![0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0];
        let rlp = Rlp::new(&data);
        let _v0: Vec<u16> = rlp.at(0).as_list();
    //    let _v1: Vec<u16> = rlp.at(1).at(0).as_list();
        let _v1: Vec<u16> = rlp.at(1).as_list();
        let nested_rlp = rlp.at(2);
        let _v2a: Vec<u16> = nested_rlp.at(0).as_list();
        let _v2b: Vec<u16> = nested_rlp.at(1).at(0).as_list();

        println!("{:?}", _v1);*/
/*
    let mut stream = RlpStream::new_list(2);
    stream.begin_list(2).append(&"cat").append(&"dog");
    stream.append(&"");
    let out = stream.out();
/// 	assert_eq!(out, vec![0xca, 0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g', 0x80]);
    let rlp = Rlp::new(&out);

    let _v1: Vec<String>  =  rlp.at(0).as_list();
    println!("{:?}", _v1);*/

/*
    let data = vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'];
    let rlp = Rlp::new(&data);
    let strings: Vec<String> = rlp.iter().map(| i | i.as_val()).collect();
    println!("{:?}", strings);
*/
//    let a: Vec<u8> = result.at(1).as_list();
    //let a: Vec<u8> = result;
    // let result: String = rlp::decode(&out);
    //let mut rlp_encoded = read_hex(encoded).unwrap();
    //println!("{:?}", a);
    //println!("{:?}", b);
    //println!("{:?}", c);
/*

    let data = vec![0xc2, 0xc0, 0x31, 0x32, 0x33];
    let r = Rlp::new(&data);
    let aa: Vec<u8>  = result.at(0).as_list();
    println!("{:?}", aa);*/

