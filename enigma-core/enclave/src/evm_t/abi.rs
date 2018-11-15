use ethabi::param_type::{ParamType, Reader};
use ethabi::token::{Token, Tokenizer, StrictTokenizer, LenientTokenizer};
use ethabi;
use evm_t::error::Error;
use ethabi::signature::short_signature;

use std::string::String;
use std::vec::Vec;
use std::string::ToString;
use std::str::from_utf8;
//use evm_t::rlp::{decode_args, complete_to_u256};
use evm_t::preprocessor;
use common::utils_t::ToHex;
use common::errors_t::EnclaveError;
use enigma_tools_t::build_arguments_g::*;
use enigma_tools_t::build_arguments_g::rlp::complete_to_u256;

fn parse_tokens(params: &[(ParamType, &str)], lenient: bool) -> Result<Vec<Token>, Error> {
    params.iter()
        .map(|&(ref param, value)| match lenient {
            true => LenientTokenizer::tokenize(param, value),
            false => StrictTokenizer::tokenize(param, value)
        })
        .collect::<Result<_, _>>()
        .map_err(From::from)

}

pub fn encode_params(types: &[String], values: &[String], lenient: bool) -> Result<Vec<u8>, Error> {
    if values.len() == 0 {
        return Ok(vec![]);
    }
    let types: Vec<ParamType> = types.iter()
        .map(|s| Reader::read(s))
        .collect::<Result<_, _>>()?;

    let params: Vec<_> = types.into_iter()
        .zip(values.iter().map(|v| v as &str))
        .collect();

    let tokens = parse_tokens(&params, lenient)?;
    let result = ethabi::encode(&tokens);

    Ok(result)
}

fn get_preprocessor(preproc: &[u8]) -> Result<Vec<String>, EnclaveError> {
    let prep_string = from_utf8(preproc).unwrap();
    let split = prep_string.split(",");
    let mut preprocessors = vec![];
    for preprocessor in split{
        let preprocessor_result = preprocessor::run(preprocessor);
        match preprocessor_result {
            Ok(v) => preprocessors.push(v.to_hex()),
            Err(e) => return Err(e),
        };
    }
    Ok(preprocessors)

}

fn create_function_signature(types_vector: Vec<String>, function_name: String) -> Result<[u8;4],EnclaveError>{
    let types: Vec<ParamType>;
    match types_vector[..].iter()
        .map(|s| Reader::read(s))
        .collect::<Result<_, _>>(){
        Ok(v) => types = v,
        Err(e) => return Err(EnclaveError::InputError{message: e.to_string()}),
    };

    let callback_signature = short_signature(&function_name, &types);
    Ok(callback_signature)
}

pub fn prepare_evm_input(callable: &[u8], callable_args: &[u8], preproc: &[u8]) -> Result<Vec<u8>, EnclaveError> {
    let callable: &str = from_utf8(callable).unwrap();

    let (types, function_name) = match get_types(callable) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let types_vector = extract_types(&types);
    let mut args_vector = match get_args(callable_args, &extract_types(&types)) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    if preproc.len() > 0 {
        let preprocessors = match get_preprocessor(preproc) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        for preprocessor in preprocessors {
            args_vector.push(complete_to_u256(preprocessor));
        }
    }
    if types_vector.len() != args_vector.len(){
        return Err(EnclaveError::InputError{message: "The number of function arguments does not match the number of actual parameters in ".to_string()+&function_name});
    }
    let params = match encode_params(&types_vector[..], &args_vector[..], false){
        Ok(v) => v,
        Err(e) => return Err(EnclaveError::InputError{message: format!( "Error in encoding of funciton: {}, {}", function_name, &e ) }),
    };

    let types: Vec<ParamType>;
        match types_vector[..].iter()
        .map(|s| Reader::read(s))
        .collect::<Result<_, _>>(){
        Ok(v) => types = v,
        Err(e) => return Err(EnclaveError::InputError{message: e.to_string()}),
    };

    let callable_signature = short_signature(&function_name, &types);

    let mut result_bytes: Vec<u8> = vec![];
    let iter = callable_signature.iter();
    for item in iter{
        result_bytes.push(*item);
    }

    let iter = params.iter();
    for item in iter{
        result_bytes.push(*item);
    }

    Ok(result_bytes)
}

pub fn create_callback(mut data: & mut Vec<u8>, callback: &[u8]) -> Result<Vec<u8>, EnclaveError>{
    let callback: &str = from_utf8(callback).unwrap();

    let (types, function_name) = match get_types(callback) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    let callback_signature = create_function_signature(extract_types(&types), function_name);
    let mut result_bytes: Vec<u8> = vec![];
    match callback_signature{
        Err(e) => return Err(e),
        Ok(v) => {
            result_bytes.extend_from_slice(&v)
        },
    };
    result_bytes.extend_from_slice(& mut data);
    Ok(result_bytes)
}