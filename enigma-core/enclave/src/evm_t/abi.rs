use ethabi::param_type::{ParamType, Reader};
use ethabi::token::{Token, Tokenizer, StrictTokenizer, LenientTokenizer};
use ethabi;
use evm_t::error::Error;
use ethabi::signature::short_signature;

use std::string::String;
use std::vec::Vec;
use std::string::ToString;
use std::str::from_utf8;
use evm_t::error::{ErrorKind};
use evm_t::rlp::decode_args;
use error_chain::State;

fn parse_tokens(params: &[(ParamType, &str)], lenient: bool) -> Result<Vec<Token>, Error> {
    params.iter()
        .map(|&(ref param, value)| match lenient {
            true => LenientTokenizer::tokenize(param, value),
            false => StrictTokenizer::tokenize(param, value)
        })
        .collect::<Result<_, _>>()
        .map_err(From::from)

}

fn encode_params(types: &[String], values: &[String], lenient: bool) -> Result<Vec<u8>, Error> {
    assert_eq!(types.len(), values.len());

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


fn get_types(function: &str) -> Result<(Vec<String>, String), Error>{
    let start_arg_index;
    let end_arg_index;

    match  function.find('(') {
        Some(x) => start_arg_index = x,
        None  => return Err(Error(ErrorKind::Msg("'callable' signature is illegal".to_string()),State {next_error:None})),
    }

    match  function.find(')') {
        Some(x) => end_arg_index = x,
        None  => return Err(Error(ErrorKind::Msg("'callable' signature is illegal".to_string()),State {next_error:None})),
    }

    let types_string: &str = &function[start_arg_index+1..end_arg_index];
    let mut types_vector: Vec<String> = vec![];
    let types_iterator = types_string.split(",");
    for each_type in types_iterator{
        types_vector.push(each_type.to_string());
    }
    Ok(( types_vector, String::from(&function[..start_arg_index] )))
}

fn get_args(callable_args: &[u8]) -> Result<Vec<String>, Error>{
    let decoded_args = &decode_args(callable_args)[..];

    let mut args_vector: Vec<String> = vec![];
    let args_iterator = decoded_args.split(",");
    for arg in args_iterator{
        args_vector.push(arg.to_string());
    }
    Ok(args_vector)
}

pub fn prepare_evm_input(callable: &[u8], callable_args: &[u8]) -> Result<Vec<u8>, Error> {
    let callable: &str = from_utf8(callable).unwrap();

    let (types_vector,function_name) = match get_types(callable){
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let args_vector = match get_args(callable_args){
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    let params = match encode_params(&types_vector[..], &args_vector[..], true){
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    let types: Vec<ParamType> =  types_vector[..].iter()
        .map(|s| Reader::read(s))
        .collect::<Result<_, _>>()?;
    ;

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
