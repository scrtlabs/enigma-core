use ethabi::param_type::{ParamType, Reader};
use ethabi::token::{Token, Tokenizer, StrictTokenizer, LenientTokenizer};
use ethabi::{encode, decode};
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
    let result = encode(&tokens);

    Ok(result)
}

pub fn prepare_evm_input(callable: &[u8], callable_args: &[u8]) -> Result<Vec<u8>, Error> {
    let callable: &str = from_utf8(callable).unwrap();
    let start_arg_index;
    let end_arg_index;

    match  callable.find('(') {
        Some(x) => start_arg_index = x,
        None  => return Err(Error(ErrorKind::Msg("'callable' signature is illegal".to_string()),State {next_error:None})),
    }

    match  callable.find(')') {
        Some(x) => end_arg_index = x,
        None  => return Err(Error(ErrorKind::Msg("'callable' signature is illegal".to_string()),State {next_error:None})),
    }

    let types_string: &str = &callable[start_arg_index+1..end_arg_index];
    let function_name = &callable[..start_arg_index];

    let mut types_vector: Vec<String> = vec![];
    let types_iterator = types_string.split(",");
    for each_type in types_iterator{
        types_vector.push(each_type.to_string());
    }

    let decoded_args = &decode_args(callable_args)[..];

    let mut args_vector: Vec<String> = vec![];
    let args_iterator = decoded_args.split(",");
    for arg in args_iterator{
        args_vector.push(arg.to_string());
    }

    println!("{:?}", args_vector);

    let val_sl = &args_vector[..];
    let types_sl = &types_vector[..];

    let result= match encode_params(types_sl, val_sl, true){
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    println!("{:?}", result);

    let types: Vec<ParamType> = types_sl.iter()
        .map(|s| Reader::read(s))
        .collect::<Result<_, _>>()?;
    ;

    let callable_signature = short_signature(function_name, &types);

    let mut result_bytes: Vec<u8> = vec![];
    let iter = callable_signature.iter();
    for item in iter{
        result_bytes.push(*item);
    }

    let iter = result.iter();
    for item in iter{
        result_bytes.push(*item);
    }

    Ok(result_bytes)
}
