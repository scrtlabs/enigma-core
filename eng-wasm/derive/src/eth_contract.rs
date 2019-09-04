use std::fs::File;

use quote::quote;

use ethabi::{Contract, ParamType};

mod errors;
mod ethereum;

use errors::EngWasmError;
use ethereum::short_signature;

trait Write {
    fn write(&self) -> String;
    fn error(&self) -> String;
}

impl Write for ParamType {
    /// Returns string which is a formatted representation of param.
    fn write(&self) -> String {
        match *self {
            ParamType::Address => "Address".to_owned(),
            ParamType::Bytes => "Vec<u8>".to_owned(),
            ParamType::FixedBytes(len) => format!("u8[{}]", len),
            ParamType::Int(len) => match len {
                32 | 64 => format!("i{}", len),
                _ => panic!("{}", self.error()),
            },
            ParamType::Uint(len) => match len {
                32 | 64 => format!("u{}", len),
                256 => "U256".to_owned(),
                _ => panic!("{}", self.error()),
            },
            ParamType::Bool => "bool".to_owned(),
            ParamType::String => "String".to_owned(),
            ParamType::FixedArray(ref param, len) => format!("{}[{}]", param.write(), len),
            ParamType::Array(ref param) => format!("Vec<{}>", param.write()),
        }
    }
    fn error(&self) -> String {
        format!("The type {} is not supported", self.to_string())
    }
}

struct FunctionAst {
    name: syn::Ident,
    args_ast_types: Vec<syn::Type>,
    args_types: Vec<ParamType>,
}

fn read_contract_file(file_path: String) -> Result<Box<File>, EngWasmError> {
    let file = File::open(file_path)?;
    let contents = Box::new(file);
    Ok(contents)
}

fn generate_eth_functions(
    contract: &Contract,
) -> Result<Vec<proc_macro2::TokenStream>, EngWasmError> {
    let mut functions: Vec<FunctionAst> = Vec::new();
    for function in &contract.functions {
        let mut args_ast_types = Vec::new();
        for input in &function.1.inputs {
            let arg_type: syn::Type = syn::parse_str(&input.kind.clone().write())?;
            args_ast_types.push(arg_type);
        }
        let args_types = function
            .1
            .inputs
            .iter()
            .map(|input| input.kind.clone())
            .collect();

        let name = syn::Ident::new(&function.1.name, proc_macro2::Span::call_site());
        functions.push(FunctionAst {
            name,
            args_types,
            args_ast_types,
        })
    }

    let result: Vec<proc_macro2::TokenStream> = functions
        .iter()
        .map(|function| {
            let function_name = &function.name;
            let args_ast_types = function.args_ast_types.clone();
            let sig_u32 = short_signature(&function_name.to_string(), &function.args_types);
            let sig = syn::Lit::Int(syn::LitInt::new(
                &format!("{}_u32", sig_u32 as u32),
                proc_macro2::Span::call_site(),
            ));
            let args_number = syn::Lit::Int(syn::LitInt::new(
                &format!("{}_usize", args_ast_types.len() as usize),
                proc_macro2::Span::call_site(),
            ));
            let args_names: Vec<syn::Ident> = function
                .args_ast_types
                .iter()
                .enumerate()
                .map(|item| {
                    let mut arg = String::from("arg");
                    arg.push_str(item.0.to_string().as_str());
                    syn::Ident::new(&arg, proc_macro2::Span::call_site())
                })
                .collect();
            let args_names_copy = args_names.clone();
            quote! {
                fn #function_name(&self, #(#args_names: #args_ast_types),*){
                    #![allow(unused_mut)]
                    #![allow(unused_variables)]
                    let mut payload = Vec::with_capacity(4 + #args_number * 32);
                    payload.push((#sig >> 24) as u8);
                    payload.push((#sig >> 16) as u8);
                    payload.push((#sig >> 8) as u8);
                    payload.push(#sig as u8);

                    let mut sink = eng_pwasm_abi::eth::Sink::new(#args_number);
                    #(sink.push(#args_names_copy);)*
                    sink.drain_to(&mut payload);
                    write_ethereum_bridge(&payload, &self.addr);
                }
            }
        })
        .collect();

    Ok(result)
}

pub fn impl_eth_contract(
    args: proc_macro2::TokenStream,
    input: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let input_tokens = parse_macro_input2!(input as syn::ItemStruct);
    let struct_name = input_tokens.ident;
    let file_path = parse_macro_input2!(args as syn::LitStr);
    let contents: Box<File> = read_contract_file(file_path.value()).expect("Bad contract file");
    let contract = Contract::load(contents).unwrap();
    let it: Vec<proc_macro2::TokenStream> = generate_eth_functions(&contract).unwrap();

    quote! {
        struct #struct_name {
            addr: Address,
        }
        impl EthContract{
            fn new(addr_str: /*Address*/&str) -> Self {
                use core::str::FromStr;

                // Ethereum Addresses need to start with `0x` so we remove the first two characters
                let addr = Address::from_str(&addr_str[2..]).expect("Failed converting the address from hex");
                EthContract{ addr }
            }
             #(#it)*
        }
    }
}
