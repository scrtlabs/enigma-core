#![feature(box_patterns)]
#![recursion_limit="128"]
extern crate eng_wasm;
extern crate proc_macro2;
#[macro_use] extern crate quote;
extern crate proc_macro;
#[macro_use]
extern crate syn;
extern crate serde_json;
extern crate ethabi;

use eng_wasm::*;
use std::fs::File;
use std::string::ToString;
//use std::io::prelude::*;
use std::convert::*;
use ethabi::{Contract, ParamType};

const CONSTRUCTOR_NAME: &str = "construct";

fn generate_eng_wasm_aux_functions() -> proc_macro2::TokenStream{
    quote!{
        #[no_mangle]
        pub fn function_name() -> String {

            let length_result = unsafe { eng_wasm::external::fetch_function_name_length() };

            match length_result {
                0 => "".to_string(),
                length => {
                let mut data = Vec::with_capacity(length as usize);
                for _ in 0..length{
                    data.push(0);
                }

                unsafe {
                    eng_wasm::external::fetch_function_name(data.as_mut_ptr());
                }
                from_utf8(&data).unwrap().to_string()
                }
            }
        }
        #[no_mangle]
        pub fn args() -> Vec<u8> {
            let length_result = unsafe { external::fetch_args_length() };

            match length_result {
                0 => Vec::new(),
                length => {
                    let mut data = Vec::with_capacity(length as usize);
                    for _ in 0..length{
                        data.push(0);
                    }

                    unsafe {
                        external::fetch_args(data.as_mut_ptr());
                    }
                    data
                }
            }
        }

    }
}

fn get_contract_methods(input: syn::Item) -> Vec<syn::TraitItemMethod> {
    let v;
    match input {
        syn::Item::Trait(input) => {
            v = input.items;
            v.iter().filter_map(|item| {
                match item {
                    syn::TraitItem::Method(item) => Some(item.clone()),
                    _ => None,
                }
            })
        },
        _ => panic!(),
    }.collect()
}

fn get_arg_types(method: &syn::TraitItemMethod) -> Vec<proc_macro2::TokenStream> {
    method.sig.decl.inputs.iter().filter_map(|arg| match arg {
        // Argument captured by a name
        syn::FnArg::Captured(arg_captured) => {
            let ty = &arg_captured.ty;
            Some(quote! {#ty})
        },
        // Argument without a name
        syn::FnArg::Ignored(type_only) => {
            Some(quote! {#type_only})
        },
        _ => None,
    }).collect()
}

fn generate_dispatch(input: syn::Item) -> proc_macro2::TokenStream{
    let it: Vec<proc_macro2::TokenStream> = get_contract_methods(input).iter().filter_map(|item| {
        let output = &item.sig.decl.output;
        let return_params_number = match output{
            syn::ReturnType::Type( _, box syn::Type::Path(n) ) => n.path.segments.len(),
            _ => 0,
        };
        let return_params_number_literal = syn::Lit::Int(syn::LitInt::new(return_params_number as u64,
                                                         syn::IntSuffix::Usize,
                                                         proc_macro2::Span::call_site()));
        let func = item.sig.ident.clone();
        if func != CONSTRUCTOR_NAME {
            let arg_types = get_arg_types(item);
            let name = &func.to_string();
            match return_params_number{
                0 => Some(quote! {
                    #name => {
                        let mut stream = pwasm_abi::eth::Stream::new(args);
                        Contract::#func(#(stream.pop::<#arg_types>().expect("argument decoding failed")),*);
                    }
                }),
                _ => Some(quote! {
                    #name => {
                        let mut stream = pwasm_abi::eth::Stream::new(args);
                        let result = Contract::#func(#(stream.pop::<#arg_types>().expect("argument decoding failed")),*);
                        let mut result_bytes: Vec<u8> = Vec::with_capacity(#return_params_number_literal * 32);
                        let mut sink = pwasm_abi::eth::Sink::new(#return_params_number_literal);
                        sink.push(result);
                        sink.drain_to(&mut result_bytes);
                        unsafe { eng_wasm::external::ret(result_bytes.as_ptr(), result_bytes.len() as u32) }
                    }
                }),
            }
        }
        else{
            None
        }
    }).collect();

    quote! {
        pub fn dispatch(name: &str, args: &[u8]){
            match name{
            #(#it,)*
            _=>panic!(),
            }
        }
    }
}

fn generate_constructor(input: syn::Item) -> proc_macro2::TokenStream{
    let contract_methods = get_contract_methods(input);
    let constructor = contract_methods.iter().find(|item| item.sig.ident.clone() == CONSTRUCTOR_NAME);
    match constructor {
        Some (v) => {
                    let constructor_name = v.sig.ident.clone();
                    let arg_types = get_arg_types(v);
                    quote! {
                        #[no_mangle]
                        pub fn deploy() {
                            deploy_internal(&args());
                        }
                        fn deploy_internal(args: &[u8]){
                            let mut stream = pwasm_abi::eth::Stream::new(args);
                            Contract::#constructor_name(#(stream.pop::<#arg_types>().expect("argument decoding failed")),*);
                        }
                    }
                },
        None => {
            quote! {
                #[no_mangle]
                pub fn deploy() {}
            }
        },
    }
}

#[proc_macro_attribute]
#[allow(unused_variables, unused_mut)]
pub fn pub_interface(args: proc_macro::TokenStream, input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input_tokens = parse_macro_input!(input as syn::Item);
    let disp = generate_dispatch(input_tokens.clone());
    let eng_wasm_aux = generate_eng_wasm_aux_functions();
    let constructor = generate_constructor(input_tokens.clone());
    let result = quote! {
        #eng_wasm_aux
        #input_tokens
        #constructor
        #disp

        #[no_mangle]
        pub fn call(){
            dispatch(&function_name(), &args());
        }
    };
    proc_macro::TokenStream::from(result)
}

//--------------------------------------------------------------------------------------------------

trait Write{
    fn write(&self) -> String;
    fn error(&self) -> String;
}

impl Write for ParamType{
    /// Returns string which is a formatted representation of param.
    fn write(&self) -> String {
        match *self{
            ParamType::Address => "Address".to_owned(),
            ParamType::Bytes => "Vec<u8>".to_owned(),
            ParamType::FixedBytes(len) => format!("u8[{}]", len),
            ParamType::Int(len) => match len{
                32 | 64 => format!("i{}", len),
                _ => panic!("{}", self.error()),
            },
            ParamType::Uint(len) => match len{
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
    fn error(&self) -> String{
        format!("The type {} is not supported", self.to_string())
    }
}

#[derive(Debug)]
struct FunctionAst {
    name: syn::Ident,
    args_ast_types: Vec<syn::Type>,
    args_types: Vec<ParamType>,
}

fn read_contract_file(file_path: String) -> Result<Box<File>, EngWasmError>{
    let file = File::open(file_path)?;
    let contents = Box::new(file);
    Ok(contents)
}

fn generate_eth_functions(contract: &Contract) -> Result<Box<Vec<proc_macro2::TokenStream>>,EngWasmError>{
    let mut functions: Vec<FunctionAst> = Vec::new();
    for function in &contract.functions{
        let mut args_ast_types = Vec::new();
        for input in &function.1.inputs{
            let arg_type: syn::Type = syn::parse_str(&input.kind.clone().write())?;
            args_ast_types.push(arg_type);
        }
        let args_types = function.1.inputs.iter().map(|input| {
            input.kind.clone()
        }).collect();

        let name = syn::Ident::new(&function.1.name, proc_macro2::Span::call_site());
        functions.push(FunctionAst{name, args_types, args_ast_types})
    }

    let result: Vec<proc_macro2::TokenStream> = functions.iter().map(|function| {
        let function_name = &function.name;
        let args_ast_types = function.args_ast_types.clone();
        let sig_u32 = short_signature(&function_name.to_string(), &function.args_types);
        let sig = syn::Lit::Int(syn::LitInt::new(sig_u32 as u64, syn::IntSuffix::U32, proc_macro2::Span::call_site()));
        let args_number = syn::Lit::Int(syn::LitInt::new(args_ast_types.len() as u64,
                                                         syn::IntSuffix::Usize,
                                                         proc_macro2::Span::call_site()));
        let args_names: Vec<syn::Ident> = function.args_ast_types.iter().enumerate().map(|item| {
            let mut arg = String::from("arg");
            arg.push_str(item.0.to_string().as_str());
            syn::Ident::new(&arg, proc_macro2::Span::call_site())
        }).collect();
        let args_names_copy = args_names.clone();
        quote!{
            fn #function_name(&self, #(#args_names: #args_ast_types),*){
                #![allow(unused_mut)]
                #![allow(unused_variables)]
                let mut payload = Vec::with_capacity(4 + #args_number * 32);
				payload.push((#sig >> 24) as u8);
				payload.push((#sig >> 16) as u8);
				payload.push((#sig >> 8) as u8);
                payload.push(#sig as u8);

                let mut sink = pwasm_abi::eth::Sink::new(#args_number);
                #(sink.push(#args_names_copy);)*
                sink.drain_to(&mut payload);
                write_ethereum_payload(payload);
                write_ethereum_contract_addr(&self.addr);
            }
        }
    }).collect();

    Ok(Box::new(result))
}

#[proc_macro_attribute]
#[allow(unused_variables, unused_mut)]
pub fn eth_contract(args: proc_macro::TokenStream, input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input_tokens = parse_macro_input!(input as syn::ItemStruct);
    let struct_name = input_tokens.ident;
    let file_path = parse_macro_input!(args as syn::LitStr);
    let mut contents: Box<File> = read_contract_file(file_path.value()).expect("Bad contract file");
    let contract = Contract::load(contents).unwrap();
    let it: Vec<proc_macro2::TokenStream> = *generate_eth_functions(&contract).unwrap();

    let result = quote! {
        struct #struct_name{
            addr: [u8;20],
        }
        impl EthContract{
            fn new(addr_str: /*Address*/&str) -> Self {
                EthContract{addr: From::from(Address::from(addr_str.as_bytes()))}
            }
             #(#it)*
        }
    };
    proc_macro::TokenStream::from(result)
}