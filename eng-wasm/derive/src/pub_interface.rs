use quote::{quote, ToTokens};
use syn::spanned::Spanned;

mod parse_signatures;

use super::into_ident::IntoIdent;
use parse_signatures::PubInterfaceSignatures;

const DEFAULT_IMPLEMENTOR_NAME: &str = "Contract";
const CONSTRUCTOR_NAME: &str = "construct";

const DEPLOY_FUNC_NAME: &str = "deploy";
const DISPATCH_FUNC_NAME: &str = "dispatch";
const FUNCTION_NAME_FUNC_NAME: &str = "function_name";
const ARGS_FUNC_NAME: &str = "args";
const CALL_FUNC_NAME: &str = "call";

pub(crate) fn impl_pub_interface(item: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    //    let item = parse_macro_input2!(item as syn::ItemTrait);
    //    println!("SYNTAX: {:#?}", item);
    //    item.to_token_stream()

    let cloned_item = item.clone();
    let pub_interface_signatures = parse_macro_input2!(cloned_item as PubInterfaceSignatures);

    let deploy_func_name = DEPLOY_FUNC_NAME.into_ident();
    let dispatch_func_name = DISPATCH_FUNC_NAME.into_ident();
    let function_name_func_name = FUNCTION_NAME_FUNC_NAME.into_ident();
    let args_func_name = ARGS_FUNC_NAME.into_ident();
    let call_func_name = CALL_FUNC_NAME.into_ident();

    let aux_functions = generate_eng_wasm_aux_functions(&function_name_func_name, &args_func_name);
    let constructor_function =
        generate_deploy_function(&pub_interface_signatures, &deploy_func_name);
    let dispatch_function =
        generate_dispatch_function(&dispatch_func_name, &pub_interface_signatures);

    quote! {
        #item
        #aux_functions
        #constructor_function
        #dispatch_function

        #[no_mangle]
        pub fn #call_func_name(){
            #dispatch_func_name(&#function_name_func_name(), &#args_func_name());
        }
    }
}

fn generate_eng_wasm_aux_functions(
    function_name_func_name: &syn::Ident,
    args_func_name: &syn::Ident,
) -> proc_macro2::TokenStream {
    quote! {
        #[no_mangle]
        pub fn #function_name_func_name() -> eng_wasm::String {
            use eng_wasm::{
                Vec,
                String,
                ToString,
                from_utf8,
                external::{
                    fetch_function_name,
                    fetch_function_name_length,
                },
            };

            let length_result = unsafe { fetch_function_name_length() };

            match length_result {
                0 => String::new(),
                length => {
                    let mut data = Vec::with_capacity(length as usize);
                    for _ in 0..length{
                        data.push(0);
                    }

                    unsafe {
                        fetch_function_name(data.as_mut_ptr());
                    }
                    from_utf8(&data).unwrap().to_string()
                }
            }
        }

        #[no_mangle]
        pub fn #args_func_name() -> eng_wasm::Vec<u8> {
            use eng_wasm::{
                Vec,
                external::{
                    fetch_args,
                    fetch_args_length,
                },
            };
            let length_result = unsafe { fetch_args_length() };

            match length_result {
                0 => Vec::new(),
                length => {
                    let mut data = Vec::with_capacity(length as usize);
                    for _ in 0..length{
                        data.push(0);
                    }

                    unsafe {
                        fetch_args(data.as_mut_ptr());
                    }
                    data
                }
            }
        }
    }
}

fn generate_deploy_function(
    signatures: &PubInterfaceSignatures,
    deploy_func_name: &syn::Ident,
) -> proc_macro2::TokenStream {
    if let Some(constructor_signature) = signatures
        .signatures
        .iter()
        .find(|item| item.ident == CONSTRUCTOR_NAME)
    {
        let implementor = &signatures.implementor;
        let constructor_name = &constructor_signature.ident;
        let input_pats_and_types = get_signature_input_pats_and_types(&constructor_signature);
        let expectations = get_contract_input_parsing_error_messages(&input_pats_and_types);
        let input_types = input_pats_and_types.iter().map(|(_pat, type_)| type_);

        return quote! {
            #[no_mangle]
            pub fn #deploy_func_name() {
                let args_ = args();
                let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(&args_);
                <#implementor>::#constructor_name(#(
                    stream.pop::<#input_types>().expect(#expectations),
                )*);
            }
        };
    } else {
        return quote! {
            #[no_mangle]
            pub fn #deploy_func_name() {}
        };
    }
}

fn get_signature_input_pats_and_types(signature: &syn::Signature) -> Vec<(&syn::Pat, &syn::Type)> {
    signature
        .inputs
        .iter()
        .map(|arg| match arg {
            syn::FnArg::Typed(arg_type) => (&*arg_type.pat, &*arg_type.ty),
            _ => unreachable!("We should have checked that trait methods don't take self"),
        })
        .collect()
}

/// Generate useful error messages for when argument parsing fails at runtime.
fn get_contract_input_parsing_error_messages(
    input_pats_and_types: &Vec<(&syn::Pat, &syn::Type)>,
) -> Vec<syn::LitStr> {
    input_pats_and_types
        .iter()
        .map(|(pat, type_)| {
            let pat_tokens = pat.to_token_stream();
            let type_tokens = type_.to_token_stream();
            syn::LitStr::new(
                &format!(
                    "could not decode argument `{}` as `{}`",
                    pat_tokens, type_tokens,
                ),
                pat_tokens.span(), // This is not very important here
            )
        })
        .collect()
}

fn generate_dispatch_function(
    dispatch_func_name: &syn::Ident,
    signatures: &PubInterfaceSignatures,
) -> proc_macro2::TokenStream {
    let implementor = &signatures.implementor;
    let match_arms: Vec<proc_macro2::TokenStream> = signatures
        .signatures
        .iter()
        .filter_map(|signature| {
            let method_name = &signature.ident;
            if method_name == CONSTRUCTOR_NAME {
                None
            } else {
                let method_name_as_string = method_name.to_string();
                let output_type = &signature.output;
                let input_pats_and_types = get_signature_input_pats_and_types(&signature);
                let expectations = get_contract_input_parsing_error_messages(&input_pats_and_types);
                let input_types = input_pats_and_types.iter().map(|(_pat, type_)| type_);

                let return_value_count = match output_type {
                    syn::ReturnType::Default => 0,
                    // If the return value is a tuple, we count it like multiple return values.
                    // This is the same thing that pwasm_abi does under
                    // pwasm_abi/derive/src/item.rs :: fn into_signature
                    // which flows back to
                    // pwasm_abi/derive/src/lib.rs :: fn generate_eth_endpoint
                    // which dictates how return values are serialised into the Sink.
                    // This can be 0 is the return type is () which is correct.
                    syn::ReturnType::Type(_, box syn::Type::Tuple(return_tuple)) => return_tuple.elems.len(),
                    // Any other type is a single return value. Arrays such as [u8; 4]
                    // are not AbiType so Sink will reject them at compile time.
                    syn::ReturnType::Type(_, _) => 1,
                };

                match return_value_count {
                    0 => Some(quote! {
                        #method_name_as_string => {
                            let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(args);
                            <#implementor>::#method_name(#(stream.pop::<#input_types>().expect(#expectations),)*);
                        }
                    }),
                    _ => Some(quote! {
                        #method_name_as_string => {
                            let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(args);
                            let result = <#implementor>::#method_name(#(stream.pop::<#input_types>().expect(#expectations),)*);
                            // 32 is the size of each argument in the serialised form
                            // The Sink.drain_to() method might resize this array is any
                            // dynamically sized elements are returned, but if not, then only one
                            // allocation (this one) will happen for the Vec.
                            let mut result_bytes = eng_wasm::Vec::with_capacity(#return_value_count * 32);
                            let mut sink = eng_wasm::eng_pwasm_abi::eth::Sink::new(#return_value_count);
                            sink.push(result);
                            sink.drain_to(&mut result_bytes);
                            unsafe { eng_wasm::external::ret(result_bytes.as_ptr(), result_bytes.len() as u32) }
                        }
                    }),
                }
            }
        })
        .collect();

    quote! {
        pub fn #dispatch_func_name(name: &str, args: &[u8]){
            match name {
                #(#match_arms)*
                _ => panic!("Unknown method called:\"{}\"", name),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_generation() -> syn::Result<()> {
        let input = quote!(
            pub trait Erc20Interface {
                fn construct(contract_owner: H256, total_supply: U256);
                /// creates new tokens and sends to the specified address
                fn mint(owner: H256, addr: H256, tokens: U256, sig: Vec<u8>);
                /// get the total_supply
                fn total_supply() -> U256;
                /// get the balance of the specified address
                fn balance_of(token_owner: H256) -> U256;
                /// get the allowed amount of the owner tokens to be spent by the spender address
                fn allowance(owner: H256, spender: H256) -> U256;
                /// transfer tokens from 'from' address to the 'to' address.
                /// the function panics if the 'from' address does not have enough tokens.
                fn transfer(from: H256, to: H256, tokens: U256, sig: Vec<u8>);
                /// approve the 'spender' address to spend 'tokens' from the 'owner's address balance.
                /// the function panics if the 'owner' address does not have enough tokens.
                fn approve(token_owner: H256, spender: H256, tokens: U256, sig: Vec<u8>);
                /// 'spender' address transfers tokens on behalf of the owner address to the 'to' address.
                /// the function panics if the 'owner' address does not have enough tokens or the 'spender'
                /// address does not have enough tokens as well.
                fn transfer_from(owner: H256, spender: H256, to: H256, tokens: U256, sig: Vec<u8>);
            }
        );

        let expected_output = quote!(
            #[no_mangle]
            pub fn deploy() {
                let args_ = args();
                let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(&args_);
                <Contract>::construct(
                    stream
                        .pop::<H256>()
                        .expect("could not decode argument `contract_owner` as `H256`"),
                    stream
                        .pop::<U256>()
                        .expect("could not decode argument `total_supply` as `U256`"),
                );
            }
        );

        let signatures = syn::parse2::<PubInterfaceSignatures>(input)?;
        let output = generate_deploy_function(&signatures, &DEPLOY_FUNC_NAME.into_ident());

        assert_eq!(
            syn::parse2::<syn::ItemFn>(output)?,
            syn::parse2::<syn::ItemFn>(expected_output)?,
        );
        Ok(())
    }

    #[test]
    fn dispatch_generation() -> syn::Result<()> {
        let input = quote!(
            pub trait Erc20Interface {
                fn construct(contract_owner: H256, total_supply: U256);
                /// creates new tokens and sends to the specified address
                fn mint(owner: H256, addr: H256, tokens: U256, sig: Vec<u8>);
                /// get the total_supply
                fn total_supply() -> U256;
                /// get the balance of the specified address
                fn balance_of(token_owner: H256) -> U256;
                /// get the allowed amount of the owner tokens to be spent by the spender address
                fn allowance(owner: H256, spender: H256) -> U256;
                /// transfer tokens from 'from' address to the 'to' address.
                /// the function panics if the 'from' address does not have enough tokens.
                fn transfer(from: H256, to: H256, tokens: U256, sig: Vec<u8>);
                /// approve the 'spender' address to spend 'tokens' from the 'owner's address balance.
                /// the function panics if the 'owner' address does not have enough tokens.
                fn approve(token_owner: H256, spender: H256, tokens: U256, sig: Vec<u8>);
                /// 'spender' address transfers tokens on behalf of the owner address to the 'to' address.
                /// the function panics if the 'owner' address does not have enough tokens or the 'spender'
                /// address does not have enough tokens as well.
                fn transfer_from(owner: H256, spender: H256, to: H256, tokens: U256, sig: Vec<u8>);
            }
        );

        #[rustfmt::skip]
        let expected_output = quote!(
            pub fn dispatch(name: &str, args: &[u8]) {
                match name {
                    "mint" => {
                        let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(args);
                        <Contract>::mint(
                            stream
                                .pop::<H256>()
                                .expect("could not decode argument `owner` as `H256`"),
                            stream
                                .pop::<H256>()
                                .expect("could not decode argument `addr` as `H256`"),
                            stream
                                .pop::<U256>()
                                .expect("could not decode argument `tokens` as `U256`"),
                            stream
                                .pop::<Vec<u8>>()
                                .expect("could not decode argument `sig` as `Vec < u8 >`"),
                        );
                    }
                    "total_supply" => {
                        let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(args);
                        let result = <Contract>::total_supply();
                        let mut result_bytes = eng_wasm::Vec::with_capacity(1usize * 32);
                        let mut sink = eng_wasm::eng_pwasm_abi::eth::Sink::new(1usize);
                        sink.push(result);
                        sink.drain_to(&mut result_bytes);
                        unsafe {
                            eng_wasm::external::ret(
                                result_bytes.as_ptr(),
                                result_bytes.len() as u32
                            )
                        }
                    }
                    "balance_of" => {
                        let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(args);
                        let result = <Contract>::balance_of(
                            stream
                                .pop::<H256>()
                                .expect("could not decode argument `token_owner` as `H256`"),
                        );
                        let mut result_bytes = eng_wasm::Vec::with_capacity(1usize * 32);
                        let mut sink = eng_wasm::eng_pwasm_abi::eth::Sink::new(1usize);
                        sink.push(result);
                        sink.drain_to(&mut result_bytes);
                        unsafe {
                            eng_wasm::external::ret(
                                result_bytes.as_ptr(),
                                result_bytes.len() as u32
                            )
                        }
                    }
                    "allowance" => {
                        let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(args);
                        let result = <Contract>::allowance(
                            stream
                                .pop::<H256>()
                                .expect("could not decode argument `owner` as `H256`"),
                            stream
                                .pop::<H256>()
                                .expect("could not decode argument `spender` as `H256`"),
                        );
                        let mut result_bytes = eng_wasm::Vec::with_capacity(1usize * 32);
                        let mut sink = eng_wasm::eng_pwasm_abi::eth::Sink::new(1usize);
                        sink.push(result);
                        sink.drain_to(&mut result_bytes);
                        unsafe {
                            eng_wasm::external::ret(
                                result_bytes.as_ptr(),
                                result_bytes.len() as u32
                            )
                        }
                    }
                    "transfer" => {
                        let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(args);
                        <Contract>::transfer(
                            stream
                                .pop::<H256>()
                                .expect("could not decode argument `from` as `H256`"),
                            stream
                                .pop::<H256>()
                                .expect("could not decode argument `to` as `H256`"),
                            stream
                                .pop::<U256>()
                                .expect("could not decode argument `tokens` as `U256`"),
                            stream
                                .pop::<Vec<u8>>()
                                .expect("could not decode argument `sig` as `Vec < u8 >`"),
                        );
                    }
                    "approve" => {
                        let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(args);
                        <Contract>::approve(
                            stream
                                .pop::<H256>()
                                .expect("could not decode argument `token_owner` as `H256`"),
                            stream
                                .pop::<H256>()
                                .expect("could not decode argument `spender` as `H256`"),
                            stream
                                .pop::<U256>()
                                .expect("could not decode argument `tokens` as `U256`"),
                            stream
                                .pop::<Vec<u8>>()
                                .expect("could not decode argument `sig` as `Vec < u8 >`"),
                        );
                    }
                    "transfer_from" => {
                        let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(args);
                        <Contract>::transfer_from(
                            stream
                                .pop::<H256>()
                                .expect("could not decode argument `owner` as `H256`"),
                            stream
                                .pop::<H256>()
                                .expect("could not decode argument `spender` as `H256`"),
                            stream
                                .pop::<H256>()
                                .expect("could not decode argument `to` as `H256`"),
                            stream
                                .pop::<U256>()
                                .expect("could not decode argument `tokens` as `U256`"),
                            stream
                                .pop::<Vec<u8>>()
                                .expect("could not decode argument `sig` as `Vec < u8 >`"),
                        );
                    }
                    _ => panic!("Unknown method called:\"{}\"", name),
                }
            }
        );

        let expected_output_ast = syn::parse2::<syn::ItemFn>(expected_output)?;

        let signatures = syn::parse2::<PubInterfaceSignatures>(input)?;
        let output = generate_dispatch_function(&DISPATCH_FUNC_NAME.into_ident(), &signatures);
        let output_ast = syn::parse2::<syn::ItemFn>(output)?;

        assert_eq!(output_ast, expected_output_ast);
        Ok(())
    }
}
