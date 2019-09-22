use quote::{quote, quote_spanned, ToTokens};
use syn::spanned::Spanned;

mod parse_signatures;

use super::into_ident::IntoIdent;
use parse_signatures::{ParseError, PubInterfaceItemType, PubInterfaceSignatures};

const DEFAULT_IMPLEMENTOR_NAME: &str = "Contract";
const CONSTRUCTOR_NAME: &str = "construct";

const DEPLOY_FUNC_NAME: &str = "deploy";
const DISPATCH_FUNC_NAME: &str = "dispatch";
const FUNCTION_NAME_FUNC_NAME: &str = "function_name";
const ARGS_FUNC_NAME: &str = "args";
const CALL_FUNC_NAME: &str = "call";

pub(crate) fn impl_pub_interface(
    attr: proc_macro2::TokenStream,
    item: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let cloned_item = item.clone();

    // Make sure that even if we issue a compilation error, we still generate
    // the original code, just like a derive macro would.
    let parse_result = syn::parse2::<PubInterfaceSignatures>(cloned_item)
        // If the main parsing was successful, check the macro attribute for any overrides
        .and_then(|mut pub_interface_signatures| {
            apply_macro_attr(attr, &mut pub_interface_signatures)
                // This makes sure that the pub_interface_signatures is returned from this nested error handling
                .map(|()| pub_interface_signatures)
        });
    let pub_interface_signatures = match parse_result {
        Ok(pub_interface_signatures) => pub_interface_signatures,
        Err(error) => {
            let compilation_error = error.to_compile_error();
            return quote!(
                #item
                #compilation_error
            );
        }
    };

    let deploy_func_name = DEPLOY_FUNC_NAME.into_ident();
    let dispatch_func_name = DISPATCH_FUNC_NAME.into_ident();
    let function_name_func_name = FUNCTION_NAME_FUNC_NAME.into_ident();
    let args_func_name = ARGS_FUNC_NAME.into_ident();
    let call_func_name = CALL_FUNC_NAME.into_ident();

    let aux_functions = generate_eng_wasm_aux_functions(&function_name_func_name, &args_func_name);
    let constructor_function =
        generate_deploy_function(&deploy_func_name, &pub_interface_signatures);
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

/// Parse the arguments to the macro and apply them to the `PubInterfaceSignatures`
///
/// The arguments to the macro are the parts written between parenthesis in the macro invocation.
///
/// # Examples:
///
/// (This never actually gets compiled for some reason. You can try doing
/// `rustdoc --test src/lib.rs` but that generated compilation errors.
/// Probably because this is a pro-macro crate.)
///
/// ```
/// # use eng_wasm_derive::pub_interface;
///
/// #[pub_interface(MyContract)]
/// trait ContractInterface {
///     fn foo();
/// }
///
/// struct MyContract;
///
/// impl ContractInterface for MyContract {
///     fn foo() {}
/// }
/// ```
fn apply_macro_attr(
    attr: proc_macro2::TokenStream,
    pub_interface_signatures: &mut PubInterfaceSignatures,
) -> syn::Result<()> {
    if attr.is_empty() {
        return Ok(());
    }

    match pub_interface_signatures.item_type {
        PubInterfaceItemType::ItemTrait => {
            let implementor: syn::Type = syn::parse2(attr)?;
            pub_interface_signatures.implementor = implementor;
            Ok(())
        }
        PubInterfaceItemType::ItemImpl => Err(syn::Error::new_spanned(
            attr,
            ParseError::CustomImplementorOnImpl,
        )),
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
                    for _ in 0..length {
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
                    for _ in 0..length {
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
    deploy_func_name: &syn::Ident,
    signatures: &PubInterfaceSignatures,
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

        // Manually construct the code that implicitly checks properties of the input types
        // so that the spans of type errors are correctly propagated
        let parsed_inputs = input_pats_and_types
            .iter()
            .map(|(_pat, type_)| type_)
            .zip(expectations)
            .map(|(type_, expectation)|
                quote_spanned!(type_.span()=> stream.pop::<#type_>().expect(#expectation))
            );
        let variables = generate_enumerated_idents("var_", input_pats_and_types.len());

        return quote! {
            #[no_mangle]
            pub fn #deploy_func_name() {
                let args_ = args();
                let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(&args_);
                #(let #variables = #parsed_inputs;)*
                <#implementor>::#constructor_name(#(#variables),*);
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
                return None;
            }

            let method_name_as_string = method_name.to_string();
            let output_type = &signature.output;
            let input_pats_and_types = get_signature_input_pats_and_types(&signature);
            let expectations = get_contract_input_parsing_error_messages(&input_pats_and_types);

            // Manually construct the code that implicitly checks properties of the input types
            // so that the spans of type errors are correctly propagated
            let parsed_inputs = input_pats_and_types
                .iter()
                .map(|(_pat, type_)| type_)
                .zip(expectations)
                .map(|(type_, expectation)|
                    quote_spanned!(type_.span()=> stream.pop::<#type_>().expect(#expectation))
                );
            let variables = generate_enumerated_idents("var_", input_pats_and_types.len());

            let return_value_count = match output_type {
                syn::ReturnType::Default => 0,
                syn::ReturnType::Type(_, type_) => match type_.as_ref() {
                    // If the return value is a tuple, we count it like multiple return values.
                    // This is the same thing that pwasm_abi does under
                    // pwasm_abi/derive/src/item.rs :: fn into_signature
                    // which flows back to
                    // pwasm_abi/derive/src/lib.rs :: fn generate_eth_endpoint
                    // which dictates how return values are serialised into the Sink.
                    // This can be 0 if the return type is () which is correct.
                    syn::Type::Tuple(return_tuple) => return_tuple.elems.len(),
                    // Any other type is a single return value. Arrays such as [u8; 4]
                    // are not AbiType so Sink will reject them at compile time.
                    _ => 1,
                }
            };

            // Make sure we only generate code for initializing the stream of inputs,
            // if we expect inputs at all
            let stream_initialization_snippet = match input_pats_and_types.len() {
                0 => quote!(),
                _ => quote!(let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(args);),
            };

            match return_value_count {
                0 => Some(quote! {
                    #method_name_as_string => {
                        #stream_initialization_snippet
                        #(let #variables = #parsed_inputs;)*
                        <#implementor>::#method_name(#(#variables),*);
                    }
                }),
                _ => {
                    // Manually construct the code that implicitly checks properties of the return type
                    // so that the spans of type errors are correctly propagated
                    let result_token = quote!(result);
                    // disassociate the return type from the arrow.
                    let output_type = match output_type {
                        syn::ReturnType::Type(_arrow, type_) => type_,
                        syn::ReturnType::Default => unreachable!("We know that there is an explicit return type")
                    };
                    let push_result_to_sink = quote_spanned!(output_type.span()=> sink.push(#result_token));
                    Some(quote! {
                        #method_name_as_string => {
                            #stream_initialization_snippet
                            #(let #variables = #parsed_inputs;)*
                            let #result_token = <#implementor>::#method_name(#(#variables),*);
                            // 32 is the size of each argument in the serialised form
                            // The Sink.drain_to() method might resize this array if any
                            // dynamically sized elements are returned, but if not, then only one
                            // allocation (this one) will happen for the Vec.
                            let mut result_bytes = eng_wasm::Vec::with_capacity(#return_value_count * 32);
                            let mut sink = eng_wasm::eng_pwasm_abi::eth::Sink::new(#return_value_count);
                            #push_result_to_sink;
                            sink.drain_to(&mut result_bytes);
                            unsafe { eng_wasm::external::ret(result_bytes.as_ptr(), result_bytes.len() as u32) }
                        }
                    })
                },
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

/// Generate `count` identifiers with the specified prefix, and a decimal suffix in ascending order.
///
/// for example, calling `generate_enumerated_idents("var_", 5)` will generate a vector with the
/// identifiers `var_0`, `var_1`, `var_2`, `var_3`, `var_4`.
fn generate_enumerated_idents(prefix: &str, count: usize) -> Vec<syn::Ident> {
    (0..count)
        .map(|index| quote::format_ident!("{}{}", prefix, index))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This is here to use as a sanity check on the full generated code.
    ///
    /// To see what code is generated, comment out the `#[ignore]` line, and run
    /// ```sh
    /// cargo test show_output -- --nocapture
    /// ```
    /// Then, take the output from the console (between the two dotted lines, drop it into
    /// https://play.rust-lang.org/ , and under the tools menu, choose "Rustfmt".
    #[test]
    #[ignore]
    fn show_output() {
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

        let output = impl_pub_interface(quote!(), input);

        eprintln!("{:-<80}", "");
        eprintln!("{}", output);
        eprintln!("{:-<80}", "");
    }

    #[test]
    fn apply_macro_attr_works_on_trait() {
        let attr_tokens = quote!(Bar);

        let mut pub_interface_signatures = PubInterfaceSignatures {
            signatures: vec![],
            implementor: syn::parse2(quote!(Foo)).unwrap(),
            item_type: PubInterfaceItemType::ItemTrait,
        };

        apply_macro_attr(attr_tokens.clone(), &mut pub_interface_signatures).unwrap();

        assert_eq!(
            syn::parse2::<syn::Type>(attr_tokens).unwrap(),
            pub_interface_signatures.implementor
        );
    }

    #[test]
    fn apply_macro_attr_with_empty_input_works_on_trait() {
        let attr_tokens = quote!(); // This is empty

        let mut pub_interface_signatures = PubInterfaceSignatures {
            signatures: vec![],
            implementor: syn::parse2(quote!(Foo)).unwrap(),
            item_type: PubInterfaceItemType::ItemTrait,
        };

        apply_macro_attr(attr_tokens.clone(), &mut pub_interface_signatures).unwrap();

        // Check that the implementor did not change
        assert_eq!(
            syn::parse2::<syn::Type>(quote!(Foo)).unwrap(),
            pub_interface_signatures.implementor
        );
    }

    #[test]
    fn apply_macro_attr_with_bad_input_fails_on_trait() {
        let attr_tokens = quote!(this is not a valid type);

        let mut pub_interface_signatures = PubInterfaceSignatures {
            signatures: vec![],
            implementor: syn::parse2(quote!(Foo)).unwrap(),
            item_type: PubInterfaceItemType::ItemTrait,
        };

        let error =
            apply_macro_attr(attr_tokens.clone(), &mut pub_interface_signatures).unwrap_err();

        assert_eq!(error.to_string(), "unexpected token");
        // Check that the implementor did not change
        assert_eq!(
            syn::parse2::<syn::Type>(quote!(Foo)).unwrap(),
            pub_interface_signatures.implementor
        );
    }

    #[test]
    fn apply_macro_attr_with_empty_input_works_on_impl() {
        let attr_tokens = quote!(); // This is empty

        let mut pub_interface_signatures = PubInterfaceSignatures {
            signatures: vec![],
            implementor: syn::parse2(quote!(Foo)).unwrap(),
            item_type: PubInterfaceItemType::ItemImpl,
        };

        apply_macro_attr(attr_tokens.clone(), &mut pub_interface_signatures).unwrap();

        // Check that the implementor did not change
        assert_eq!(
            syn::parse2::<syn::Type>(quote!(Foo)).unwrap(),
            pub_interface_signatures.implementor
        );
    }

    #[test]
    fn apply_macro_attr_fails_on_impl() {
        let attr_tokens = quote!(Bar);

        let mut pub_interface_signatures = PubInterfaceSignatures {
            signatures: vec![],
            implementor: syn::parse2(quote!(Foo)).unwrap(),
            item_type: PubInterfaceItemType::ItemImpl,
        };

        let error =
            apply_macro_attr(attr_tokens.clone(), &mut pub_interface_signatures).unwrap_err();

        assert_eq!(
            error.to_string(),
            ParseError::CustomImplementorOnImpl.to_string()
        );
        // Check that the implementor did not change
        assert_eq!(
            syn::parse2::<syn::Type>(quote!(Foo)).unwrap(),
            pub_interface_signatures.implementor
        );
    }

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
                let var_0 = stream
                    .pop::<H256>()
                    .expect("could not decode argument `contract_owner` as `H256`");
                let var_1 = stream
                    .pop::<U256>()
                    .expect("could not decode argument `total_supply` as `U256`");
                <Contract>::construct(var_0, var_1);
            }
        );

        let signatures = syn::parse2::<PubInterfaceSignatures>(input)?;
        let output = generate_deploy_function(&DEPLOY_FUNC_NAME.into_ident(), &signatures);

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
                        let var_0 = stream
                            .pop::<H256>()
                            .expect("could not decode argument `owner` as `H256`");
                        let var_1 = stream
                            .pop::<H256>()
                            .expect("could not decode argument `addr` as `H256`");
                        let var_2 = stream
                            .pop::<U256>()
                            .expect("could not decode argument `tokens` as `U256`");
                        let var_3 = stream
                            .pop::<Vec<u8>>()
                            .expect("could not decode argument `sig` as `Vec < u8 >`");
                        <Contract>::mint(var_0, var_1, var_2, var_3);
                    }
                    "total_supply" => {
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
                        let var_0 = stream
                            .pop::<H256>()
                            .expect("could not decode argument `token_owner` as `H256`");
                        let result = <Contract>::balance_of(var_0);
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
                        let var_0 = stream
                            .pop::<H256>()
                            .expect("could not decode argument `owner` as `H256`");
                        let var_1 = stream
                            .pop::<H256>()
                            .expect("could not decode argument `spender` as `H256`");
                        let result = <Contract>::allowance(var_0, var_1);
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
                        let var_0 = stream
                            .pop::<H256>()
                            .expect("could not decode argument `from` as `H256`");
                        let var_1 = stream
                            .pop::<H256>()
                            .expect("could not decode argument `to` as `H256`");
                        let var_2 = stream
                            .pop::<U256>()
                            .expect("could not decode argument `tokens` as `U256`");
                        let var_3 = stream
                            .pop::<Vec<u8>>()
                            .expect("could not decode argument `sig` as `Vec < u8 >`");
                        <Contract>::transfer(var_0, var_1, var_2, var_3);
                    }
                    "approve" => {
                        let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(args);
                        let var_0 = stream
                            .pop::<H256>()
                            .expect("could not decode argument `token_owner` as `H256`");
                        let var_1 = stream
                            .pop::<H256>()
                            .expect("could not decode argument `spender` as `H256`");
                        let var_2 = stream
                            .pop::<U256>()
                            .expect("could not decode argument `tokens` as `U256`");
                        let var_3 = stream
                            .pop::<Vec<u8>>()
                            .expect("could not decode argument `sig` as `Vec < u8 >`");
                        <Contract>::approve(var_0, var_1, var_2, var_3);
                    }
                    "transfer_from" => {
                        let mut stream = eng_wasm::eng_pwasm_abi::eth::Stream::new(args);
                        let var_0 = stream
                            .pop::<H256>()
                            .expect("could not decode argument `owner` as `H256`");
                        let var_1 = stream
                            .pop::<H256>()
                            .expect("could not decode argument `spender` as `H256`");
                        let var_2 = stream
                            .pop::<H256>()
                            .expect("could not decode argument `to` as `H256`");
                        let var_3 = stream
                            .pop::<U256>()
                            .expect("could not decode argument `tokens` as `U256`");
                        let var_4 = stream
                            .pop::<Vec<u8>>()
                            .expect("could not decode argument `sig` as `Vec < u8 >`");
                        <Contract>::transfer_from(var_0, var_1, var_2, var_3, var_4);
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
