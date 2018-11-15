#![recursion_limit="128"]
extern crate eng_wasm;
extern crate proc_macro2;
#[macro_use] extern crate quote;
extern crate proc_macro;
#[macro_use]
extern crate syn;

use eng_wasm::*;

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
        pub fn args() -> String {
            let length_result = unsafe { external::fetch_args_length() };

            match length_result {
                0 => "".to_string(),
                length => {
                    let mut data = Vec::with_capacity(length as usize);
                    for _ in 0..length{
                        data.push(0);
                    }

                    unsafe {
                        external::fetch_args(data.as_mut_ptr());
                    }
                    from_utf8(&data).unwrap().to_string()
                }
            }
        }

    }
}

fn generate_dispatch(input: syn::Item) -> proc_macro2::TokenStream{
    let v;
    let functions= match input {
        syn::Item::Trait(input) => {
            v = input.items;
            v.iter()
        },
        _ => panic!(),
    };

    let it: Vec<proc_macro2::TokenStream> = functions.filter_map(|item| {
        match item {
                syn::TraitItem::Method(item) => {
                    let func = item.sig.ident.clone();
                    let arg_types: Vec<proc_macro2::TokenStream> = item.sig.decl.inputs.iter().filter_map(|arg| match arg {
                        // Argument captured by a name
                        syn::FnArg::Captured(arg_captured) => {
                            let ty = &arg_captured.ty;
                            Some(quote!{#ty})
                        },
                        // Argument without a name
                        syn::FnArg::Ignored(type_only) => {
                            Some(quote!{#type_only})
                        },
                        _ => None,
                    }).collect();

                    let name = &func.to_string();
                    println!("METHOD {:#?} TYPES {:#?}", item, arg_types);
                    Some(quote!{
                        #name => {
                            let mut stream = pwasm_abi::eth::Stream::new(args.as_bytes());

                            Contract::#func(#(stream.pop::<#arg_types>().expect("argument decoding failed")),*);

                        }
                    })
                },
                _ => None,
        }
    }).collect();


    quote! {
        pub fn dispatch(name: &str, args: &str){
            match name{
            #(#it,)*
            _=>panic!(),
            }
        }
    }
}

#[proc_macro_attribute]
#[allow(unused_variables, unused_mut)]
pub fn dispatch(args: proc_macro::TokenStream, input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input_tokens = parse_macro_input!(input as syn::Item);
    let disp = generate_dispatch(input_tokens.clone());
    let eng_wasm_aux = generate_eng_wasm_aux_functions();
    let result = quote! {
        #eng_wasm_aux
        #input_tokens
        #disp

        #[no_mangle]
        pub fn call(){
            dispatch(&function_name(), &args());
        }
    };
    proc_macro::TokenStream::from(result)
}
