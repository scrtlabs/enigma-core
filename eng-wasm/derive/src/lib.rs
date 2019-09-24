#![feature(slice_concat_trait)]

extern crate proc_macro;

use proc_macro::TokenStream;

/// This is a proc_macro2 equivalent of syn::parse_macro_input.
///
/// I placed it here because [that's how macro_rules scoping works][macro-rules-scoping]
/// and rust didn't like it when i put it in a module and exported it. If you figure out a
/// better way to hide it, please file a PR.
///
/// [macro-rules-scoping]: https://danielkeep.github.io/tlborm/book/mbe-min-scoping.html
macro_rules! parse_macro_input2 {
    ($input: ident as $type: ty) => {
        match syn::parse2::<$type>($input) {
            Ok(parsed) => parsed,
            // This is what generates the diagnostics for all our error messages.
            Err(error) => return error.to_compile_error(),
        };
    };
}

mod into_ident;
mod reduce_mut;

mod eth_contract;
mod pub_interface;

use eth_contract::impl_eth_contract;
use pub_interface::impl_pub_interface;

/// This macro is used in secret contracts to define which functions they export.
///
/// It can either be placed on a trait or impl block. If it is placed on a trait,
/// it is expected that a struct called `Contract` implements it. All methods defined on the
/// trait will be considered exported by the contract. If it is placed on an impl block,
/// all methods declared as pub will be exported by the contract. if placed on an impl block,
/// the implementing struct can have any name you choose.
#[proc_macro_attribute]
pub fn pub_interface(attr: TokenStream, item: TokenStream) -> TokenStream {
    impl_pub_interface(attr.into(), item.into()).into()
}

#[proc_macro_attribute]
pub fn eth_contract(attr: TokenStream, item: TokenStream) -> TokenStream {
    impl_eth_contract(attr.into(), item.into()).into()
}
