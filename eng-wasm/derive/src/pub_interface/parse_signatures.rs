//! This module defines the parsing of input for the `#[pub_interface]` macro

use quote::quote;
use syn::parse::discouraged::Speculative;

use parse_display::Display;

use crate::into_ident::IntoIdent;
use crate::reduce_mut::ReduceMut;

use crate::pub_interface::CONSTRUCTOR_NAME;

/// Failures that can happen while parsing the macro input.
///
/// This type mostly exists to pass into syn::Error as an error message.
#[derive(Display, Debug)]
pub(crate) enum ParseError {
    #[display("pub_interface item must be either a trait or an inherent struct impl")]
    BadInputItem,

    #[display("pub_interface item can not be a trait impl")]
    TraitImpl,

    #[display("The constructor function of a secret contract should be `pub`")]
    PrivateImplConstructor,

    #[display("The constructor function of a secret contract should not have a return value")]
    ConstructorWithReturnValue,

    #[display("pub_interface item can not have methods that receive `self`")]
    MethodWithReceiver,

    #[display(
        "methods in traits annotated with pub_interface should not define default implementations"
    )]
    TraitMethodWithImplementation,

    #[display(
        "methods in traits annotated with pub_interface should not be annotated with additional attributes"
    )]
    TraitMethodWithAttributes,

    #[display(
        "methods in impls annotated with pub_interface should not be annotated with no_mangle"
    )]
    ImplMethodWithNoMangleAttribute,

    #[display("methods in impls annotated with pub_interface should be either `fn` or `pub fn`")]
    ImplMethodWithBadVisibility,

    #[display("custom implementors are not supported when pub_interface is applied to `impl`s")]
    CustomImplementorOnImpl,
}

/// This enum is used to present the result of the speculative parsing inside
/// `impl syn::parse::Parse for PubInterfaceSignatures` which tries to parse the macro input
/// in one of several ways
enum PubInterfaceInput {
    ItemTrait(syn::ItemTrait),
    ItemImpl(syn::ItemImpl),
}

/// This enum is used to record what kind of item the macro was applied to.
///
/// This information is used later when considering the macro `attr` to modify the
/// `PubInterfaceSignatures` that was parsed in this module.
#[derive(Copy, Clone)]
pub(crate) enum PubInterfaceItemType {
    ItemTrait,
    ItemImpl,
}

/// The signatures collected while parsing the macro input
#[derive(Clone)]
pub(crate) struct PubInterfaceSignatures {
    /// The path to the type implementing the methods.
    pub(crate) implementor: syn::Type,

    /// The list of exported signatures
    pub(crate) signatures: Vec<syn::Signature>,

    /// This records what kind of item the macro was applied to
    pub(crate) item_type: PubInterfaceItemType,
}

impl syn::parse::Parse for PubInterfaceSignatures {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut forked_input;

        // Speculatively try to parse the input in several ways.

        // First, try to parse the input as a trait,
        // which will  be backwards compatible with the original API...
        let pub_interface_input = {
            forked_input = input.fork();
            forked_input
                .parse::<syn::ItemTrait>()
                .map(PubInterfaceInput::ItemTrait)
        }
        // If that fails, try to parse the input as an impl of a struct/enum...
        .or_else(|_err| {
            forked_input = input.fork();
            forked_input
                .parse::<syn::ItemImpl>()
                .map(PubInterfaceInput::ItemImpl)
        })
        // If one of the attempts worked,
        // signal to the parse mechanism that parsing finished successfully.
        .map(|pub_interface_input| {
            input.advance_to(&forked_input);
            pub_interface_input
        })
        // If none of the options worked, we tell the user that he gave us bad input.
        .map_err(|_err| input.error(ParseError::BadInputItem))?;

        let item_type: PubInterfaceItemType;
        let implementor: syn::Type;
        let signatures = match pub_interface_input {
            PubInterfaceInput::ItemTrait(item_trait) => {
                item_type = PubInterfaceItemType::ItemTrait;
                let default_implementor_name = super::DEFAULT_IMPLEMENTOR_NAME.into_ident();
                implementor = syn::parse2::<syn::Type>(quote!(#default_implementor_name)).unwrap();
                get_signatures_from_item_trait(item_trait)
            }
            PubInterfaceInput::ItemImpl(item_impl) => {
                if let Some(trait_) = item_impl.trait_ {
                    return Err(syn::Error::new_spanned(trait_.1, ParseError::TraitImpl));
                }

                item_type = PubInterfaceItemType::ItemImpl;
                implementor = *item_impl.self_ty.clone();
                get_signatures_from_item_impl(item_impl)
            }
        }?;

        Ok(Self {
            implementor,
            signatures,
            item_type,
        })
    }
}

/// Extract the signatures of methods defined in a trait.
///
/// If errors are found while parsing, they are all `.combine()`d into one error.
fn get_signatures_from_item_trait(
    item_trait: syn::ItemTrait,
) -> Result<Vec<syn::Signature>, syn::Error> {
    let (trait_methods, errors) = item_trait
        .items
        .into_iter()
        // Filter out anything that isn't a trait method
        .filter_map(get_trait_item_as_method)
        // For each method in the definition, collect problems `Vec<syn::Error>`
        .map(check_trait_method)
        .partition::<Vec<_>, _>(|item| item.is_ok());

    // Thanks to the .partition() above, we know that:
    // all `trait_methods` are `Result::Ok(syn::Signature)`
    // and all `errors` are `Result::Err(Vec<syn::Error>)`
    // so we can safely `.unwrap()` and `.err().unwrap()` below.
    // Note that `Result::unwrap_err()` requires `T: Debug` which
    // is false in this case. That's why we instead use `.err().unwrap()`

    if errors.is_empty() {
        Ok(trait_methods
            .into_iter()
            .map(|res| res.unwrap())
            .map(|method| method.sig)
            .collect())
    } else {
        let errors = errors.into_iter().map(|res| res.err().unwrap()).flatten();
        // We can unwrap here because we know that `errors` wasn't empty.`
        let combined_errors = errors.reduce_mut(syn::Error::combine).unwrap();
        Err(combined_errors)
    }
}

/// Try to extract a `syn::TraitItemMethod` from a `syn::TraitItem`
fn get_trait_item_as_method(trait_item: syn::TraitItem) -> Option<syn::TraitItemMethod> {
    if let syn::TraitItem::Method(trait_method) = trait_item {
        Some(trait_method)
    } else {
        None
    }
}

/// Check if the trait method is defined the way we want it.
///
/// Specifically we check that:
/// * it has no additional attributes on it (except doc comments)
/// * it has no `self` receiver
/// * it has no default implementation
/// * if it's the constructor function, we make sure it returns nothing.
fn check_trait_method(
    trait_method: syn::TraitItemMethod,
) -> Result<syn::TraitItemMethod, Vec<syn::Error>> {
    let mut errors = Vec::new();

    for attr in &trait_method.attrs {
        if attr
            .path
            .get_ident()
            .map(|ident| ident != "doc")
            // if it's not a simple ident, it's definitely not allowed
            .unwrap_or(true)
        {
            errors.push(syn::Error::new_spanned(
                attr.clone(),
                ParseError::TraitMethodWithAttributes,
            ))
        }
    }

    trait_method.sig.inputs.first().map(|first_input| {
        if let syn::FnArg::Receiver(receiver) = first_input {
            errors.push(syn::Error::new_spanned(
                receiver.clone(),
                ParseError::MethodWithReceiver,
            ))
        }
    });

    if trait_method.sig.ident == CONSTRUCTOR_NAME && signature_has_return_value(&trait_method.sig) {
        errors.push(syn::Error::new_spanned(
            trait_method.sig.output.clone(),
            ParseError::ConstructorWithReturnValue,
        ))
    }

    if trait_method.default.is_some() {
        errors.push(syn::Error::new_spanned(
            trait_method.default.clone(),
            ParseError::TraitMethodWithImplementation,
        ))
    }

    if errors.is_empty() {
        Ok(trait_method)
    } else {
        Err(errors)
    }
}

/// Extract the signatures of methods defined in an impl.
///
/// If errors are found while parsing, they are all `.combine()`d into one error.
fn get_signatures_from_item_impl(
    item_impl: syn::ItemImpl,
) -> Result<Vec<syn::Signature>, syn::Error> {
    // Split the methods to private and non-private
    let (priv_methods, non_priv_methods) = item_impl
        .items
        .into_iter()
        .filter_map(get_impl_item_as_method)
        .partition::<Vec<_>, _>(is_impl_item_method_private);

    // Check things about the non-private methods (pub, pub(crate), pub(in foo::bar))
    let (impl_non_priv_methods, non_priv_method_errors) = non_priv_methods
        .into_iter()
        // For each method in the definition, collect problems `Vec<syn::Error>`
        .map(check_impl_non_priv_method)
        .partition::<Vec<_>, _>(|item| item.is_ok());

    // Check things about the private methods
    let (_impl_priv_methods, priv_method_errors) = priv_methods
        .into_iter()
        // For each method in the definition, collect problems `Vec<syn::Error>`
        .map(check_impl_priv_method)
        .partition::<Vec<_>, _>(|item| item.is_ok());

    // Collect all the different errors we found into one list.
    let errors = {
        let mut errors = non_priv_method_errors;
        errors.extend(priv_method_errors);
        errors
    };

    // Thanks to the .partition() above, we know that:
    // all `impl_non_priv_methods` are `Result::Ok(syn::Signature)`
    // and all `errors` are `Result::Err(Vec<syn::Error>)`
    // so we can safely `.unwrap()` and `.err().unwrap()` below.
    // Note that `Result::unwrap_err()` requires `T: Debug` which
    // is false in this case. That's why we instead use `.err().unwrap()`

    if errors.is_empty() {
        Ok(impl_non_priv_methods
            .into_iter()
            .map(|res| res.unwrap())
            .map(|method| method.sig)
            .collect())
    } else {
        let errors = errors.into_iter().map(|res| res.err().unwrap()).flatten();
        // We can unwrap here because we know that `errors` wasn't empty.`
        let combined_errors = errors.reduce_mut(syn::Error::combine).unwrap();
        Err(combined_errors)
    }
}

/// Try to extract a `syn::ImplItemMethod` from a `syn::ImplItem`
fn get_impl_item_as_method(impl_item: syn::ImplItem) -> Option<syn::ImplItemMethod> {
    if let syn::ImplItem::Method(impl_method) = impl_item {
        Some(impl_method)
    } else {
        None
    }
}

/// Check if a `syn::ImplItemMethod` is private
fn is_impl_item_method_private(method: &syn::ImplItemMethod) -> bool {
    if let syn::Visibility::Inherited = method.vis {
        true
    } else {
        false
    }
}

/// Check if the private impl-method is defined the way we want it.
///
/// Specifically we check that:
/// * it is not named like the constructor.
/// * if it's named like a constructor, check that it looks like a valid constructor.
fn check_impl_priv_method(
    impl_method: syn::ImplItemMethod,
) -> Result<syn::ImplItemMethod, Vec<syn::Error>> {
    let mut errors = Vec::new();

    if impl_method.sig.ident == CONSTRUCTOR_NAME {
        errors.push(syn::Error::new_spanned(
            impl_method.sig.clone(),
            ParseError::PrivateImplConstructor,
        ));

        if signature_has_return_value(&impl_method.sig) {
            errors.push(syn::Error::new_spanned(
                impl_method.sig.output.clone(),
                ParseError::ConstructorWithReturnValue,
            ))
        }
    }

    if errors.is_empty() {
        Ok(impl_method)
    } else {
        Err(errors)
    }
}

/// Check if the non-private impl-method is defined the way we want it.
///
/// Specifically we check that:
/// * it has no `#[no_mangle]` attribute on it
/// * it is not pub(crate) or similar
/// * it has no `self` receiver
fn check_impl_non_priv_method(
    impl_method: syn::ImplItemMethod,
) -> Result<syn::ImplItemMethod, Vec<syn::Error>> {
    let mut errors = Vec::new();

    for attr in &impl_method.attrs {
        if let Some(attr_name) = attr.path.segments.last() {
            if attr_name.ident == "no_mangle" {
                errors.push(syn::Error::new_spanned(
                    attr.clone(),
                    ParseError::ImplMethodWithNoMangleAttribute,
                ));
            }
        }
    }

    match &impl_method.vis {
        syn::Visibility::Public(_) | syn::Visibility::Inherited => {}
        _ => errors.push(syn::Error::new_spanned(
            impl_method.vis.clone(),
            ParseError::ImplMethodWithBadVisibility,
        )),
    }

    impl_method.sig.inputs.first().map(|first_input| {
        if let syn::FnArg::Receiver(receiver) = first_input {
            errors.push(syn::Error::new_spanned(
                receiver.clone(),
                ParseError::MethodWithReceiver,
            ))
        }
    });

    if impl_method.sig.ident == CONSTRUCTOR_NAME && signature_has_return_value(&impl_method.sig) {
        errors.push(syn::Error::new_spanned(
            impl_method.sig.output.clone(),
            ParseError::ConstructorWithReturnValue,
        ))
    }

    if errors.is_empty() {
        Ok(impl_method)
    } else {
        Err(errors)
    }
}

/// This function checks if the function has a non-unit return type.
///
/// This has two syntactic forms, either the function specifies no return type at all,
/// or explicitly states that it returns an empty tuple: `-> ()`.
fn signature_has_return_value(signature: &syn::Signature) -> bool {
    match &signature.output {
        syn::ReturnType::Default => false, // No return type specified
        syn::ReturnType::Type(_, type_) => match type_.as_ref() {
            syn::Type::Tuple(tuple) => match tuple.elems.len() {
                0 => false, // return type is ()
                _ => true,  // return type is some other tuple
            },
            _ => true, // return type is any other explicit type
        },
    }
}

#[cfg(test)]
mod tests {
    use quote::quote;

    use super::*;

    /// We can't parse `syn::Signature`s directly, so we wrap it up.
    macro_rules! signature_of {
        ($($tts:tt)*) => {{
            let method: syn::TraitItemMethod = syn::parse_quote!($($tts)*);
            method.sig
        }}
    }

    #[test]
    fn bad_input_error_for_trait_impl() {
        let tokens = quote!(
            impl Trait for Bar {}
        );

        let parse_errors = syn::parse2::<PubInterfaceSignatures>(tokens)
            .err()
            .expect("The macro should not accept trait impls");

        assert_eq!(
            vec![ParseError::TraitImpl.to_string()],
            parse_errors
                .into_iter()
                .map(|parse_error| parse_error.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn bad_input_error_for_struct() {
        let tokens = quote!(
            struct Foo(i32)
        );

        let parse_errors = syn::parse2::<PubInterfaceSignatures>(tokens)
            .err()
            .expect("The macro should not accept structs");

        assert_eq!(
            vec![ParseError::BadInputItem.to_string()],
            parse_errors
                .into_iter()
                .map(|parse_error| parse_error.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn bad_input_error_for_enum() {
        let tokens = quote!(
            enum Foo(i32)
        );

        let parse_errors = syn::parse2::<PubInterfaceSignatures>(tokens)
            .err()
            .expect("The macro should not accept enums");

        assert_eq!(
            vec![ParseError::BadInputItem.to_string()],
            parse_errors
                .into_iter()
                .map(|parse_error| parse_error.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn trait_signatures_parsing() -> syn::Result<()> {
        let tokens = quote!(
            trait Foo {
                fn foo();
                fn bar(_bar: i32) -> usize;
            }
        );

        let signatures = syn::parse2::<PubInterfaceSignatures>(tokens)?;

        assert_eq!(
            signatures.signatures,
            vec![
                signature_of!(fn foo();),
                signature_of!(fn bar(_bar: i32) -> usize;)
            ],
        );
        Ok(())
    }

    #[test]
    fn impl_signatures_parsing() -> syn::Result<()> {
        let tokens = quote!(
            impl Foo {
                pub fn foo() {}
                // Notice that this will be skipped in the parsing
                fn private() -> String {}
                pub fn bar(_bar: i32) -> usize {}
            }
        );

        let signatures = syn::parse2::<PubInterfaceSignatures>(tokens)?;

        assert_eq!(
            signatures.signatures,
            vec![
                signature_of!(fn foo();),
                signature_of!(fn bar(_bar: i32) -> usize;)
            ],
        );
        Ok(())
    }

    #[test]
    fn constructor_in_trait_with_no_return_type() -> syn::Result<()> {
        let tokens = quote!(
            trait Foo {
                fn construct();
            }
        );

        let signatures = syn::parse2::<PubInterfaceSignatures>(tokens)?;

        assert_eq!(signatures.signatures, vec![signature_of!(fn construct();)],);
        Ok(())
    }

    #[test]
    fn constructor_in_trait_with_unit_return_type() -> syn::Result<()> {
        let tokens = quote!(
            trait Foo {
                fn construct() -> ();
            }
        );

        let signatures = syn::parse2::<PubInterfaceSignatures>(tokens)?;

        assert_eq!(
            signatures.signatures,
            vec![signature_of!(fn construct() -> ();)],
        );
        Ok(())
    }

    #[test]
    fn constructor_in_trait_with_return_type_error() {
        let tokens = quote!(
            trait Foo {
                fn construct() -> Foo;
            }
        );

        let parse_errors = syn::parse2::<PubInterfaceSignatures>(tokens)
            .err()
            .expect("This macro should not accept constructors with return types");

        assert_eq!(
            vec![ParseError::ConstructorWithReturnValue.to_string(); 1],
            parse_errors
                .into_iter()
                .map(|parse_error| parse_error.to_string())
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn constructor_in_impl_with_no_return_type() -> syn::Result<()> {
        let tokens = quote!(
            impl Foo {
                pub fn construct() {}
            }
        );

        let signatures = syn::parse2::<PubInterfaceSignatures>(tokens)?;

        assert_eq!(signatures.signatures, vec![signature_of!(fn construct();)],);
        Ok(())
    }

    #[test]
    fn constructor_in_impl_with_unit_return_type() -> syn::Result<()> {
        let tokens = quote!(
            impl Foo {
                pub fn construct() -> () {}
            }
        );

        let signatures = syn::parse2::<PubInterfaceSignatures>(tokens)?;

        assert_eq!(
            signatures.signatures,
            vec![signature_of!(fn construct() -> ();)],
        );
        Ok(())
    }

    #[test]
    fn constructor_in_impl_with_return_type_error() {
        let tokens = quote!(
            impl Foo {
                pub fn construct() -> Foo {}
            }
        );

        let parse_errors = syn::parse2::<PubInterfaceSignatures>(tokens)
            .err()
            .expect("This macro should not accept constructors with return types");

        assert_eq!(
            vec![ParseError::ConstructorWithReturnValue.to_string(); 1],
            parse_errors
                .into_iter()
                .map(|parse_error| parse_error.to_string())
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn private_constructor_in_impl_error() {
        let tokens = quote!(
            impl Foo {
                fn construct() {}
            }
        );

        let parse_errors = syn::parse2::<PubInterfaceSignatures>(tokens)
            .err()
            .expect("This macro should not accept constructors without pub");

        assert_eq!(
            vec![ParseError::PrivateImplConstructor.to_string(); 1],
            parse_errors
                .into_iter()
                .map(|parse_error| parse_error.to_string())
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn trait_methods_with_attributes_errors() {
        let tokens = quote!(
            trait Foo {
                #[some_attribute]
                #[another_attribute]
                fn foo();

                #[yet_another_attribute]
                #[and_one_for_next_year]
                fn bar();
            }
        );

        let parse_errors = syn::parse2::<PubInterfaceSignatures>(tokens)
            .err()
            .expect("The macro should not accept attributes on trait methods");

        assert_eq!(
            vec![ParseError::TraitMethodWithAttributes.to_string(); 4],
            parse_errors
                .into_iter()
                .map(|parse_error| parse_error.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn trait_methods_with_doc_comments_parsing() -> syn::Result<()> {
        let tokens = quote!(
            trait Foo {
                /// do a foo
                fn foo();
                /// go to a bar
                fn bar(_bar: i32) -> usize;
            }
        );

        let signatures = syn::parse2::<PubInterfaceSignatures>(tokens)?;

        assert_eq!(
            signatures.signatures,
            vec![
                signature_of!(fn foo();),
                signature_of!(fn bar(_bar: i32) -> usize;)
            ],
        );
        Ok(())
    }

    #[test]
    fn trait_methods_with_self_receiver() {
        let tokens = quote!(
            trait Foo {
                fn foo(self);

                fn bar(&self);

                fn baz(&mut self);
            }
        );

        let parse_errors = syn::parse2::<PubInterfaceSignatures>(tokens)
            .err()
            .expect("The macro should not accept methods with `self` receiver");

        assert_eq!(
            vec![ParseError::MethodWithReceiver.to_string(); 3],
            parse_errors
                .into_iter()
                .map(|parse_error| parse_error.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn trait_methods_with_default_implementations_errors() {
        let tokens = quote!(
            trait Foo {
                fn foo() {
                    such_logic();
                }

                fn bar() {
                    much_default();
                }

                fn baz() {
                    wow!();
                }
            }
        );

        let parse_errors = syn::parse2::<PubInterfaceSignatures>(tokens)
            .err()
            .expect("The macro should not accept default implementations in trait methods");

        assert_eq!(
            vec![ParseError::TraitMethodWithImplementation.to_string(); 3],
            parse_errors
                .into_iter()
                .map(|parse_error| parse_error.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn impl_methods_with_no_mangle_attributes_errors() {
        let tokens = quote!(
            impl Foo {
                #[some_attribute]
                #[no_mangle]
                pub fn foo() {}

                #[yet_another_attribute]
                #[and_one_for_next_year]
                pub fn bar() {}
            }
        );

        let parse_errors = syn::parse2::<PubInterfaceSignatures>(tokens)
            .err()
            .expect("The macro should not accept no_mangle attributes on impl methods");

        assert_eq!(
            vec![ParseError::ImplMethodWithNoMangleAttribute.to_string()],
            parse_errors
                .into_iter()
                .map(|parse_error| parse_error.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn impl_methods_with_bad_visibility_errors() {
        let tokens = quote!(
            impl Foo {
                fn good_foo() {}

                pub(in super) fn bad_bar() {}

                pub(crate) fn bad_baz() {}

                pub fn good_qux() {}
            }
        );

        let parse_errors = syn::parse2::<PubInterfaceSignatures>(tokens)
            .err()
            .expect("The macro should not accept impl methods with complex visibility");

        assert_eq!(
            vec![ParseError::ImplMethodWithBadVisibility.to_string(); 2],
            parse_errors
                .into_iter()
                .map(|parse_error| parse_error.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn impl_methods_with_self_receiver() {
        let tokens = quote!(
            impl Foo {
                pub fn foo(self) {}

                pub fn bar(&self) {}

                pub fn baz(&mut self) {}
            }
        );

        let parse_errors = syn::parse2::<PubInterfaceSignatures>(tokens)
            .err()
            .expect("The macro should not accept methods with `self` receiver");

        assert_eq!(
            vec![ParseError::MethodWithReceiver.to_string(); 3],
            parse_errors
                .into_iter()
                .map(|parse_error| parse_error.to_string())
                .collect::<Vec<_>>(),
        )
    }
}
