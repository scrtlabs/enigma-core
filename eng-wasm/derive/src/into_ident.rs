pub trait IntoIdent {
    fn into_ident(self) -> syn::Ident;
}

impl IntoIdent for &str {
    fn into_ident(self) -> syn::Ident {
        quote::format_ident!("{}", self)
    }
}
