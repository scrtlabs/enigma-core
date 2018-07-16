#![crate_type = "lib"]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde;
extern crate reqwest;
extern crate base64;
extern crate openssl;
extern crate rustc_hex as hex;

pub mod attestation_service;
pub mod common_u;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
