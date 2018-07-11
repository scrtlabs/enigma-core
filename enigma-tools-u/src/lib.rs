#![crate_type = "lib"]

#[macro_use]
extern crate failure;
extern crate reqwest;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate rlp;
pub mod attestation_service;
pub mod common_u;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
