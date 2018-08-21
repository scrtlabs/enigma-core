#![no_std]

#[cfg(not(test))]
#[macro_use]
extern crate sgx_tstd as std;
//#[macro_use]
//extern crate serde_json;
//extern crate rmp_serde as rmps;
//extern crate serde;
//extern crate json_patch;


#[cfg(test)]
mod tests {
    #![no_std]
//    #[macro_use]
//    extern crate sgx_tstd as std;
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
