#![no_std]

#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate serde_json;
extern crate serde;
extern crate rmp_serde as rmps;
extern crate enigma_tools_t;

pub mod state;

pub mod tests {
    use state::{ContractState, IOInterface};
    use std::string::String;
    use serde_json;
    use serde_json::map::Map;
    pub fn it_works() {
        let mut s = ContractState::new("Hi!");
        let value = json!({
            "code": 200,
            "success": true,
            "payload": {
                "features": [
                    "serde",
                    "json"]
            }
        });
        s.write_key("a", value).unwrap();
        s.write_key("b", json!(9)).unwrap();
//        let b = s.read_key("ab").clone();
        let a: Map<String, serde_json::Value> = s.read_key("a").unwrap();
        println!("a: {:?}", a);
        println!("WHY: {:?}", &s);
        let wha: u64 = s.read_key("b").unwrap();
        let qq: Map<String, serde_json::Value> = s.read_key("a").unwrap();
        println!("WHY: {:?}", wha);
        println!("WHY: {:?}", qq);
        let ser =  s.serialize();
        println!("serialized: {:?}", ser);
        let back = ContractState::parse("WOO", ser.unwrap());
        println!("{:?}", back);

        assert_eq!(2 + 2, 4);
    }
}
