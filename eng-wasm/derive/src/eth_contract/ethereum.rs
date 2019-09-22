use ethabi::param_type::{ParamType, Writer};
use tiny_keccak::Keccak;

pub fn short_signature(name: &str, params: &[ParamType]) -> u32 /*[u8; 4] */ {
    let mut result = [0u8; 4];
    fill_signature(name, params, &mut result);
    u32::from_be_bytes(result)
}

fn fill_signature(name: &str, params: &[ParamType], result: &mut [u8]) {
    let types = params
        .iter()
        .map(Writer::write)
        .collect::<Vec<String>>()
        .join(",");

    let data: Vec<u8> = From::from(format!("{}({})", name, types).as_str());

    let mut sponge = Keccak::new_keccak256();
    sponge.update(&data);
    sponge.finalize(result);
}
