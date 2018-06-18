pub mod evm_t;


pub mod preprocessor{
    use sgx_trts::trts::rsgx_read_rand;
    // TODO: Implement Errors
    fn run(pre_sig: &str) -> Vec<u8> {
        match pre_sig {
            "rand()" | "rand" => rand(),
            _ => panic!()
        }
    }
    
    fn rand() -> Vec<u8> {
        let mut r: [u8; 16] = [0; 16];
        match rsgx_read_rand(&mut r) {
            Ok(_) => r.to_vec(),
            Err(err) => panic!(err)
        }
    }

}