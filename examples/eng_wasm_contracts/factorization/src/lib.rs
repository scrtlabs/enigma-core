#![no_std]

use eng_wasm_derive::pub_interface;

struct S;

#[pub_interface]
impl S {
    pub fn find_number_of_prime_factors(mut number: u64) -> u64{
        let mut result: u64 = 0;
        let factor_bound = ((number as f64).sqrt().round() + 1.0) as u64;

        // The maximal number of 2s that divide `number`
        while number & 1 == 0 {
            result += 1;
            number = number.clone() >> 1;
        }

        for i in (3..factor_bound).step_by(2) {
            while number % i == 0 {
                result += 1;
                number = number.clone() / i;
            }
        }
        result
    }
}

