#![no_std]

use eng_wasm_derive::pub_interface;

struct S;

#[pub_interface]
impl S {
    pub fn find_number_of_prime_factors(mut number: u64) -> u64{
        if number == 0 {return 0;}
        // The maximal number of 2s that divide `number`
        let mut result = number.trailing_zeros() as u64;
        let factor_bound = ((number as f64).sqrt().ceil()) as u64;

        number >>= result;

        for i in (3..=factor_bound).step_by(2) {
            while number % i == 0 {
                result += 1;
                number = number / i;
            }
        }
        if number > 1 {
            result += 1;
        }
        result
    }
}

