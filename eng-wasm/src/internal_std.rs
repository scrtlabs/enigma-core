pub extern crate std;

pub use self::std::fmt;
// pub use self::std::prelude::v1::*;
pub use self::std::{
    io, iter, mem,
    slice::SliceConcatExt,
    str::from_utf8,
    string::{String, ToString},
    vec::Vec,
};

// pub fn zeroed_vec(s: usize) -> Vec<u8>  {
//    vec![0u8; s]
//}
#[macro_use]
pub(crate) mod std_macro {
    #[macro_export]
    macro_rules! eformat {
        ( $($arg:tt)* ) => (
            $crate::fmt::format( format_args!($($arg)*) )
        )
    }
}
