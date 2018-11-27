pub extern crate std;

pub use self::std::fmt;
//pub use self::std::prelude::v1::*;
pub use self::std::iter;
pub use self::std::string::{ToString, String};
pub use self::std::vec::Vec;
pub use self::std::str::from_utf8;
pub use self::std::io;
pub use self::std::slice::SliceConcatExt;

//pub fn zeroed_vec(s: usize) -> Vec<u8>  {
//    vec![0u8; s]
//}
#[macro_use]
pub mod std_macro {
    #[macro_export]
    macro_rules! eformat {
        ( $($arg:tt)* ) => (
            $crate::fmt::format( format_args!($($arg)*) )
        )
    }
}