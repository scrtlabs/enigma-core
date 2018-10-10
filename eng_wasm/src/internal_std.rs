#![macro_use]
extern crate std;

pub use self::std::vec::*;
pub use self::std::string::*;
pub use self::std::str::*;
pub use self::std::slice::*;
pub use self::std::fmt;


pub mod std_macro {
    #[macro_export]
    macro_rules! eformat {
    ( $($arg:tt)* ) => (
        $crate::fmt::format(format_args!($($arg)*))
    )
}
}