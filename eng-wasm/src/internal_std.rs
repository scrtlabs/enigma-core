pub extern crate std;

pub use self::std::fmt;

pub use self::std::{
    io, iter, mem,
    slice::Join,
    str::from_utf8,
    string::{String, ToString},
    vec::Vec,
    vec,
};

#[macro_use]
pub(crate) mod std_macro {
    #[macro_export]
    macro_rules! eformat {
        ( $($arg:tt)* ) => (
            $crate::fmt::format( format_args!($($arg)*) )
        )
    }
}
