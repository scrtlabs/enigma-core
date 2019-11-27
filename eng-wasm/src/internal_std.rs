pub use std::fmt;

pub use std::{
    io, iter, mem,
    slice::Join,
    str::from_utf8,
    string::{String, ToString},
    vec::Vec,
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
