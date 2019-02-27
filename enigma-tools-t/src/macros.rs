#[macro_export]
macro_rules! debugln {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            println!($($arg)*);
        }
    };
}