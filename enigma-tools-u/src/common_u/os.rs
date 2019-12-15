use gethostname;

pub fn hostname() -> String {
    gethostname::gethostname().into_string().unwrap()
}