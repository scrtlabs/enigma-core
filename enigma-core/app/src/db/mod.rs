pub mod dal;
pub mod iterator;
pub mod primitives;

pub use crate::db::dal::*;
pub use crate::db::iterator::*;
pub use crate::db::primitives::*;


#[cfg(test)]
pub mod tests {
    extern crate tempfile;
    use self::tempfile::TempDir;
    use crate::db::DB;

    /// It's important to save TempDir too, because when it gets dropped the directory will be removed.
    pub fn create_test_db() -> (DB, TempDir) {
        let tempdir = tempfile::tempdir().unwrap();
        let db = DB::new(tempdir.path(), true).unwrap();
        (db, tempdir)
    }
}