static EMPTY: [u8; 1] = [0];

pub trait SliceCPtr {
    type Target;
    fn as_c_ptr(&self) -> *const Self::Target;
}

impl<T> SliceCPtr for [T] {
    type Target = T;
    fn as_c_ptr(&self) -> *const Self::Target {
        if self.is_empty() {
            EMPTY.as_ptr() as *const _
        } else {
            self.as_ptr()
        }
    }
}

impl SliceCPtr for str {
    type Target = u8;
    fn as_c_ptr(&self) -> *const Self::Target {
        if self.is_empty() {
            EMPTY.as_ptr() as *const _
        } else {
            self.as_ptr()
        }
    }
}