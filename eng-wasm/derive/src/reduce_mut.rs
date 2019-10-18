/// This trait adds the `reduce_mut` method to all iterators.
///
/// The reduce_mut method takes the first item in the iterator, and then applies the supplied
/// operation on it with each subsequent item in the iterator as input.
///
/// This is a slight modification of https://github.com/dtolnay/reduce
///
/// We should file a pull request against dtolnay/reduce to merge this upstream.
pub trait ReduceMut<T> {
    fn reduce_mut<F>(self, f: F) -> Option<T>
    where
        Self: Sized,
        F: FnMut(&mut T, T);
}

impl<T, I> ReduceMut<T> for I
where
    I: Iterator<Item = T>,
{
    #[inline]
    fn reduce_mut<F>(mut self, mut f: F) -> Option<T>
    where
        Self: Sized,
        F: FnMut(&mut T, T),
    {
        self.next().map(|mut first| {
            for item in self {
                f(&mut first, item);
            }
            first
        })
    }
}
