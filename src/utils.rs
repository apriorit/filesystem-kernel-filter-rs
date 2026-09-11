use alloc::vec::Vec;
use core::ops;

pub trait TryPush<T> {
    /// Try to allocate enough space to insert a single element. Return an error if allocation fails
    fn try_push(&mut self, element: T) -> ntresult::Result<()>;
}

impl<T> TryPush<T> for Vec<T> {
    /// Reserve space for at least one additional element. Insert the element into the vector.
    /// Return an error if allocation fails
    fn try_push(&mut self, element: T) -> ntresult::Result<()> {
        self.try_reserve(1)?;

        self.push(element);

        Ok(())
    }
}

/// Checks if any of the specified `flags` are set in the given `value`.
pub fn is_any_flag_set<T>(value: T, flags: T) -> bool
where
    T: ops::BitAnd<Output = T> + PartialEq + Copy + Default,
{
    (value & flags) != T::default()
}
