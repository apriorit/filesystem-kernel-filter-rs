//! Conversions from foreign error types into [`ntresult::Error`].
//!
//! The orphan rule forbids `impl From<ForeignError> for ntresult::Error` here,
//! so these conversions are exposed as explicit trait methods instead of `?`.

pub mod hashbrown;
pub mod nt_string;

/// Convert a foreign error type into an [`ntresult::Error`].
pub trait IntoNtError {
    /// Convert `self` into the `Error` carrying the matching `NTSTATUS`.
    fn into_nt_error(self) -> ntresult::Error;
}

/// Convert a `Result` carrying a foreign error into an [`ntresult::Result`].
pub trait IntoNtResult<T> {
    /// Map the error half through [`IntoNtError`].
    fn into_nt_result(self) -> ntresult::Result<T>;
}

impl<T, E> IntoNtResult<T> for Result<T, E>
where
    E: IntoNtError,
{
    fn into_nt_result(self) -> ntresult::Result<T> {
        self.map_err(IntoNtError::into_nt_error)
    }
}
