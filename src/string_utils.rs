use core::ptr::null_mut;
use kerror::{Error, IntoResult};
use nt_string::unicode_string::{NtUnicodeStr, NtUnicodeString};
use wdk_sys::{
    ntddk::{
        FsRtlIsNameInExpression, RtlCompareUnicodeString, RtlDowncaseUnicodeString,
        RtlPrefixUnicodeString, RtlUpcaseUnicodeChar, RtlUpcaseUnicodeString,
    },
    STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_PARAMETER, UNICODE_STRING,
};

/// Compare two Unicode characters for equality.
#[allow(dead_code)]
fn cmp_unicode_chars(ch1: char, ch2: char) -> bool {
    cmp_unicode_chars_impl(ch1, ch2, false)
}

/// Compare two Unicode characters, ignoring case differences.
#[allow(dead_code)]
fn cmp_unicode_chars_no_case(ch1: char, ch2: char) -> bool {
    cmp_unicode_chars_impl(ch1, ch2, true)
}

/// Internal function to compare Unicode characters with optional case insensitivity.
///
/// If `case_insensitive` is true, both characters are converted to uppercase before comparison.
/// Otherwise, they are compared directly.
fn cmp_unicode_chars_impl(ch1: char, ch2: char, case_insensitive: bool) -> bool {
    if case_insensitive {
        // SAFETY:
        // Inherently unsafe as a system call, `RtlUpcaseUnicodeChar`
        // reads copies `ch1` and `ch2` and compares them. `ch1` and `ch2`
        // must be valid unicode characters
        unsafe { RtlUpcaseUnicodeChar(ch1 as u16) == RtlUpcaseUnicodeChar(ch2 as u16) }
    } else {
        ch1 == ch2
    }
}

/// Check if a string matches a given regex pattern.
///
/// This function calls the `FsRtlIsNameInExpression` system function to evaluate
/// whether `string` matches the `regex` pattern, optionally ignoring case differences.
fn matches_impl(string: &NtUnicodeStr, regex: &NtUnicodeStr, case_insensitive: bool) -> bool {
    // SAFETY:
    // Inherently unsafe as a system call, `FsRtlIsNameInExpression`
    // reads `string` and `regex` via a const pointer. The caller ensures that
    // `string` and `regex` are properly initialized and accessible to avoid
    // undefined behavior.
    unsafe {
        FsRtlIsNameInExpression(
            regex.as_ptr().cast::<UNICODE_STRING>().cast_mut(),
            string.as_ptr().cast::<UNICODE_STRING>().cast_mut(),
            case_insensitive.into(),
            null_mut(),
        ) != 0
    }
}

/// Check if `str1` starts with `str2`, with optional case insensitivity.
///
/// Calls `RtlPrefixUnicodeString` to determine if `str1` begins with `str2`.
fn starts_with_impl(str1: &NtUnicodeStr, str2: &NtUnicodeStr, case_insensitive: bool) -> bool {
    // SAFETY:
    // Inherently unsafe as a system call, `RtlPrefixUnicodeString`
    // reads `str1` and `str2` via a const pointer. The caller ensures that
    // `str1` and `str2` are properly initialized and accessible to avoid
    // undefined behavior.
    unsafe {
        RtlPrefixUnicodeString(
            str2.as_ptr().cast::<UNICODE_STRING>(),
            str1.as_ptr().cast::<UNICODE_STRING>(),
            case_insensitive.into(),
        ) != 0
    }
}

/// Check if `str1` ends with `str2`, with optional case insensitivity.
///
/// This function compares characters from the end of `str1` and `str2`.
/// If `str2` is longer than `str1`, it returns false immediately.
fn ends_with_impl(str1: &NtUnicodeStr, str2: &NtUnicodeStr, case_insensitive: bool) -> bool {
    if str2.len() > str1.len() {
        return false;
    }

    str1.chars()
        .rev()
        .zip(str2.chars().rev())
        .all(|(ch1, ch2)| cmp_unicode_chars_impl(ch1.unwrap(), ch2.unwrap(), case_insensitive))
}

/// Check if two strings are equal, with optional case insensitivity.
///
/// Calls `RtlCompareUnicodeString` to compare `str1` and `str2`.
fn equals_impl(str1: &NtUnicodeStr, str2: &NtUnicodeStr, case_insensitive: bool) -> bool {
    // SAFETY:
    // Inherently unsafe as a system call, `RtlCompareUnicodeString`
    // reads `str1` and `str2` via a const pointer. The caller ensures that
    // `str1` and `str2` are properly initialized and accessible to avoid
    // undefined behavior.
    unsafe {
        RtlCompareUnicodeString(
            str1.as_ptr().cast::<UNICODE_STRING>(),
            str2.as_ptr().cast::<UNICODE_STRING>(),
            case_insensitive.into(),
        ) == 0
    }
}

/// Trait for converting Unicode strings to uppercase or lowercase.
#[allow(dead_code)]
pub trait NtStringConvert {
    /// Convert string to uppercase
    fn convert_to_upper(&mut self) -> kerror::Result<()>;
    /// Convert string to lowercase
    fn convert_to_lower(&mut self) -> kerror::Result<()>;
}

impl NtStringConvert for NtUnicodeString {
    fn convert_to_upper(&mut self) -> kerror::Result<()> {
        // SAFETY:
        // Inherently unsafe as a system call, `RtlUpcaseUnicodeString`
        // modifies `self` via a mutable pointer. The caller ensures that
        // `self` is properly initialized and accessible to avoid undefined
        // behavior.
        unsafe {
            RtlUpcaseUnicodeString(self.as_mut_ptr().cast(), self.as_ptr().cast(), false.into())
        }
        .into_result()
    }

    fn convert_to_lower(&mut self) -> kerror::Result<()> {
        // SAFETY:
        // Inherently unsafe as a system call, `RtlDowncaseUnicodeString`
        // modifies `self` via a mutable pointer. The caller ensures that
        // `self` is properly initialized and accessible to avoid undefined
        // behavior.
        unsafe {
            RtlDowncaseUnicodeString(self.as_mut_ptr().cast(), self.as_ptr().cast(), false.into())
        }
        .into_result()
    }
}

#[allow(dead_code)]
pub trait NtStrExt {
    /// Create a [`NtUnicodeStr`] from a raw pointer to the `string` parameter.
    fn from_native_str<'a>(string: *const UNICODE_STRING) -> kerror::Result<NtUnicodeStr<'a>>;

    /// Check if string matches the `regex` parameter.
    fn mathes(&self, regex: &NtUnicodeStr) -> bool;
    /// Check if string matches the `regex` parameter. Ignores case.
    fn mathes_no_case(&self, regex: &NtUnicodeStr) -> bool;

    /// Get length of the string in 2-byte characters.
    fn len_in_elements(&self) -> usize;

    /// Check if string starts with `str` string.
    fn starts_with(&self, str: &NtUnicodeStr) -> bool;
    /// Check if string starts with `str` string. Ignores case.
    fn starts_with_no_case(&self, str: &NtUnicodeStr) -> bool;

    /// Check if string ends with `str`.
    fn ends_with(&self, str: &NtUnicodeStr) -> bool;
    /// Check if string ends with `str`. Ignores case.
    fn ends_with_no_case(&self, str: &NtUnicodeStr) -> bool;

    /// Check if string equals `str` parameter.
    fn equals(&self, str: &NtUnicodeStr) -> bool;
    /// Check if string equals `str` parameter. Ignores case.
    fn equals_no_case(&self, str: &NtUnicodeStr) -> bool;

    /// Get last index of the `ch` character in this string.
    fn last_index_of(&self, ch: u16) -> Option<usize>;

    /// Splits the string at the given index and attempts to create an [`NtUnicodeString`] from the second half.
    fn substring(&self, idx: u16) -> kerror::Result<NtUnicodeString>;
    /// Returns the second half of the string split at the given index.
    fn substr(&self, idx: u16) -> kerror::Result<NtUnicodeStr<'_>>;

    /// Extracts a slice of the string between the given start and end indices.
    /// Ensures indices are valid and within bounds before extracting the substring.
    fn slice(&self, idx_start: u16, idx_end: u16) -> kerror::Result<NtUnicodeStr<'_>>;

    /// Splits the string at the specified index and returns the two resulting substrings.
    /// Returns an error if the index is out of bounds.
    fn split_at(&self, mid: u16) -> kerror::Result<(NtUnicodeStr<'_>, NtUnicodeStr<'_>)>;
}

impl NtStrExt for NtUnicodeStr<'_> {
    /// Create a [`NtUnicodeStr`] from a raw pointer to the `string` parameter.
    ///
    /// Returns an `Err(Error(STATUS_INVALID_PARAMETER))` if `string` is a null pointer.
    fn from_native_str<'a>(string: *const UNICODE_STRING) -> kerror::Result<NtUnicodeStr<'a>> {
        let str =
            // SAFETY: Get reference from the raw pointer is safe because it's checked to be non-null
            unsafe { string.as_ref() }.ok_or(Error::from_ntstatus(STATUS_INVALID_PARAMETER))?;

        // SAFETY: Raw data used to create a NtUnicodeStr from the UNICODE_STRING reference. It's safe to
        // read it's fields because it's a valid data. This caller assumes that referenced memory really points
        // to UNICODE_STRING
        Ok(unsafe { NtUnicodeStr::from_raw_parts(str.Buffer, str.Length, str.MaximumLength) })
    }

    fn mathes(&self, regex: &NtUnicodeStr) -> bool {
        matches_impl(self, regex, false)
    }

    fn mathes_no_case(&self, regex: &NtUnicodeStr) -> bool {
        matches_impl(self, regex, true)
    }

    fn len_in_elements(&self) -> usize {
        self.as_slice().len()
    }

    fn starts_with(&self, str: &NtUnicodeStr) -> bool {
        starts_with_impl(self, str, false)
    }

    fn starts_with_no_case(&self, str: &NtUnicodeStr) -> bool {
        starts_with_impl(self, str, true)
    }

    fn ends_with(&self, str: &NtUnicodeStr) -> bool {
        ends_with_impl(self, str, false)
    }

    fn ends_with_no_case(&self, str: &NtUnicodeStr) -> bool {
        ends_with_impl(self, str, true)
    }

    fn equals(&self, str: &NtUnicodeStr) -> bool {
        equals_impl(self, str, false)
    }

    fn equals_no_case(&self, str: &NtUnicodeStr) -> bool {
        equals_impl(self, str, true)
    }

    fn last_index_of(&self, ch_to_find: u16) -> Option<usize> {
        self.as_slice().iter().rposition(|ch| *ch == ch_to_find)
    }

    fn substring(&self, idx: u16) -> kerror::Result<NtUnicodeString> {
        Ok(NtUnicodeString::try_from_u16(
            self.split_at(idx)?.1.as_slice(),
        )?)
    }

    fn substr(&self, idx: u16) -> kerror::Result<NtUnicodeStr<'_>> {
        Ok(self.split_at(idx)?.1)
    }

    fn slice(&self, idx_start: u16, idx_end: u16) -> kerror::Result<NtUnicodeStr<'_>> {
        if idx_start > idx_end {
            return Err(Error::from_ntstatus(STATUS_INFO_LENGTH_MISMATCH));
        }

        if idx_end > u16::try_from(self.len_in_elements())? {
            return Err(Error::from_ntstatus(STATUS_INFO_LENGTH_MISMATCH));
        }

        let byte_length = (idx_end - idx_start) as usize * size_of::<u16>();

        // SAFETY: Raw data used to create a NtUnicodeStr from indices. These indices are
        // checked for correctness: idx_start cannot be greater than idx_end and idx_end
        // cannot be beyond end.
        Ok(unsafe {
            NtUnicodeStr::from_raw_parts(
                self.as_slice().as_ptr().offset(isize::try_from(idx_start)?),
                u16::try_from(byte_length)?,
                u16::try_from(byte_length)?,
            )
        })
    }

    fn split_at(&self, mid: u16) -> kerror::Result<(NtUnicodeStr<'_>, NtUnicodeStr<'_>)> {
        if mid > u16::try_from(self.len_in_elements())? {
            return Err(Error::from_ntstatus(STATUS_INFO_LENGTH_MISMATCH));
        }

        let parts = self.as_u16str().split_at(mid as _);

        let lpart = NtUnicodeStr::try_from(parts.0)?;
        let rpart = NtUnicodeStr::try_from(parts.1)?;

        Ok((lpart, rpart))
    }
}
