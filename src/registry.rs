use crate::{
    kernel_objects::{
        cm_key_object_path::CmKeyObjectPath, handle::Handle, object_attributes::ObjectAttributes,
    },
    utils::TryPush,
};
use alloc::vec::Vec;
use core::ptr::null_mut;
use kerror::IntoResult;
use nt_string::unicode_string::{NtUnicodeStr, NtUnicodeString};
use wdk_sys::{
    ntddk::{
        CmCallbackGetKeyObjectIDEx, ZwCreateKey, ZwEnumerateKey, ZwEnumerateValueKey, ZwOpenKey,
    },
    HANDLE, KEY_ALL_ACCESS, KEY_BASIC_INFORMATION, KEY_VALUE_BASIC_INFORMATION, LARGE_INTEGER,
    NTSTATUS, OBJ_CASE_INSENSITIVE, OBJ_KERNEL_HANDLE, PULONG, PUNICODE_STRING, PVOID,
    STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER,
    STATUS_NO_MORE_ENTRIES, ULONG,
    _KEY_INFORMATION_CLASS::KeyBasicInformation,
    _KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation,
};

type EnumFunc<C> = unsafe extern "C" fn(HANDLE, ULONG, C, PVOID, ULONG, PULONG) -> NTSTATUS;

pub trait KeyEnumNamesInfo {
    /// Get the name from the structure describing the registry key
    fn name(&self) -> kerror::Result<NtUnicodeString>;
}

impl KeyEnumNamesInfo for KEY_BASIC_INFORMATION {
    /// Get the registry key name.
    ///
    /// Returns an `Err(Error(STATUS_INSUFFICIENT_RESOURCES))` if [`NtUnicodeString`]
    /// allocation fails.
    fn name(&self) -> kerror::Result<NtUnicodeString> {
        // SAFETY: Raw data used to create a NtUnicodeStr from KEY_BASIC_INFORMATION.
        // The caller ensures that the `Name` and `NameLength` fields of this structure are
        // valid and represent a real UNICODE_STRING
        let name = unsafe {
            #[allow(clippy::cast_possible_truncation)]
            NtUnicodeStr::from_raw_parts(
                self.Name.as_ptr(),
                self.NameLength as u16,
                self.NameLength as u16,
            )
        };

        Ok(NtUnicodeString::try_from(&name)?)
    }
}

impl KeyEnumNamesInfo for KEY_VALUE_BASIC_INFORMATION {
    /// Get the registry value name.
    ///
    /// Returns an `Err(Error(STATUS_INSUFFICIENT_RESOURCES))` if [`NtUnicodeString`]
    /// allocation fails.
    fn name(&self) -> kerror::Result<NtUnicodeString> {
        // SAFETY: Raw data used to create a NtUnicodeStr from KEY_VALUE_BASIC_INFORMATION.
        // The caller ensures that the `Name` and `NameLength` fields of this structure are
        // valid and represent a real UNICODE_STRING
        let name = unsafe {
            #[allow(clippy::cast_possible_truncation)]
            NtUnicodeStr::from_raw_parts(
                self.Name.as_ptr(),
                self.NameLength as u16,
                self.NameLength as u16,
            )
        };

        Ok(NtUnicodeString::try_from(&name)?)
    }
}

/// The structure describes the registry key to be used.
///
/// It contains information about access rights to the key, object attributes
/// and the handle of the registry key
pub struct RegKey {
    attributes: ObjectAttributes,
    key_handle: Handle,
    desired_access: u32,
}

impl RegKey {
    /// Create a [`RegKey`] structure with `OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE` object
    /// attributes and full access to the registry key.
    ///
    /// # Notes
    /// It doesn't open or create the key. It just create the structure with parameters to be
    /// used for the key opening or creation.
    pub fn new() -> Self {
        let attributes =
            ObjectAttributes::new().with_attributes(OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);

        Self {
            attributes,
            key_handle: Handle::new(),
            desired_access: KEY_ALL_ACCESS,
        }
    }

    /// Consume the registry key and set the object name
    pub fn with_path(mut self, full_path: &NtUnicodeStr) -> Self {
        self.attributes.set_object_name(full_path.as_ptr().cast());
        self
    }

    /// Consume the registry key and set the root object
    pub fn with_root(mut self, root_object: HANDLE) -> Self {
        self.attributes.set_root_directory(root_object);
        self
    }

    /// Consume the registry key and set the desired access
    pub fn with_access(mut self, desired_access: u32) -> Self {
        self.desired_access = desired_access;
        self
    }

    /// Open the registry key with predefined parameters.
    ///
    /// Opens the registry key using the [`ZwOpenKey`] call.
    /// Saves the handle on success.
    pub fn open(&mut self) -> kerror::Result<()> {
        let mut handle = null_mut();

        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that the `handle` parameter is a
        // valid mutable pointer which can receive a value from the system, that the `attributes`
        // parameter is a valid pointer to the `OBJECT_ATTRIBUTES` structure.
        unsafe {
            ZwOpenKey(
                &raw mut handle,
                self.desired_access,
                self.attributes.as_ptr().cast_mut(),
            )
        }
        .into_result()?;

        self.key_handle = Handle::new().with_handle(handle);

        Ok(())
    }

    /// Create the registry key with predefined parameters.
    ///
    /// Creates or opens the registry key using the [`ZwCreateKey`] call.
    /// Saves the handle on success.
    ///
    /// Returns an Ok(`REG_CREATED_NEW_KEY`) if it created a new key or
    /// Ok(`REG_OPENED_EXISTING_KEY`) if it opened an existing registry key.
    /// Or returns an Err(NTSTATUS) with appropriate error code in failure.
    pub fn create(&mut self) -> kerror::Result<u32> {
        let mut handle = null_mut();

        let mut disposition = 0;

        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that the `handle` parameter is a
        // valid mutable pointer which can receive a value from the system, that the `attributes`
        // parameter is a valid pointer to the `OBJECT_ATTRIBUTES` structure.
        unsafe {
            ZwCreateKey(
                &raw mut handle,
                self.desired_access,
                self.attributes.as_ptr().cast_mut(),
                0,
                null_mut(),
                0,
                &raw mut disposition,
            )
        }
        .into_result()?;

        self.key_handle = Handle::new().with_handle(handle);

        Ok(disposition)
    }

    /// Get a native registry key handle.
    pub fn handle(&self) -> HANDLE {
        self.key_handle.handle()
    }

    /// A generic function used to enumerate registry key information by index (like subkeys or values).
    fn enumerate_names_by_index<I, C>(
        enum_func: EnumFunc<C>,
        key_handle: HANDLE,
        index: u32,
        buffer: *mut u8,
        buffer_size: u32,
        information_class: C,
        result_length: &mut u32,
    ) -> kerror::Result<Option<NtUnicodeString>>
    where
        I: KeyEnumNamesInfo,
        C: Copy,
    {
        // SAFETY:
        // Inherently unsafe as a system call (ZwEnumerateKey, ZwEnumerateValueKey)
        // The caller ensures that `key_handle` is a valid handle to some registry key
        // and `buffer` is a valid pointer which can be used to obtain some data from the system
        let status = unsafe {
            enum_func(
                key_handle,
                index,
                information_class,
                buffer.cast(),
                buffer_size,
                result_length,
            )
        };

        if status == STATUS_NO_MORE_ENTRIES {
            return Ok(None);
        }

        status.into_result()?;

        // SAFETY:
        // The system ensures that the `buffer` isn't empty and isn't null of the status returned
        // from the `enum_func` is STATUS_SUCCESS. It's also checked to be non-null
        let name_info = unsafe {
            buffer
                .cast::<I>()
                .as_ref()
                .ok_or(STATUS_INVALID_PARAMETER.into_error())?
        };

        Ok(Some(name_info.name()?))
    }

    /// Enumerate the registry key names (subkeys or values).
    ///
    /// # Parameters
    /// - `enum_func`: - A function used to enumerate the registry key.
    /// - `info_class`: - An information class that describes what type of information to query.
    ///
    /// # Type Parameters
    /// - `I`: A structure that implements the `KeyEnumNamesInfo` trait and allows to get
    ///   the name of an object. The array of these objects is returned by the `enum_func` function.
    /// - `C`: An information class uses as a parameter for the `enum_func` function.
    fn enumerate_names_impl<I, C>(
        &self,
        enum_func: EnumFunc<C>,
        info_class: C,
    ) -> kerror::Result<Vec<NtUnicodeString>>
    where
        I: KeyEnumNamesInfo,
        C: Copy,
    {
        let mut names = Vec::new();

        let mut idx = 0;

        // `Vec::try_with_capacity` is unstable so we use `new` + `try_reserve`
        let mut buffer = Vec::new();
        buffer.try_reserve(size_of::<I>())?;

        let mut result_len = 0;

        loop {
            let res = Self::enumerate_names_by_index::<I, C>(
                enum_func,
                self.key_handle.handle(),
                idx,
                buffer.as_mut_ptr(),
                u32::try_from(buffer.capacity())?,
                info_class,
                &mut result_len,
            );

            if let Err(err) = res {
                if err.ntstatus() == STATUS_BUFFER_TOO_SMALL
                    || err.ntstatus() == STATUS_BUFFER_OVERFLOW
                {
                    buffer.try_reserve(
                        result_len.saturating_sub(u32::try_from(buffer.len())?) as usize
                    )?;

                    continue;
                }

                return Err(err);
            }

            idx += 1;

            let name = res.expect("Name information must be valid after buffer validation");

            match name {
                Some(name) => {
                    names.try_push(name)?;
                }
                None => break,
            }
        }

        Ok(names)
    }

    /// Get a `Vec` of registry key subkeys names.
    pub fn subkeys(&self) -> kerror::Result<Vec<NtUnicodeString>> {
        self.enumerate_names_impl::<KEY_BASIC_INFORMATION, _>(ZwEnumerateKey, KeyBasicInformation)
    }

    /// Get a `Vec` of registry key values names.
    pub fn value_names(&self) -> kerror::Result<Vec<NtUnicodeString>> {
        self.enumerate_names_impl::<KEY_VALUE_BASIC_INFORMATION, _>(
            ZwEnumerateValueKey,
            KeyValueBasicInformation,
        )
    }
}

/// Get a full registry key path.
///
/// Get a key path from the key `object` obtained from the registry callback
/// registered with a `CmRegisterCallbackEx` call.
///
/// # Parameters
/// - `cookie`: A cookie value obtained when registering a registry callback.
/// - `object`: An object obtained in the registry callback from the `argument2`
///   pointer to the corresponding structure.
pub fn full_key_path<'a>(
    mut cookie: LARGE_INTEGER,
    object: PVOID,
) -> kerror::Result<CmKeyObjectPath<'a>> {
    let mut object_name: PUNICODE_STRING = null_mut();

    // SAFETY:
    // Inherently unsafe as a system call. The caller ensures that the `cookie` value is valid
    // (obtain from the CmRegisterCallbackEx function) and object_name is a valid pointer to UNICODE_STRING
    unsafe {
        CmCallbackGetKeyObjectIDEx(
            &raw mut cookie,
            object,
            null_mut(),
            (&raw mut object_name).cast(),
            0,
        )
    }
    .into_result()?;

    Ok(CmKeyObjectPath::from(object_name.cast_const()))
}
