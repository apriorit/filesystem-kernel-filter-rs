use crate::{
    kernel_objects::cm_key_object_path::CmKeyObjectPath, registry::full_key_path,
    rules_manager::RulesManager, string_utils::NtStrExt,
};
use core::{ffi::c_void, ptr::null_mut};
use kerror::IntoResult;
use nt_string::unicode_string::NtUnicodeStr;
use wdk_sys::{
    ntddk::{CmRegisterCallbackEx, CmUnRegisterCallback},
    LARGE_INTEGER, NTSTATUS, PDRIVER_OBJECT, PVOID, REG_DELETE_VALUE_KEY_INFORMATION,
    REG_NOTIFY_CLASS, REG_POST_OPERATION_INFORMATION, REG_RENAME_KEY_INFORMATION,
    REG_SET_VALUE_KEY_INFORMATION, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, UNICODE_STRING,
    _REG_NOTIFY_CLASS::{
        RegNtPostDeleteKey, RegNtPostDeleteValueKey, RegNtPostRenameKey, RegNtPostSetValueKey,
        RegNtPreRenameKey,
    },
};

/// A registry manager that manages all the registry operations on the system.
/// It notifies the [`RulesManager`] of changes to the protection rules key root.
///
/// Contains a cookie value obtained when registering a registry callback.
#[derive(Default)]
pub struct RegistryManager {
    pub cookie: LARGE_INTEGER,
}

impl Drop for RegistryManager {
    /// Unregister the registry callback function.
    fn drop(&mut self) {
        // SAFETY:
        // Inherently unsafe as a system call, `CmUnRegisterCallback` unregisters the
        // `registry_callback` function. The caller ensures that the `self.cookie`
        // value is valid.
        let _ = unsafe { CmUnRegisterCallback(self.cookie) }
            .into_result()
            .inspect_err(|err| log::error!("Failed to unregister registry callback: {err}"));
    }
}

impl RegistryManager {
    /// Create an empty [`RegistryManager`] with `cookie` set to zero.
    ///
    /// # Notes
    /// It doesn't register a registry callback function. It simply creates an instance of the structure.
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize the registry manager.
    ///
    /// Sets the registry callback function that will monitor registry operations.
    pub fn init(&mut self, driver: PDRIVER_OBJECT, altitude: &NtUnicodeStr) -> kerror::Result<()> {
        self.set_callback(driver, altitude)
            .inspect_err(|err| log::error!("Failed to set registry callback: {err}"))
    }

    /// Register the [`RegistryManager::registry_callback`] function using
    /// the [`CmRegisterCallbackEx`] call.
    ///
    /// It saves the returned `cookie` value.
    fn set_callback(
        &mut self,
        driver: PDRIVER_OBJECT,
        altitude: &NtUnicodeStr,
    ) -> kerror::Result<()> {
        // SAFETY:
        // Inherently unsafe as a system call, `CmRegisterCallbackEx` registers the
        // `registry_callback` function in system. The caller ensures that the `altitude`
        // is a valid UNICODE_STRING that equals the altitude specified in the
        // `.inx` file. The caller also ensures that the `driver` is a valid
        // pointer to the current driver object, and cookie as a valid object
        unsafe {
            CmRegisterCallbackEx(
                Some(Self::registry_callback),
                altitude.as_ptr().cast(),
                driver.cast(),
                core::ptr::from_mut(self).cast(),
                &raw mut self.cookie,
                null_mut(),
            )
        }
        .into_result()
    }

    /// Post delete key operation handler.
    ///
    /// It gets a full path to the registry key using the `cookie` and registry key object,
    /// using the [`full_key_path`] call and checks if it's a protection key using
    /// [`RulesManager::is_protection_key`]. It does nothing if it isn't a protection key.
    /// Then notifies the rules manager using the [`RulesManager::delete_key_rules`] call.
    fn post_delete_key(
        cookie: LARGE_INTEGER,
        post_op_info: &REG_POST_OPERATION_INFORMATION,
    ) -> kerror::Result<()> {
        if post_op_info.Status != STATUS_SUCCESS {
            return Ok(());
        }

        let cm_key_object_path = full_key_path(cookie, post_op_info.Object)?;
        let key_path = cm_key_object_path.path()?;

        if !RulesManager::is_protection_key(&key_path) {
            return Ok(());
        }

        RulesManager::delete_key_rules(&key_path)
    }

    /// Pre delete key operation handler.
    ///
    /// It gets a full path to the registry key and saves it in the [`REG_RENAME_KEY_INFORMATION::CallContext`]
    /// field to pass in to post operation handler. Post operation handler cant get an old registry key name
    /// because executes when the key already has a new name.
    ///
    /// A post operation handler is responsible for releasing the [`CmKeyObjectPath`] object leaked in this
    /// handler.
    fn pre_rename_key(
        cookie: LARGE_INTEGER,
        rename_info: &mut REG_RENAME_KEY_INFORMATION,
    ) -> kerror::Result<()> {
        let cm_key_object_old_path = full_key_path(cookie, rename_info.Object)?;

        rename_info.CallContext = cm_key_object_old_path.leak().cast::<c_void>().cast_mut();

        Ok(())
    }

    /// Post rename key operation handler.
    ///
    /// It gets a full path to the registry key from the [`REG_POST_OPERATION_INFORMATION::CallContext`]
    /// field previously filled in the [`RegistryManager::pre_rename_key`] handler. It casts it to the [`CmKeyObjectPath`]
    /// which will release the object path in it's destructor. Then checks if it's a protection key using the
    /// [`RulesManager::is_protection_key`] It does nothing if it isn't a protection key.
    /// Then it gets a new key name from the [`REG_RENAME_KEY_INFORMATION::NewName`]
    /// field and notifies the rules manager using the [`RulesManager::rename_key_rules`] call.
    fn post_rename_key(post_op_info: &REG_POST_OPERATION_INFORMATION) -> kerror::Result<()> {
        let cm_key_object_old_path = CmKeyObjectPath::from(
            post_op_info
                .CallContext
                .cast::<UNICODE_STRING>()
                .cast_const(),
        );

        if post_op_info.Status != STATUS_SUCCESS {
            return Ok(());
        }

        let old_key_path = cm_key_object_old_path.path()?;

        if !RulesManager::is_protection_key(&old_key_path) {
            return Ok(());
        }

        let new_key_name = NtUnicodeStr::from_native_str(
            // SAFETY:
            // The system ensures that the `REG_POST_OPERATION_INFORMATION::PreInformation`
            // is a valid pointer to the `REG_RENAME_KEY_INFORMATION` structure in case
            // of `RegNtPostRenameKey` notification. It's also checked to be non-null
            unsafe {
                post_op_info
                    .PreInformation
                    .cast::<REG_RENAME_KEY_INFORMATION>()
                    .as_ref()
                    .ok_or(STATUS_INVALID_PARAMETER.into_error())?
            }
            .NewName
            .cast_const(),
        )?;

        RulesManager::rename_key_rules(&old_key_path, &new_key_name)
    }

    /// Post delete value operation handler.
    ///
    /// It gets a full path to the registry key using the `cookie` and registry key object,
    /// using the [`full_key_path`] call and checks if it's a protection key using
    /// [`RulesManager::is_protection_key`]. It does nothing if it isn't a protection key.
    /// Then it gets a `value name` from the [`REG_DELETE_VALUE_KEY_INFORMATION::ValueName`]
    /// field and notifies the rules manager using the [`RulesManager::delete_key_value_rule`] call.
    fn post_delete_value(
        cookie: LARGE_INTEGER,
        post_op_info: &REG_POST_OPERATION_INFORMATION,
    ) -> kerror::Result<()> {
        if post_op_info.Status != STATUS_SUCCESS {
            return Ok(());
        }

        let cm_key_object_path = full_key_path(cookie, post_op_info.Object)?;
        let key_path = cm_key_object_path.path()?;

        if !RulesManager::is_protection_key(&key_path) {
            return Ok(());
        }

        let value_name = NtUnicodeStr::from_native_str(
            // SAFETY:
            // The system ensures that the `REG_POST_OPERATION_INFORMATION::PreInformation`
            // is a valid pointer to the `REG_DELETE_VALUE_KEY_INFORMATION` structure in case
            // of `RegNtPostDeleteValueKey` notification. It's also checked to be non-null
            unsafe {
                post_op_info
                    .PreInformation
                    .cast::<REG_DELETE_VALUE_KEY_INFORMATION>()
                    .as_ref()
                    .ok_or(STATUS_INVALID_PARAMETER.into_error())?
            }
            .ValueName,
        )?;

        RulesManager::delete_key_value_rule(&key_path, &value_name)
    }

    /// Post set value operation handler.
    ///
    /// It gets a full path to the registry key using the `cookie` and registry key object,
    /// using the [`full_key_path`] call and checks if it's a protection key using
    /// [`RulesManager::is_protection_key`]. It does nothing if it isn't a protection key.
    /// Then it gets a `value name` from the [`REG_SET_VALUE_KEY_INFORMATION::ValueName`]
    /// field and notifies the rules manager using the [`RulesManager::set_key_value_rule`] call.
    fn post_set_value(
        cookie: LARGE_INTEGER,
        post_op_info: &REG_POST_OPERATION_INFORMATION,
    ) -> kerror::Result<()> {
        if post_op_info.Status != STATUS_SUCCESS {
            return Ok(());
        }

        let cm_key_object_path = full_key_path(cookie, post_op_info.Object)?;
        let key_path = cm_key_object_path.path()?;

        if !RulesManager::is_protection_key(&key_path) {
            return Ok(());
        }

        let value_name = NtUnicodeStr::from_native_str(
            // SAFETY:
            // The system ensures that the `REG_POST_OPERATION_INFORMATION::PreInformation`
            // is a valid pointer to the `REG_SET_VALUE_KEY_INFORMATION` structure in case
            // of `RegNtPostSetValueKey` notification. It's also checked to be non-null
            unsafe {
                post_op_info
                    .PreInformation
                    .cast::<REG_SET_VALUE_KEY_INFORMATION>()
                    .as_ref()
                    .ok_or(STATUS_INVALID_PARAMETER.into_error())?
            }
            .ValueName,
        )?;

        RulesManager::set_key_value_rule(&key_path, &value_name)
    }

    /// Registry callback implementation. This routine is triggered every type
    /// some process tries to modify the registry.
    ///
    /// It monitors the following operation types:
    /// - `RegNtPreRenameKey` - called before rename key operation.
    /// - `RegNtPostRenameKey` - called after rename key operation.
    /// - `RegNtPostDeleteKey` - called after delete key operation.
    /// - `RegNtPostDeleteValueKey` - called after delete value operation.
    /// - `RegNtPostSetValueKey` - called after set value operation.
    ///
    /// # Parameters
    /// - `callback_context`: The callback context specified when registering the callback function.
    ///   It points to the [`RegistryManager`] global instance.
    /// - `argument1`: A [`REG_NOTIFY_CLASS`] value that indicates which operation type was triggered.
    /// - `argument2`: A pointer to operation-associated structure which contains all the information about
    ///   the operation being performed.
    ///
    /// # Notes
    /// There is no way to rename a key value. We only monitor delete and set value operations
    /// because it's the only way to change the value name.
    fn registry_callback_impl(
        callback_context: PVOID,
        argument1: PVOID,
        argument2: PVOID,
    ) -> kerror::Result<()> {
        let operation_type = argument1 as REG_NOTIFY_CLASS;

        // SAFETY:
        // The caller must ensure that a pointer to the RegistryManager instance was passed
        // to the `CmRegisterCallbackEx` function as a `Context` parameter. System passes
        // this pointer to the `callback_context` parameter of the `registry_callback` function
        let registry_manager = unsafe {
            callback_context
                .cast::<RegistryManager>()
                .as_ref()
                .ok_or(STATUS_INVALID_PARAMETER.into_error())?
        };

        #[allow(non_upper_case_globals)]
        match operation_type {
            // SAFETY:
            // The system ensures that the `argument2` is a valid pointer to the `REG_RENAME_KEY_INFORMATION`
            // structure in case of `RegNtPreRenameKey` notification. It's also checked to be non-null
            RegNtPreRenameKey => Self::pre_rename_key(registry_manager.cookie, unsafe {
                argument2
                    .cast::<REG_RENAME_KEY_INFORMATION>()
                    .as_mut()
                    .ok_or(STATUS_INVALID_PARAMETER.into_error())
                    .inspect_err(|err| log::warn!("pre_rename_key failed: {err}"))?
            }),
            // SAFETY:
            // The system ensures that the `argument2` is a valid pointer to the `REG_POST_OPERATION_INFORMATION`
            // structure in case of `RegNtPostRenameKey` notification. It's also checked to be non-null
            RegNtPostRenameKey => Self::post_rename_key(unsafe {
                argument2
                    .cast::<REG_POST_OPERATION_INFORMATION>()
                    .as_ref()
                    .ok_or(STATUS_INVALID_PARAMETER.into_error())
                    .inspect_err(|err| log::warn!("post_rename_key failed: {err}"))?
            }),
            // SAFETY:
            // The system ensures that the `argument2` is a valid pointer to the `REG_POST_OPERATION_INFORMATION`
            // structure in case of `RegNtPostDeleteKey` notification. It's also checked to be non-null
            RegNtPostDeleteKey => Self::post_delete_key(registry_manager.cookie, unsafe {
                argument2
                    .cast::<REG_POST_OPERATION_INFORMATION>()
                    .as_ref()
                    .ok_or(STATUS_INVALID_PARAMETER.into_error())
                    .inspect_err(|err| log::warn!("post_delete_key failed: {err}"))?
            }),
            // SAFETY:
            // The system ensures that the argument2 is a valid pointer to the `REG_POST_OPERATION_INFORMATION`
            // structure in case of `RegNtPostDeleteValueKey` notification. It's also checked to be non-null
            RegNtPostDeleteValueKey => Self::post_delete_value(registry_manager.cookie, unsafe {
                argument2
                    .cast::<REG_POST_OPERATION_INFORMATION>()
                    .as_ref()
                    .ok_or(STATUS_INVALID_PARAMETER.into_error())
                    .inspect_err(|err| log::warn!("post_delete_value failed: {err}"))?
            }),
            // SAFETY:
            // The system ensures that the `argument2` is a valid pointer to the `REG_POST_OPERATION_INFORMATION`
            // structure in case of `RegNtPostSetValueKey` notification. It's also checked to be non-null
            RegNtPostSetValueKey => Self::post_set_value(registry_manager.cookie, unsafe {
                argument2
                    .cast::<REG_POST_OPERATION_INFORMATION>()
                    .as_ref()
                    .ok_or(STATUS_INVALID_PARAMETER.into_error())
                    .inspect_err(|err| log::warn!("post_set_value failed: {err}"))?
            }),
            _ => STATUS_SUCCESS.into_result(),
        }
    }

    /// A callback function triggered by the system when registry operation happens.
    /// This function is registered by the [`CmRegisterCallbackEx`] call at
    /// [`RegistryManager`] initialization stage and unregistered in it's destructor with
    /// [`CmUnRegisterCallback`].
    ///
    /// # Safety
    /// This function is inherently unsafe because it's a registry callback called by the configuration manager.
    /// Parameters are provided by the operating system when some process tries to perform a registry operation and it
    /// ensures that they are valid.
    unsafe extern "C" fn registry_callback(
        callback_context: PVOID,
        argument1: PVOID,
        argument2: PVOID,
    ) -> NTSTATUS {
        if let Err(err) = Self::registry_callback_impl(callback_context, argument1, argument2) {
            err.ntstatus()
        } else {
            STATUS_SUCCESS
        }
    }
}
