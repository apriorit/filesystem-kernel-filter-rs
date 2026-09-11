use alloc::boxed::Box;
use kernel_allocator::kernel_allocator::NonPagedAlloc;
use ntresult::IntoResult;
use wdk_sys::{
    minifilter::{FltAcquireResourceExclusive, FltAcquireResourceShared, FltReleaseResource},
    ntddk::{ExDeleteResourceLite, ExInitializeResourceLite},
    ERESOURCE, PERESOURCE,
};

/// Wrapper for the [`ERESOURCE`] structure used for synchronization. Allows two types of resource usage:
/// `exclusive` and `shared` (see the doc <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinitializeresourcelite>).
///
/// This structure allocates the [`ERESOURCE`] structure on heap from nonpaged pool.
///
/// It owns the [`ERESOURCE`] and deletes it in the destructor using [`ExDeleteResourceLite`] call.
///
/// # Examples
/// ```rust,no_run
/// let mut resource = FltResource::new()?;
/// {
///     let _shared_lock = resource.acquire_shared();
///     // read shared data
/// }
/// {
///     let _exclusive_lock = resource.acquire_exclusive();
///     // write shared data
/// }
/// ```
pub struct FltResource {
    resource: Box<ERESOURCE, NonPagedAlloc>,
}

impl Drop for FltResource {
    /// Delete the [`ERESOURCE`] pointer with [`ExDeleteResourceLite`] call
    fn drop(&mut self) {
        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that
        // the `resource` parameter is a valid pointer to ERESOURCE structure
        let _ = unsafe { ExDeleteResourceLite(&raw mut *self.resource) };
    }
}

impl FltResource {
    /// Try to create a new [`FltResource`] structure.
    ///
    /// Allocates the [`ERESOURCE_SIZE_X64`] bytes on heap from nonpaged pool
    /// and initializes the [`ERESOURCE`] structure using [`ExInitializeResourceLite`] call.
    pub fn new() -> ntresult::Result<Self> {
        // SAFETY:
        // Zero-initialize the ERESOURCE structure before using it.
        // The `EResourceAlias` is an alias type with correct size for the kernel type.
        // The caller ensures that the EResourceAlias size is equal to the correct size of the ERESOURCE structure.
        let mut resource: Box<ERESOURCE, _> =
            unsafe { Box::try_new_zeroed_in(NonPagedAlloc {})?.assume_init() };

        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that
        // the `resource` parameter is a valid pointer to ERESOURCE structure
        unsafe { ExInitializeResourceLite(&raw mut *resource) }.into_result()?;

        Ok(Self { resource })
    }

    /// Acquire exclusive lock for the [`FltResource`] with [`FltAcquireResourceExclusive`] call.
    ///
    /// # Returns
    ///
    /// - `FltResourceExclusiveLock` - Structure that holds the lock and releases it in the destructor.
    pub fn acquire_exclusive(&mut self) -> FltResourceExclusiveLock {
        let eresource_ptr = &raw mut *self.resource;

        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that
        // the `resource` parameter is a valid pointer to ERESOURCE structure
        unsafe { FltAcquireResourceExclusive(eresource_ptr.cast()) };
        FltResourceExclusiveLock::new(eresource_ptr)
    }

    /// Acquire shared lock for the [`FltResource`] with [`FltAcquireResourceShared`] call.
    ///
    /// # Returns
    ///
    /// - `FltResourceSharedLock` - Structure that holds the lock and releases it in the destructor.
    pub fn acquire_shared(&mut self) -> FltResourceSharedLock {
        let eresource_ptr = &raw mut *self.resource;

        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that
        // the `resource` parameter is a valid pointer to ERESOURCE structure
        unsafe { FltAcquireResourceShared(eresource_ptr.cast()) };
        FltResourceSharedLock::new(eresource_ptr)
    }
}

/// The [`FltResource`] exclusive lock that holds the pointer to the [`ERESOURCE`]
/// structure and releases the lock in the destructor.
pub struct FltResourceExclusiveLock {
    resource: PERESOURCE,
}

impl Drop for FltResourceExclusiveLock {
    /// Release the exclusive lock with [`FltReleaseResource`] call.
    fn drop(&mut self) {
        if !self.resource.is_null() {
            // SAFETY:
            // Inherently unsafe as a system call. The caller ensures that
            // the `resource` parameter is a valid pointer to ERESOURCE structure
            unsafe { FltReleaseResource(self.resource.cast()) };
        }
    }
}

impl FltResourceExclusiveLock {
    /// Create an object of [`FltResourceExclusiveLock`] that saves the `resource`
    /// parameter and releases it in the destructor.
    pub fn new(resource: PERESOURCE) -> Self {
        Self { resource }
    }
}

/// The [`FltResource`] shared lock that holds the pointer to the [`ERESOURCE`]
/// structure and releases the lock in the destructor.
pub struct FltResourceSharedLock {
    resource: PERESOURCE,
}

impl Drop for FltResourceSharedLock {
    /// Release the shared lock with [`FltReleaseResource`] call.
    fn drop(&mut self) {
        if !self.resource.is_null() {
            // SAFETY:
            // Inherently unsafe as a system call. The caller ensures that
            // the `resource` parameter is a valid to ERESOURCE structure
            unsafe { FltReleaseResource(self.resource.cast()) };
        }
    }
}

impl FltResourceSharedLock {
    /// Create an object of [`FltResourceSharedLock`] that saves the `resource`
    /// parameter and releases it in the destructor.
    pub fn new(resource: PERESOURCE) -> Self {
        Self { resource }
    }
}
