use core::ptr::null_mut;
use wdk_sys::{
    HANDLE, OBJECT_ATTRIBUTES, PCOBJECT_ATTRIBUTES, PCUNICODE_STRING, POBJECT_ATTRIBUTES,
};

/// Wrapper for the [`OBJECT_ATTRIBUTES`] structure
pub struct ObjectAttributes {
    inner: OBJECT_ATTRIBUTES,
}

impl Default for ObjectAttributes {
    /// Zero all the structure fields and set `Length` to `size_of::<OBJECT_ATTRIBUTES>()`.
    fn default() -> Self {
        Self {
            inner: OBJECT_ATTRIBUTES {
                #[allow(clippy::cast_possible_truncation)]
                Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: null_mut(),
                ObjectName: null_mut(),
                Attributes: 0,
                SecurityDescriptor: null_mut(),
                SecurityQualityOfService: null_mut(),
            },
        }
    }
}

#[allow(dead_code)]
impl ObjectAttributes {
    /// Create an empty [`ObjectAttributes`] with zeroed fields and `Length` containing the size of
    /// the [`OBJECT_ATTRIBUTES`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume the object and set `RootDirectory` to `root`.
    pub fn with_root_directory(mut self, root: HANDLE) -> Self {
        self.inner.RootDirectory = root;
        self
    }

    ///  Set `RootDirectory` to `root`.
    pub fn set_root_directory(&mut self, root: HANDLE) {
        self.inner.RootDirectory = root;
    }

    /// Consume the object and set `ObjectName` to `object_name`.
    pub fn with_object_name(mut self, object_name: PCUNICODE_STRING) -> Self {
        self.inner.ObjectName = object_name.cast_mut();
        self
    }

    ///  Set `ObjectName` to `object_name`.
    pub fn set_object_name(&mut self, object_name: PCUNICODE_STRING) {
        self.inner.ObjectName = object_name.cast_mut();
    }

    /// Consume the object and set `Attributes` to `attributes`.
    pub fn with_attributes(mut self, attributes: u32) -> Self {
        self.inner.Attributes = attributes;
        self
    }

    ///  Set `Attributes` to `attributes`.
    pub fn set_attributes(&mut self, attributes: u32) {
        self.inner.Attributes = attributes;
    }

    /// Get a raw const pointer to the [`OBJECT_ATTRIBUTES`] structure.
    pub fn as_ptr(&self) -> PCOBJECT_ATTRIBUTES {
        &raw const self.inner
    }

    /// Get a raw mutable pointer to the [`OBJECT_ATTRIBUTES`] structure.
    pub fn as_mut_ptr(&mut self) -> POBJECT_ATTRIBUTES {
        &raw mut self.inner
    }
}
