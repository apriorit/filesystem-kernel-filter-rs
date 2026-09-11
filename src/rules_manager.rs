use crate::{
    constants::{
        DENY_RULES_REGISTRY_KEY_NAME, DENY_RULES_REGISTRY_KEY_PATH, FILTER_REGISTRY_KEY_PATH,
        FOLDER_RULE_POSTFIX, READ_ONLY_RULES_REGISTRY_KEY_NAME, READ_ONLY_RULES_REGISTRY_KEY_PATH,
        RULES_REGISTRY_KEY_PATH,
    },
    driver::Driver,
    err_map::IntoNtResult,
    kernel_objects::flt_resource::FltResource,
    path_utils::dos_path_to_nt,
    registry::RegKey,
    string_utils::{NtStrExt, NtStringConvert},
    utils::TryPush,
};
use alloc::vec::Vec;
use nt_string::{
    nt_unicode_str,
    unicode_string::{NtUnicodeStr, NtUnicodeString},
};
use ntresult::Error;
use wdk_sys::{
    KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND,
};

/// Action performed on a file operation
#[derive(Debug, Copy, Clone)]
pub enum FileSystemRuleAction {
    /// Bypass operation and do nothing
    Bypass,
    /// Block file operation
    Deny,
    /// Block a file operation if it can modify the file, bypass if not
    ReadOnly,
}

/// A file access entry, representing a combination of the process name
/// and file paths to which the rules should be applied
pub struct FileAccessEntry {
    process_name: NtUnicodeString,
    file_paths: Vec<NtUnicodeString>,
}

/// Filter registry key rule that consists of [`FileSystemRuleAction`]
/// and process name
#[derive(Default)]
struct RuleKeyPath<'a> {
    rule_type: Option<FileSystemRuleAction>,
    process_name: Option<NtUnicodeStr<'a>>,
}

impl TryFrom<&NtUnicodeStr<'_>> for FileSystemRuleAction {
    type Error = Error;

    /// Try to convert a registry key name to the [`FileSystemRuleAction`].
    ///
    /// Ignores string case.
    ///
    /// Returns [`STATUS_INVALID_PARAMETER`] error if `str` parameter is an unknown
    /// rule type string.
    fn try_from(str: &NtUnicodeStr) -> ntresult::Result<Self> {
        if str.equals_no_case(&DENY_RULES_REGISTRY_KEY_NAME) {
            Ok(Self::Deny)
        } else if str.equals_no_case(&READ_ONLY_RULES_REGISTRY_KEY_NAME) {
            Ok(Self::ReadOnly)
        } else {
            Err(Error::from_ntstatus(STATUS_INVALID_PARAMETER))
        }
    }
}

impl TryFrom<FileSystemRuleAction> for NtUnicodeStr<'_> {
    type Error = Error;

    /// Try to convert a [`FileSystemRuleAction`] to registry key name.
    ///
    /// Returns [`STATUS_INVALID_PARAMETER`] error if `action` parameter is not a supported rule type
    fn try_from(action: FileSystemRuleAction) -> ntresult::Result<NtUnicodeStr<'static>> {
        match action {
            FileSystemRuleAction::Deny => Ok(DENY_RULES_REGISTRY_KEY_NAME),
            FileSystemRuleAction::ReadOnly => Ok(READ_ONLY_RULES_REGISTRY_KEY_NAME),
            FileSystemRuleAction::Bypass => Err(Error::from_ntstatus(STATUS_INVALID_PARAMETER)),
        }
    }
}

/// Check if `path` string is starts with specified disk name in dos format.
///
/// # Examples
/// ```rust,no_run
/// assert!(is_disk_specified(&nt_unicode_str!("C:\\Users\\user\\*")));
/// assert!(!is_disk_specified(&nt_unicode_str!("*user\\*")));
/// ```
fn is_disk_specified(path: &NtUnicodeStr) -> bool {
    path.mathes(&nt_unicode_str!("?:*"))
}

/// Prepare the `path` parameter for further filtering process.
///
/// If disk is specified it converts the `path` to nt format using
/// [`dos_path_to_nt`]. Then if the `path` ends with `\` which indicates that it's
/// path to the folder, it adds the `*` symbol to it.
///
/// And converts the `path` to upper case in the end.
fn prepare_rule_file_path(path: &mut NtUnicodeString) -> ntresult::Result<()> {
    if is_disk_specified(path) {
        *path = dos_path_to_nt(path.as_unicode_str())
            .inspect_err(|err| log::error!("Failed to convert dos path\"{path}\" to nt: {err}"))?;
    }

    if path.ends_with(&nt_unicode_str!("\\")) {
        path.try_push('*').into_nt_result()?;
    }

    path.convert_to_upper()
}

fn prepare_registry_keys() -> ntresult::Result<()> {
    RegKey::new()
        .with_path(&FILTER_REGISTRY_KEY_PATH)
        .create()?;

    RegKey::new().with_path(&RULES_REGISTRY_KEY_PATH).create()?;

    RegKey::new()
        .with_path(&DENY_RULES_REGISTRY_KEY_PATH)
        .create()?;
    RegKey::new()
        .with_path(&READ_ONLY_RULES_REGISTRY_KEY_PATH)
        .create()?;

    Ok(())
}

/// The rules manager which contains all the protection rules
/// and [`FltResource`] for each of them.
pub struct RulesManager {
    deny_rules: Vec<FileAccessEntry>,
    deny_rules_lock: FltResource,
    readonly_rules: Vec<FileAccessEntry>,
    readonly_rules_lock: FltResource,
}

impl RulesManager {
    /// Create a [`RulesManager`] with empty rules and initialized
    /// locks for each rule type.
    pub fn new() -> ntresult::Result<Self> {
        Ok(Self {
            deny_rules: Vec::default(),
            deny_rules_lock: FltResource::new()?,
            readonly_rules: Vec::default(),
            readonly_rules_lock: FltResource::new()?,
        })
    }

    /// Initialize the [`RulesManager`].
    ///
    /// Initializes protection rules. If the [`RULES_REGISTRY_PATH`] doesn't exist
    /// it handles the error and returns Ok(()) anyway because it isn't a critical
    /// error and rules can be added later.
    pub fn init(&mut self) -> ntresult::Result<()> {
        if let Err(err) = self.init_rules() {
            if err.ntstatus() == STATUS_OBJECT_NAME_NOT_FOUND {
                log::info!("Rules manager failed to read rules from the registry, the rules registry key is absent");
                Ok(())
            } else {
                log::warn!("Rules manager isn't initialized: {err}");
                Err(err)
            }
        } else {
            Ok(())
        }
    }

    /// Read protection rules from the [`RULES_REGISTRY_PATH`] registry key.
    ///
    /// Tries to do the following:
    /// 1) Open the key, get it's subkeys (rule types);
    /// 2) Open each rule type key, get it's subkeys (process names);
    /// 3) Open each process name key, get it's values (file paths);
    /// 4) Add obtained rules to the [`RulesManager`].
    fn init_rules(&mut self) -> ntresult::Result<()> {
        let mut root_rules_key = RegKey::new()
            .with_path(&RULES_REGISTRY_KEY_PATH)
            .with_access(KEY_ENUMERATE_SUB_KEYS);

        prepare_registry_keys()?;

        root_rules_key
            .open()
            .inspect_err(|err| log::warn!("Failed to open the rules registry key: {err}"))?;

        let rule_types = root_rules_key
            .subkeys()
            .inspect_err(|err| log::error!("Failed to get subkeys of the root rules key: {err}"))?;

        for rule_type in rule_types {
            let mut rule_type_key = RegKey::new()
                .with_root(root_rules_key.handle())
                .with_path(&rule_type)
                .with_access(KEY_ENUMERATE_SUB_KEYS);

            rule_type_key
                .open()
                .inspect_err(|err| log::error!("Failed to open {rule_type} rules subkey: {err}"))?;

            let mut processes = rule_type_key.subkeys()?;
            processes
                .iter_mut()
                .try_for_each(NtStringConvert::convert_to_upper)?;

            let action = FileSystemRuleAction::try_from(rule_type.as_unicode_str())?;

            let mut rules = Vec::new();
            rules.try_reserve(processes.len())?;

            for process_name in processes {
                let mut process_rules = RegKey::new()
                    .with_root(rule_type_key.handle())
                    .with_path(&process_name)
                    .with_access(KEY_QUERY_VALUE);

                process_rules.open().inspect_err(|err| {
                    log::error!("Failed to open {process_name} process rules subkey: {err}");
                })?;

                let mut file_paths = process_rules.value_names()?;
                file_paths.iter_mut().try_for_each(prepare_rule_file_path)?;

                let access_entry = FileAccessEntry {
                    process_name,
                    file_paths,
                };

                rules.try_push(access_entry)?;
            }

            match action {
                FileSystemRuleAction::Deny => self.deny_rules = rules,
                FileSystemRuleAction::ReadOnly => self.readonly_rules = rules,
                FileSystemRuleAction::Bypass => (),
            }
        }

        Ok(())
    }

    /// Check if protection rule for `process_name` and `file_path` exists in the `rules`
    /// array. Acquires shared lock before performing a search.
    fn search_rule_impl(
        rules: &[FileAccessEntry],
        rules_lock: &mut FltResource,
        process_name: &NtUnicodeStr,
        file_path: &NtUnicodeStr,
    ) -> bool {
        let _lock = rules_lock.acquire_shared();

        rules
            .iter()
            .find(|access_entry| process_name.mathes_no_case(&access_entry.process_name))
            .is_some_and(|access_entry| {
                access_entry.file_paths.iter().any(|rule_file_path| {
                    if file_path.mathes_no_case(rule_file_path) {
                        return true;
                    } else if rule_file_path.ends_with(&FOLDER_RULE_POSTFIX) {
                        #[allow(clippy::cast_possible_truncation)]
                        let folder_path = rule_file_path.split_at(
                            (rule_file_path
                                .len_in_elements()
                                .saturating_sub(FOLDER_RULE_POSTFIX.len_in_elements()))
                                as u16,
                        );
                        if let Ok(folder_path) = folder_path {
                            return file_path.mathes_no_case(&folder_path.0);
                        }
                    }
                    false
                })
            })
    }

    /// Search for [`FileSystemRuleAction`] for the specified
    /// `process_name` and `file_path` arguments.
    pub fn search_rule_action(
        process_name: &NtUnicodeStr,
        file_path: &NtUnicodeStr,
    ) -> FileSystemRuleAction {
        let rules_manager = Self::instance_mut();

        if Self::search_rule_impl(
            &rules_manager.deny_rules,
            &mut rules_manager.deny_rules_lock,
            process_name,
            file_path,
        ) {
            FileSystemRuleAction::Deny
        } else if Self::search_rule_impl(
            &rules_manager.readonly_rules,
            &mut rules_manager.readonly_rules_lock,
            process_name,
            file_path,
        ) {
            FileSystemRuleAction::ReadOnly
        } else {
            FileSystemRuleAction::Bypass
        }
    }

    /// Check if the specified `key_path` starts with [`RULES_REGISTRY_PATH`]
    /// key path. Ignores key path case.
    #[inline]
    pub fn is_protection_key(key_path: &NtUnicodeStr) -> bool {
        key_path.starts_with_no_case(&RULES_REGISTRY_KEY_PATH)
    }

    /// Parse the `key_path` and convert it to the [`RuleKeyPath`] structure.
    ///
    /// The [`RuleKeyPath`] can either contain:
    /// 1) Both rule type and process name;
    /// 2) Only rule type;
    /// 3) None.
    fn parse_protection_rule_key<'a>(
        key_path: &'a NtUnicodeStr,
    ) -> ntresult::Result<RuleKeyPath<'a>> {
        let rules_type_key_path =
            key_path.substr(RULES_REGISTRY_KEY_PATH.len_in_elements().try_into()?)?;

        if rules_type_key_path.is_empty() {
            // key_path is \REGISTRY\MACHINE\SOFTWARE\FilesystemFilter\Rules
            return Ok(RuleKeyPath::default());
        }

        // rules_type_key_path is "\<RuleType>\<app_name.exe>" or "\<RuleType>"

        let last_slash_idx = rules_type_key_path
            .last_index_of('\\' as _)
            .ok_or(Error::from_ntstatus(STATUS_INVALID_PARAMETER))?;

        if last_slash_idx == 0 {
            // rules_type_key_path is "\<RuleType>"
            let rule_type_str = rules_type_key_path.substr(1)?;
            let rule_type = FileSystemRuleAction::try_from(&rule_type_str).inspect_err(|err| {
                log::error!("Failed to convert {rule_type_str} into FileSystemRuleAction: {err}");
            })?;

            return Ok(RuleKeyPath {
                rule_type: Some(rule_type),
                process_name: None,
            });
        }

        // rules_type_key_path is "\<RuleType>\<app_name.exe>"
        let rule_type_str = rules_type_key_path.slice(1, last_slash_idx.try_into()?)?;
        let rule_type = FileSystemRuleAction::try_from(&rule_type_str)?;

        let process_name = key_path.substr(
            u16::try_from(RULES_REGISTRY_KEY_PATH.len_in_elements())?
                + u16::try_from(last_slash_idx)?
                + 1,
        )?;

        Ok(RuleKeyPath {
            rule_type: Some(rule_type),
            process_name: Some(process_name),
        })
    }

    /// Remove the `process_name` from the `rules` array.
    fn clear_rules_for_process_impl(
        rules: &mut Vec<FileAccessEntry>,
        lock: &mut FltResource,
        process_name: &NtUnicodeStr,
    ) {
        let _lock = lock.acquire_exclusive();

        if let Some(pos) = rules
            .iter()
            .position(|entry| entry.process_name.equals_no_case(process_name))
        {
            let removed_access_entry = rules.remove(pos);
            log::trace!(
                "Removed rules for {} process",
                removed_access_entry.process_name
            );
        } else {
            log::error!("Failed to remove {process_name} process rules: process name not found!");
        }
    }

    /// Remove the specified `process_name` from the [`RulesManager`] rules
    /// that correspond to the specified `rules_type` argument. Does nothing for
    /// [`FileSystemRuleAction::Bypass`] action.
    fn clear_rules_for_process(
        &mut self,
        rules_type: FileSystemRuleAction,
        process_name: &NtUnicodeStr,
    ) {
        match rules_type {
            FileSystemRuleAction::Deny => Self::clear_rules_for_process_impl(
                &mut self.deny_rules,
                &mut self.deny_rules_lock,
                process_name,
            ),
            FileSystemRuleAction::ReadOnly => Self::clear_rules_for_process_impl(
                &mut self.readonly_rules,
                &mut self.readonly_rules_lock,
                process_name,
            ),
            FileSystemRuleAction::Bypass => {}
        }
    }

    /// Rename the `old_process_name` to the `new_process_name` in the `rules` array.
    fn rename_process_rules_impl(
        rules: &mut [FileAccessEntry],
        lock: &mut FltResource,
        old_process_name: &NtUnicodeStr,
        new_process_name: &NtUnicodeStr,
    ) -> ntresult::Result<()> {
        let mut new_process_name = NtUnicodeString::try_from(new_process_name).into_nt_result()?;
        new_process_name.convert_to_upper()?;

        let _lock = lock.acquire_exclusive();

        if let Some(entry) = rules
            .iter_mut()
            .find(|entry| entry.process_name.equals_no_case(old_process_name))
        {
            entry.process_name = new_process_name;
            log::trace!(
                "Renamed rules {old_process_name} process rules to {} process rules",
                entry.process_name
            );
        } else {
            log::error!(
                "Failed to rename {old_process_name} process rules: process name not found!"
            );
        }

        Ok(())
    }

    /// Rename the `old_process_name` to the `new_process_name` in the [`RulesManager`] rules
    /// that correspond to the specified `rules_type`. Does nothing for
    /// [`FileSystemRuleAction::Bypass`] action.
    fn rename_process_rules(
        &mut self,
        rules_type: FileSystemRuleAction,
        old_process_name: &NtUnicodeStr,
        new_process_name: &NtUnicodeStr,
    ) -> ntresult::Result<()> {
        match rules_type {
            FileSystemRuleAction::Deny => Self::rename_process_rules_impl(
                &mut self.deny_rules,
                &mut self.deny_rules_lock,
                old_process_name,
                new_process_name,
            ),
            FileSystemRuleAction::ReadOnly => Self::rename_process_rules_impl(
                &mut self.readonly_rules,
                &mut self.readonly_rules_lock,
                old_process_name,
                new_process_name,
            ),
            FileSystemRuleAction::Bypass => Ok(()),
        }
    }

    /// Remove the `file_path` from the `process_name` rules in the `rules` array.
    fn remove_file_from_process_rules_impl(
        rules: &mut [FileAccessEntry],
        lock: &mut FltResource,
        process_name: &NtUnicodeStr,
        file_path: &NtUnicodeStr,
    ) {
        let _lock = lock.acquire_exclusive();

        if let Some(entry) = rules
            .iter_mut()
            .find(|entry| entry.process_name.equals_no_case(process_name))
        {
            if let Some(pos) = entry
                .file_paths
                .iter_mut()
                .position(|rule_file_path| rule_file_path.equals_no_case(file_path))
            {
                entry.file_paths.remove(pos);
                log::trace!("Removed {file_path} file path rule for the {process_name} process");
            } else {
                log::error!(
                    "Failed to remove {file_path} file path rule for the {process_name} process: file path not found!"
                );
            }
        } else {
            log::error!(
                "Failed to remove {file_path} file path rule for the {process_name} process: process name not found!"
            );
        }
    }

    /// Remove the `file_path` from the `process_name` rules in the [`RulesManager`] rules
    /// that correspond to `rules_type` argument. Does nothing for
    /// [`FileSystemRuleAction::Bypass`] action.
    fn remove_file_from_process_rules(
        &mut self,
        rules_type: FileSystemRuleAction,
        process_name: &NtUnicodeStr,
        file_path: &NtUnicodeStr,
    ) {
        match rules_type {
            FileSystemRuleAction::Deny => Self::remove_file_from_process_rules_impl(
                &mut self.deny_rules,
                &mut self.deny_rules_lock,
                process_name,
                file_path,
            ),
            FileSystemRuleAction::ReadOnly => Self::remove_file_from_process_rules_impl(
                &mut self.readonly_rules,
                &mut self.readonly_rules_lock,
                process_name,
                file_path,
            ),
            FileSystemRuleAction::Bypass => {}
        }
    }

    /// Add the `file_path` to the `process_name` rules in the `rules` array.
    fn add_file_to_process_rules_impl(
        rules: &mut Vec<FileAccessEntry>,
        lock: &mut FltResource,
        process_name: &NtUnicodeStr,
        file_path: NtUnicodeString,
    ) -> ntresult::Result<()> {
        let mut process_name_upcase = NtUnicodeString::try_from(process_name).into_nt_result()?;
        process_name_upcase.convert_to_upper()?;

        let _lock = lock.acquire_exclusive();

        if let Some(entry) = rules
            .iter_mut()
            .find(|entry| entry.process_name.equals_no_case(&process_name_upcase))
        {
            entry.file_paths.try_push(file_path)?;
        } else {
            let mut file_paths = Vec::new();

            file_paths.try_push(file_path)?;

            rules.try_push(FileAccessEntry {
                process_name: process_name_upcase,
                file_paths,
            })?;
        }

        Ok(())
    }

    /// Add the `file_path` to the `process_name` rules in the [`RulesManager`] rules
    /// that correspond to `rules_type` argument. Does nothing for
    /// [`FileSystemRuleAction::Bypass`] action.
    fn add_file_to_process_rules(
        &mut self,
        rules_type: FileSystemRuleAction,
        process_name: &NtUnicodeStr,
        file_path: NtUnicodeString,
    ) -> ntresult::Result<()> {
        match rules_type {
            FileSystemRuleAction::Deny => Self::add_file_to_process_rules_impl(
                &mut self.deny_rules,
                &mut self.deny_rules_lock,
                process_name,
                file_path,
            ),
            FileSystemRuleAction::ReadOnly => Self::add_file_to_process_rules_impl(
                &mut self.readonly_rules,
                &mut self.readonly_rules_lock,
                process_name,
                file_path,
            ),
            FileSystemRuleAction::Bypass => Ok(()),
        }
    }

    /// Rename the old `key_path` to the `new_key_name`.
    ///
    /// Parses the `key_path` to get it's parts and renames process rules if
    /// the key if the [`RuleKeyPath::rule_type`] and [`RuleKeyPath::process_name`] aren't `None`.
    pub fn rename_key_rules(
        key_path: &NtUnicodeStr,
        new_key_name: &NtUnicodeStr,
    ) -> ntresult::Result<()> {
        log::info!("Rename key: {key_path} to {new_key_name}");

        let rules_manager = Self::instance_mut();

        let parsed_key_rule = Self::parse_protection_rule_key(key_path)?;

        if let (Some(rules_type), Some(old_process_name)) =
            (parsed_key_rule.rule_type, parsed_key_rule.process_name)
        {
            rules_manager.rename_process_rules(rules_type, &old_process_name, new_key_name)?;

            log::info!(
                "Successfully renamed {} rules from process {old_process_name} to {new_key_name}",
                NtUnicodeStr::try_from(rules_type)?
            );
        }

        Ok(())
    }

    /// Deletes protection rules for the specified `key_path`.
    ///
    /// Parses the key path and deletes the key if the [`RuleKeyPath::rule_type`]
    /// and [`RuleKeyPath::process_name`] aren't `None`.
    pub fn delete_key_rules(key_path: &NtUnicodeStr) -> ntresult::Result<()> {
        log::info!("Delete key: {key_path}");

        let rules_manager = Self::instance_mut();

        let parsed_key_rule = Self::parse_protection_rule_key(key_path)?;

        if let (Some(rules_type), Some(process_name)) =
            (parsed_key_rule.rule_type, parsed_key_rule.process_name)
        {
            rules_manager.clear_rules_for_process(rules_type, &process_name);

            log::info!(
                "Successfully removed {} rules for process {process_name}",
                NtUnicodeStr::try_from(rules_type)?
            );
        }

        Ok(())
    }

    /// Delete the `value_name` key value (file path) from the [`RulesManager`]
    /// according to the `key_path` content.
    ///
    /// Converts the file path to valid format using [`prepare_rule_file_path`].
    ///
    /// Removes the file path from the `process_name` rules according to rule type
    /// from the `key_path`.
    pub fn delete_key_value_rule(
        key_path: &NtUnicodeStr,
        value_name: &NtUnicodeStr,
    ) -> ntresult::Result<()> {
        log::info!("Delete key {key_path} value {value_name}");

        let rules_manager = Self::instance_mut();

        let mut file_path = NtUnicodeString::try_from(value_name).into_nt_result()?;
        prepare_rule_file_path(&mut file_path)?;

        let parsed_key_rule = Self::parse_protection_rule_key(key_path)?;

        if let (Some(rules_type), Some(process_name)) =
            (parsed_key_rule.rule_type, parsed_key_rule.process_name)
        {
            rules_manager.remove_file_from_process_rules(rules_type, &process_name, &file_path);

            log::info!(
                "Successfully removed {} rule for process {process_name} and file path {file_path}",
                NtUnicodeStr::try_from(rules_type)?
            );
        }

        Ok(())
    }

    /// Set the `value_name` (file path) to the process rules from the `key_path`.
    ///
    /// Converts the file path to valid format using [`prepare_rule_file_path`].
    ///
    /// Adds the file path to the `process_name` rules according to rule type
    /// from the `key_path`.
    pub fn set_key_value_rule(
        key_path: &NtUnicodeStr,
        value_name: &NtUnicodeStr,
    ) -> ntresult::Result<()> {
        log::info!("Set key {key_path} value {value_name}");

        let rules_manager = Self::instance_mut();

        let mut file_path = NtUnicodeString::try_from(value_name).into_nt_result()?;
        prepare_rule_file_path(&mut file_path)?;

        let parsed_key_rule = Self::parse_protection_rule_key(key_path)?;

        if let (Some(rules_type), Some(process_name)) =
            (parsed_key_rule.rule_type, parsed_key_rule.process_name)
        {
            rules_manager.add_file_to_process_rules(rules_type, &process_name, file_path)?;

            log::info!(
                "Successfully added {} rule for process {process_name} and file path {value_name}",
                NtUnicodeStr::try_from(rules_type)?
            );
        }

        Ok(())
    }

    /// Get a mutable reference to the [`RulesManager`] global instance
    /// stored in the [`Driver`] instance.
    pub fn instance_mut<'a>() -> &'a mut Self {
        Driver::instance_mut()
            .rules_manager
            .as_mut()
            .expect("Rules manager must exist to get a mutable instance reference.")
    }
}
