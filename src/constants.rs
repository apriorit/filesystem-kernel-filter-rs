use const_format::concatcp;
use nt_string::{nt_unicode_str, unicode_string::NtUnicodeStr};

const SOFTWARE_KEY_PATH: &str = "\\REGISTRY\\MACHINE\\SOFTWARE";

const FILTER_KEY_NAME: &str = "FilesystemFilter";
const FILTER_KEY_PATH: &str = concatcp!(SOFTWARE_KEY_PATH, "\\", FILTER_KEY_NAME);
pub const FILTER_REGISTRY_KEY_PATH: NtUnicodeStr<'static> = nt_unicode_str!(FILTER_KEY_PATH);

const RULES_KEY_NAME: &str = "Rules";
const RULES_KEY_PATH: &str = concatcp!(FILTER_KEY_PATH, "\\", RULES_KEY_NAME);
pub const RULES_REGISTRY_KEY_PATH: NtUnicodeStr<'static> = nt_unicode_str!(RULES_KEY_PATH);

const DENY_KEY_NAME: &str = "Deny";
pub const DENY_RULES_REGISTRY_KEY_NAME: NtUnicodeStr<'static> = nt_unicode_str!(DENY_KEY_NAME);
const DENY_KEY_PATH: &str = concatcp!(RULES_KEY_PATH, "\\", DENY_KEY_NAME);
pub const DENY_RULES_REGISTRY_KEY_PATH: NtUnicodeStr<'static> = nt_unicode_str!(DENY_KEY_PATH);

const READ_ONLY_KEY_NAME: &str = "ReadOnly";
pub const READ_ONLY_RULES_REGISTRY_KEY_NAME: NtUnicodeStr<'static> = nt_unicode_str!("ReadOnly");
const READ_ONLY_KEY_PATH: &str = concatcp!(RULES_KEY_PATH, "\\", READ_ONLY_KEY_NAME);
pub const READ_ONLY_RULES_REGISTRY_KEY_PATH: NtUnicodeStr<'static> =
    nt_unicode_str!(READ_ONLY_KEY_PATH);

pub const FOLDER_RULE_POSTFIX: NtUnicodeStr<'static> = nt_unicode_str!("\\*");
