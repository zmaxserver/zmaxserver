//! Geriye dönük uyumluluk köprüsü (`acme_runtime` -> `config::acme`).
pub use crate::config::acme::*;

#[cfg(test)]
pub mod tests {
    pub use crate::config::acme::tests::*;

    #[test]
    fn apply_global_acme_root_sets_only_when_non_empty() {
        super::tests::resolve_global_acme_root_resolves_default_and_override();
    }

    #[test]
    fn resolve_vhost_acme_root_handles_relative_empty_and_absolute() {
        super::tests::resolve_vhost_acme_root_handles_relative_empty_and_absolute();
    }
}
