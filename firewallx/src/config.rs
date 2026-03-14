use crate::modules::rule::RuleSet;
use crate::modules::ids::IdsConfig;
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

#[derive(Serialize, Deserialize, Default)]
pub struct FirewallConfig {
    pub ids: IdsConfig,
    pub ruleset: RuleSet,
}

impl FirewallConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file at {:?}", path.as_ref()))?;
        let config: FirewallConfig = toml::from_str(&contents)
            .with_context(|| "Failed to parse toml config")?;
        Ok(config)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let toml_string = toml::to_string_pretty(self)
            .with_context(|| "Failed to serialize config to toml")?;
        if let Some(parent) = path.as_ref().parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(path.as_ref(), toml_string)
            .with_context(|| format!("Failed to write config file to {:?}", path.as_ref()))?;
        Ok(())
    }
}
