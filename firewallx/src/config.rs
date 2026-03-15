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
    #[serde(default)]
    pub feeds: Vec<String>,
    #[serde(default)]
    pub suricata_rules: Vec<String>,
    #[serde(default = "default_rate_limit")]
    pub max_connections_per_sec: u32,
    #[serde(default = "default_bandwidth")]
    pub max_bandwidth_mbps: u64,
    #[serde(default)]
    pub wg_peers: Vec<String>,
    #[serde(default)]
    pub siem_enabled: bool,
    #[serde(default)]
    pub siem_url: Option<String>,
    #[serde(default)]
    pub siem_api_key: Option<String>,
    
    // New Production Features configuration
    #[serde(default)]
    pub prometheus_enabled: bool,
    #[serde(default = "default_prometheus_addr")]
    pub prometheus_addr: String,
    #[serde(default)]
    pub json_logging: bool,
    #[serde(default = "default_blocklist_update_interval")]
    pub blocklist_update_interval_secs: u64,
    
    // AI Integration Settings
    #[serde(default)]
    pub ai_agent_enabled: bool,
    #[serde(default)]
    pub openai_api_key: Option<String>,
    #[serde(default = "default_ai_model")]
    pub ai_model: String,
}

fn default_rate_limit() -> u32 { 100 }
fn default_bandwidth() -> u64 { 1000 } // 1 Gbps default
fn default_prometheus_addr() -> String { "0.0.0.0:9100".to_string() }
fn default_blocklist_update_interval() -> u64 { 3600 }
fn default_ai_model() -> String { "gpt-4o-mini".to_string() }

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
