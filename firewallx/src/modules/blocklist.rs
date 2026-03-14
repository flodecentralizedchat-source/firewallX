// firewallx/src/modules/blocklist.rs

use std::net::Ipv4Addr;
use std::collections::HashSet;

/// Manager for fetching and parsing external threat intelligence blocklists.
pub struct BlocklistManager {
    feeds: Vec<String>,
}

impl BlocklistManager {
    pub fn new() -> Self {
        Self {
            feeds: Vec::new(),
        }
    }

    pub fn add_feed(&mut self, url: String) {
        if !self.feeds.contains(&url) {
            self.feeds.push(url);
        }
    }

    pub fn feeds(&self) -> &[String] {
        &self.feeds
    }

    /// Fetches all configured feeds synchronously.
    /// Returns a combined HashSet of blocked IPv4 addresses.
    pub fn fetch_all_ips(&self) -> Result<HashSet<Ipv4Addr>, anyhow::Error> {
        let mut all_ips = HashSet::new();
        
        // Use a blocking reqwest client with a reasonable timeout
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        for feed_url in &self.feeds {
            match client.get(feed_url).send() {
                Ok(response) => {
                    if response.status().is_success() {
                        if let Ok(text) = response.text() {
                            let parsed = Self::parse_list(&text);
                            all_ips.extend(parsed);
                        }
                    } else {
                        log::warn!("Failed to fetch blocklist feed {}: HTTP {}", feed_url, response.status());
                    }
                }
                Err(e) => {
                    log::warn!("Error fetching blocklist feed {}: {}", feed_url, e);
                }
            }
        }
        
        Ok(all_ips)
    }

    /// Parses a raw text blocklist file into a HashSet of Ipv4Addr.
    /// Supports plain IPs per line, ignores `#` comments and empty lines.
    /// In the future, this could be extended to support CIDR expansion.
    pub fn parse_list(text: &str) -> HashSet<Ipv4Addr> {
        let mut ips = HashSet::new();
        
        for line in text.lines() {
            let line = line.trim();
            // Ignore empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Handle lines with inline comments (e.g., "1.2.3.4 # bad host")
            let content = line.split('#').next().unwrap_or("").trim();
            
            // Basic parsing. If it's a valid IPv4, keep it.
            // If it's a CIDR block (e.g., 1.2.3.0/24), we currently ignore or parse the base IP.
            if let Ok(ip) = content.parse::<Ipv4Addr>() {
                ips.insert(ip);
            }
        }
        
        ips
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_list() {
        let text = r#"
        # This is a comment
        192.168.1.1
        10.0.0.1  # inline comment
        
        invalid_ip
        192.168.1.256 # invalid byte
        "#;
        
        let ips = BlocklistManager::parse_list(text);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"192.168.1.1".parse().unwrap()));
        assert!(ips.contains(&"10.0.0.1".parse().unwrap()));
    }
}
