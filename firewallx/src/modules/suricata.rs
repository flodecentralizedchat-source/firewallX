// firewallx/src/modules/suricata.rs
// Parser for Suricata / Snort .rules files

use crate::modules::dpi::{Signature, Severity, SigCategory};
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

/// Parses a `.rules` string and translates compatible rules to standard `Signature` objects.
pub struct SuricataParser;

impl SuricataParser {
    /// Loads a `.rules` file from a path
    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<Vec<Signature>> {
        let text = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read Suricata rules file {:?}", path.as_ref()))?;
        Ok(Self::parse_string(&text))
    }

    /// Parses a string of Suricata/Snort rules.
    /// Expects formats like:
    /// alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"MALWARE-CNC Win.Trojan.X"; flow:established,to_server; content:"POST"; content:"User-Agent|3A| Mozilla/"; sid:2000001; rev:1;)
    pub fn parse_string(text: &str) -> Vec<Signature> {
        let mut signatures = Vec::new();
        // Fallback ID if no sid is provided
        let mut fallback_id = 100_000;

        for line in text.lines() {
            let line = line.trim();
            // Ignore comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Only process lines starting with an action like 'alert', 'drop', 'pass', etc.
            // For simplicity, we grab anything that has a (msg:...) block.
            if let Some(opts_start) = line.find('(') {
                if let Some(opts_end) = line.rfind(')') {
                    let options = &line[opts_start + 1..opts_end];
                    
                    if let Some(sig) = Self::parse_rule_options(options, &mut fallback_id) {
                        signatures.push(sig);
                    }
                }
            }
        }

        signatures
    }

    /// Parses the components inside the parenthesis of a rule.
    fn parse_rule_options(options: &str, fallback_id: &mut u32) -> Option<Signature> {
        let mut sid = None;
        let mut msg = String::from("Imported Suricata Rule");
        let mut contents = Vec::new();
        let mut classtype = String::new();

        // Very basic split by semicolon. Note: This could break if there is an escaped semicolon inside a string
        let parts: Vec<&str> = options.split(';').map(|s| s.trim()).collect();

        for part in parts {
            if part.is_empty() {
                continue;
            }

            let split: Vec<&str> = part.splitn(2, ':').collect();
            if split.len() == 2 {
                let key = split[0].trim().to_lowercase();
                let val = split[1].trim().trim_matches('"'); // remove surrounding quotes

                match key.as_str() {
                    "sid" => {
                        if let Ok(id) = val.parse::<u32>() {
                            sid = Some(id);
                        }
                    }
                    "msg" => {
                        msg = val.to_string();
                    }
                    "classtype" => {
                        classtype = val.to_string();
                    }
                    "content" => {
                        if let Some(parsed_content) = Self::parse_content_string(val) {
                            if !parsed_content.is_empty() {
                                contents.push(parsed_content);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // If we found at least one content string, we'll create a Signature
        if !contents.is_empty() {
            let id = sid.unwrap_or_else(|| {
                *fallback_id += 1;
                *fallback_id
            });

            // Map classtype to SigCategory (rough approximation)
            let category = match classtype.as_str() {
                "trojan-activity" | "malware-cnc" => SigCategory::Malware,
                "attempted-admin" | "attempted-user" | "web-application-attack" => SigCategory::Exploit,
                "policy-violation" => SigCategory::Policy,
                _ => SigCategory::Anomaly,
            };

            // Map standard severities (we default imported rules to Medium/High so they block)
            let severity = match category {
                SigCategory::Malware => Severity::Critical,
                SigCategory::Exploit => Severity::High,
                SigCategory::Anomaly => Severity::Medium,
                SigCategory::Policy => Severity::Medium,
                SigCategory::Protocol => Severity::Low,
            };

            // In FirewallX DPI Engine V1, Signature struct takes a single `Vec<u8>` pattern.
            // For now, we'll just take the longest `content` string found to have the highest uniqueness.
            // A more advanced engine would logically AND all contents together.
            let best_content = contents.into_iter().max_by_key(|c| c.len()).unwrap();

            return Some(Signature::new(
                id,
                &msg,
                &best_content,
                0, // Default offset to 0 as we do full packet scans
                severity,
                category,
            ));
        }

        None
    }

    /// Parses Suricata content strings which can mix plain text and hex bytes (e.g. `User-Agent|3A 20|Mozilla`)
    fn parse_content_string(raw: &str) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut in_hex = false;
        let mut hex_buffer = String::new();

        for c in raw.chars() {
            if c == '|' {
                if in_hex {
                    // Flush hex buffer
                    for byte_str in hex_buffer.split_whitespace() {
                        if let Ok(b) = u8::from_str_radix(byte_str, 16) {
                            out.push(b);
                        }
                    }
                    hex_buffer.clear();
                    in_hex = false;
                } else {
                    in_hex = true;
                }
            } else if in_hex {
                hex_buffer.push(c);
            } else {
                out.push(c as u8);
            }
        }

        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_content_string_plain() {
        let raw = "GET / HTTP/1.1";
        let parsed = SuricataParser::parse_content_string(raw).unwrap();
        assert_eq!(String::from_utf8(parsed).unwrap(), "GET / HTTP/1.1");
    }

    #[test]
    fn test_parse_content_string_with_hex() {
        let raw = "User-Agent|3A 20|Mozilla";
        let parsed = SuricataParser::parse_content_string(raw).unwrap();
        assert_eq!(String::from_utf8(parsed).unwrap(), "User-Agent: Mozilla");
    }

    #[test]
    fn test_parse_rule_full() {
        let rules_str = r#"
        alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"MALWARE-CNC Win.Trojan.Zeus"; flow:established,to_server; content:"POST"; content:"|2F|zeus|2E|php"; classtype:trojan-activity; sid:2000001; rev:1;)
        # this is a comment
        alert tcp any any -> any any (msg:"POLICY Default SSH"; content:"SSH-2.0-"; classtype:policy-violation; sid:100;)
        "#;

        let sigs = SuricataParser::parse_string(rules_str);
        assert_eq!(sigs.len(), 2);
        
        let zeus = sigs.iter().find(|s| s.id == 2000001).unwrap();
        assert_eq!(zeus.name, "MALWARE-CNC Win.Trojan.Zeus");
        assert_eq!(zeus.category, SigCategory::Malware);
        assert_eq!(zeus.severity, Severity::Critical);
        // The parser grabs the longest content ("POST" vs "/zeus.php")
        assert_eq!(String::from_utf8(zeus.pattern.clone()).unwrap(), "/zeus.php");

        let ssh = sigs.iter().find(|s| s.id == 100).unwrap();
        assert_eq!(ssh.name, "POLICY Default SSH");
        assert_eq!(ssh.category, SigCategory::Policy);
    }
}
