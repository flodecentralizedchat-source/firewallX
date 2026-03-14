#[derive(Debug, PartialEq, Eq)]
pub enum FirewallError {
    General(String),
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallError::General(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for FirewallError {}
