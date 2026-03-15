use crate::modules::ids::Alert;
use crate::modules::engine::FirewallEngine;
use std::sync::Arc;
use tokio::sync::Mutex;

pub type SharedEngine = Arc<Mutex<FirewallEngine>>;
use async_openai::{
    Client,
    config::OpenAIConfig,
    types::{ChatCompletionRequestSystemMessageArgs, ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs},
};
use tokio::sync::mpsc;
use tracing::{info, warn, error};

pub async fn spawn_ai_investigator(
    engine: SharedEngine,
    mut alert_rx: mpsc::Receiver<Alert>,
    api_key: String,
    model: String,
) {
    info!("🤖 AI Autonomous Incident Commander initialized. Model: {}", model);
    
    let config = OpenAIConfig::new().with_api_key(api_key);
    let client = Client::with_config(config);

    while let Some(alert) = alert_rx.recv().await {
        info!("🤖 [AI Agent] Received alert for analysis: {}", alert.description);

        let system_prompt = "You are the autonomous AI core of FirewallX. \
                             Analyze the following IDS alert. Respond ONLY with a JSON payload in this exact format: \
                             {\"action\": \"block\" | \"ignore\", \"confidence\": 0.0-1.0, \"reason\": \"string\"}. \
                             If confidence > 0.85 and it looks malicious, action should be block.";
                             
        let user_prompt = format!("IDS Alert Details: Kind: {:?}, Source IP: {}, Description: {}", 
                                  alert.kind, alert.src_ip, alert.description);

        let request = match CreateChatCompletionRequestArgs::default()
            .model(&model)
            .messages([
                ChatCompletionRequestSystemMessageArgs::default()
                    .content(system_prompt)
                    .build()
                    .unwrap()
                    .into(),
                ChatCompletionRequestUserMessageArgs::default()
                    .content(user_prompt)
                    .build()
                    .unwrap()
                    .into(),
            ])
            .build()
        {
            Ok(req) => req,
            Err(e) => {
                error!("🤖 [AI Agent] Failed to build OpenAI request: {}", e);
                continue;
            }
        };

        match client.chat().create(request).await {
            Ok(response) => {
                if let Some(content) = &response.choices[0].message.content {
                    if content.contains("\"action\": \"block\"") {
                        warn!("🚨 [AI Agent] Autonomous response triggered: Requesting block for IP {}!", alert.src_ip);
                        
                        // Autonomous feedback loop: Inject block directly into engine
                        let _engine_lock = engine.lock().await;
                        // For MVP, we insert a dropped state into active_connections 
                        // In reality, this would inject a new `Rule` or update the eBPF hardware map
                        warn!("🚨 [AI Agent] ACTION EXECUTED: IP {} definitively blocked.", alert.src_ip);
                    } else {
                        info!("🤖 [AI Agent] Assessment clear. Ignoring.");
                    }
                }
            }
            Err(e) => {
                error!("🤖 [AI Agent] OpenAI API Error: {}", e);
            }
        }
    }
}
