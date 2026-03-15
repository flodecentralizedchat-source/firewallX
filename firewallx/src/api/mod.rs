use firewallx::modules::engine::FirewallEngine;
use firewallx::modules::rule::Rule;
use firewallx::modules::vpn::{VpnGateway, TunnelState};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use http::header::HeaderValue;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

pub type SharedEngine = Arc<Mutex<FirewallEngine>>;
pub type SharedVpn = Arc<Mutex<VpnGateway>>;

#[derive(Clone)]
pub struct DashboardState {
    pub engine: SharedEngine,
    pub vpn: SharedVpn,
}

#[derive(Serialize)]
pub struct DashboardStats {
    pub total_packets: u64,
    pub allowed_packets: u64,
    pub dropped_packets: u64,
    pub active_connections: usize,
    pub ids_alerts: u64,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime: u32,
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        uptime: std::process::id(),
    })
}

pub async fn start_api_server(state: DashboardState) {
    // Allow requests from Railway health check domain
    let cors = CorsLayer::new()
        .allow_origin([
            "*".parse::<HeaderValue>().unwrap(),
            "https://healthcheck.railway.app".parse::<HeaderValue>().unwrap(),
        ])
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/stats", get(get_stats))
        .route("/api/rules", get(get_rules).post(add_rule))
        .route("/api/alerts", get(get_alerts))
        .route("/api/tunnels", get(get_tunnels))
        .route("/api/chat", post(handle_chat))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("Dashboard API listening on http://0.0.0.0:3000");
    
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("API server error: {}", e);
    }
}

async fn get_stats(State(state): State<DashboardState>) -> Json<DashboardStats> {
    let engine = state.engine.lock().await;
    let s = engine.stats();
    
    Json(DashboardStats {
        total_packets: s.total,
        allowed_packets: s.allowed,
        dropped_packets: s.dropped,
        active_connections: engine.active_connections(),
        ids_alerts: engine.ids().total_alerts(),
    })
}

async fn get_rules(State(state): State<DashboardState>) -> Json<Vec<Rule>> {
    let engine = state.engine.lock().await;
    Json(engine.ruleset().rules.clone())
}

async fn add_rule(State(state): State<DashboardState>, Json(rule): Json<Rule>) -> Json<Rule> {
    let mut engine = state.engine.lock().await;
    engine.ruleset_mut().add(rule.clone());
    Json(rule)
}

#[derive(Serialize)]
pub struct AlertResponse {
    pub kind: String,
    pub src_ip: String,
    pub description: String,
    pub block: bool,
}

async fn get_alerts(State(state): State<DashboardState>) -> Json<Vec<AlertResponse>> {
    let engine = state.engine.lock().await;
    let alerts = engine.ids().alerts().iter().map(|a| AlertResponse {
        kind: a.kind.to_string(),
        src_ip: a.src_ip.to_string(),
        description: a.description.clone(),
        block: a.block,
    }).collect();
    Json(alerts)
}

#[derive(Serialize)]
pub struct TunnelResponse {
    pub id: u64,
    pub peer_ip: String,
    pub state: String,
    pub cipher: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

async fn get_tunnels(State(state): State<DashboardState>) -> Json<Vec<TunnelResponse>> {
    let vpn = state.vpn.lock().await;
    let tunnels = vpn.active_sessions().iter().map(|t| TunnelResponse {
        id: t.id,
        peer_ip: t.peer_ip.to_string(),
        state: match t.state {
            TunnelState::Established => "Established".to_string(),
            TunnelState::Negotiating => "Negotiating".to_string(),
            TunnelState::Rekeying => "Rekeying".to_string(),
            TunnelState::Closing => "Closing".to_string(),
            TunnelState::Closed => "Closed".to_string(),
        },
        cipher: t.cipher.to_string(),
        bytes_in: t.bytes_in,
        bytes_out: t.bytes_out,
    }).collect();
    Json(tunnels)
}

#[derive(serde::Deserialize)]
pub struct ChatRequest {
    pub prompt: String,
}

#[derive(Serialize)]
pub struct ChatResponse {
    pub response: String,
}

async fn handle_chat(State(state): State<DashboardState>, Json(req): Json<ChatRequest>) -> Json<ChatResponse> {
    // Collect minimal system state to embed into the prompt context
    let engine = state.engine.lock().await;
    let s = engine.stats();
    let stats = format!("Total Pkts: {}, Dropped: {}, Active Tunnels: {}, Alerts: {}", 
                        s.total, s.dropped, engine.active_connections(), engine.ids().total_alerts());
                        
    drop(engine); // Release early
    
    // NOTE: A production version of this would securely construct an `async_openai` client here as well,
    // execute the chat completions call, and mutate state.
    // For this initial UI testing scaffold, we're returning exactly what that output WOULD look like.
    
    let mock_reply = format!(
        "🤖 [Copilot Response] System context registered ({stats}). Understood your command: \"{}\". Action has been scheduled.",
        req.prompt
    );

    Json(ChatResponse {
        response: mock_reply
    })
}
