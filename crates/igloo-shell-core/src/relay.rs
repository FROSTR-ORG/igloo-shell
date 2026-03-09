use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use k256::schnorr::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, interval};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    #[serde(default)]
    pub ids: Option<Vec<String>>,
    #[serde(default)]
    pub authors: Option<Vec<String>>,
    #[serde(default)]
    pub kinds: Option<Vec<u64>>,
    #[serde(default)]
    pub since: Option<u64>,
    #[serde(default)]
    pub until: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEvent {
    pub content: String,
    pub created_at: u64,
    pub id: String,
    pub kind: u64,
    pub pubkey: String,
    pub sig: String,
    pub tags: Vec<Vec<String>>,
}

#[derive(Debug, Clone)]
struct Subscription {
    client_id: u64,
    sub_id: String,
    filters: Vec<EventFilter>,
}

#[derive(Debug)]
struct RelayState {
    cache: Vec<SignedEvent>,
    subscriptions: HashMap<String, Subscription>,
    clients: HashMap<u64, mpsc::UnboundedSender<Message>>,
    conn: usize,
    next_client_id: u64,
}

impl RelayState {
    fn new() -> Self {
        Self {
            cache: Vec::new(),
            subscriptions: HashMap::new(),
            clients: HashMap::new(),
            conn: 0,
            next_client_id: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NostrRelay {
    pub host: String,
    pub port: u16,
    pub purge_interval_secs: Option<u64>,
    state: Arc<Mutex<RelayState>>,
}

impl NostrRelay {
    pub fn new(host: impl Into<String>, port: u16, purge_interval_secs: Option<u64>) -> Self {
        Self {
            host: host.into(),
            port,
            purge_interval_secs,
            state: Arc::new(Mutex::new(RelayState::new())),
        }
    }

    pub async fn start(&self) -> Result<()> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr)
            .await
            .with_context(|| format!("bind relay {addr}"))?;

        if let Some(purge_secs) = self.purge_interval_secs {
            let state = self.state.clone();
            tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(purge_secs));
                loop {
                    ticker.tick().await;
                    let mut guard = state.lock().await;
                    guard.cache.clear();
                }
            });
        }

        loop {
            let (stream, _) = listener.accept().await.context("accept ws client")?;
            let relay = self.clone();
            tokio::spawn(async move {
                if let Err(err) = relay.handle_client(stream).await {
                    tracing::debug!(domain = "relay", event = "client_ended", error = %err);
                }
            });
        }
    }

    async fn handle_client(&self, stream: TcpStream) -> Result<()> {
        let ws = accept_async(stream).await.context("ws accept")?;
        let (mut writer, mut reader) = ws.split();

        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

        let client_id = {
            let mut state = self.state.lock().await;
            let id = state.next_client_id;
            state.next_client_id = state.next_client_id.saturating_add(1);
            state.conn = state.conn.saturating_add(1);
            state.clients.insert(id, tx);
            id
        };

        let writer_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if writer.send(msg).await.is_err() {
                    break;
                }
            }
        });

        while let Some(frame) = reader.next().await {
            match frame {
                Ok(Message::Text(text)) => {
                    self.handle_text(client_id, text.as_ref()).await;
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }

        writer_task.abort();
        self.cleanup_client(client_id).await;
        Ok(())
    }

    async fn cleanup_client(&self, client_id: u64) {
        let mut state = self.state.lock().await;
        state.clients.remove(&client_id);
        state.conn = state.conn.saturating_sub(1);

        let remove_ids: Vec<String> = state
            .subscriptions
            .iter()
            .filter_map(|(k, v)| {
                if v.client_id == client_id {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        for key in remove_ids {
            state.subscriptions.remove(&key);
        }
    }

    async fn handle_text(&self, client_id: u64, text: &str) {
        let parsed: Result<Value, _> = serde_json::from_str(text);
        let Ok(Value::Array(parts)) = parsed else {
            self.send_notice(client_id, "Unable to parse message").await;
            return;
        };

        let Some(Value::String(verb)) = parts.first() else {
            self.send_notice(client_id, "Unable to parse message").await;
            return;
        };

        match verb.as_str() {
            "REQ" => self.handle_req(client_id, &parts).await,
            "EVENT" => self.handle_event(client_id, &parts).await,
            "CLOSE" => self.handle_close(client_id, &parts).await,
            _ => {
                self.send_notice(client_id, "Unable to handle message")
                    .await
            }
        }
    }

    async fn handle_req(&self, client_id: u64, parts: &[Value]) {
        let Some(Value::String(sub_id)) = parts.get(1) else {
            self.send_notice(client_id, "Invalid REQ").await;
            return;
        };

        let filters = if parts.len() == 3 {
            if let Some(Value::Array(items)) = parts.get(2) {
                items
                    .iter()
                    .filter_map(|v| serde_json::from_value::<EventFilter>(v.clone()).ok())
                    .collect::<Vec<_>>()
            } else {
                parts[2..]
                    .iter()
                    .filter_map(|v| serde_json::from_value::<EventFilter>(v.clone()).ok())
                    .collect::<Vec<_>>()
            }
        } else {
            parts[2..]
                .iter()
                .filter_map(|v| serde_json::from_value::<EventFilter>(v.clone()).ok())
                .collect::<Vec<_>>()
        };

        if filters.is_empty() {
            self.send_notice(client_id, "Invalid REQ filters").await;
            return;
        }

        let (events, sender) = {
            let mut state = self.state.lock().await;
            let key = format!("{client_id}/{sub_id}");
            state.subscriptions.insert(
                key,
                Subscription {
                    client_id,
                    sub_id: sub_id.clone(),
                    filters: filters.clone(),
                },
            );

            let cache = state.cache.clone();
            let sender = state.clients.get(&client_id).cloned();
            (cache, sender)
        };

        if let Some(tx) = sender {
            for filter in &filters {
                let mut remaining = filter.limit;
                for event in &events {
                    let allow = remaining.map(|r| r > 0).unwrap_or(true);
                    if !allow {
                        break;
                    }
                    if match_filter(event, filter) {
                        let _ = tx.send(Message::Text(
                            json!(["EVENT", sub_id, event]).to_string().into(),
                        ));
                        if let Some(left) = remaining.as_mut() {
                            *left = left.saturating_sub(1);
                        }
                    }
                }
            }
            let _ = tx.send(Message::Text(json!(["EOSE", sub_id]).to_string().into()));
        }
    }

    async fn handle_event(&self, client_id: u64, parts: &[Value]) {
        let Some(event_value) = parts.get(1) else {
            self.send_notice(client_id, "Invalid EVENT").await;
            return;
        };
        let Ok(event) = serde_json::from_value::<SignedEvent>(event_value.clone()) else {
            self.send_notice(client_id, "Invalid EVENT").await;
            return;
        };

        let ok = verify_signed_event(&event);
        self.send_ok(client_id, event.id.clone(), ok, if ok { "" } else { "invalid sig" })
            .await;
        if !ok {
            return;
        }

        let targets = {
            let mut state = self.state.lock().await;
            if !state.cache.iter().any(|existing| existing.id == event.id) {
                state.cache.push(event.clone());
            }
            state
                .subscriptions
                .values()
                .filter(|sub| sub.filters.iter().any(|filter| match_filter(&event, filter)))
                .map(|sub| (sub.client_id, sub.sub_id.clone()))
                .collect::<Vec<_>>()
        };

        for (target_client, sub_id) in targets {
            self.send_to_client(target_client, json!(["EVENT", sub_id, event]).to_string())
                .await;
        }
    }

    async fn handle_close(&self, client_id: u64, parts: &[Value]) {
        let Some(Value::String(sub_id)) = parts.get(1) else {
            self.send_notice(client_id, "Invalid CLOSE").await;
            return;
        };
        let mut state = self.state.lock().await;
        state
            .subscriptions
            .remove(&format!("{client_id}/{sub_id}"));
    }

    async fn send_notice(&self, client_id: u64, message: &str) {
        self.send_to_client(client_id, json!(["NOTICE", message]).to_string())
            .await;
    }

    async fn send_ok(&self, client_id: u64, id: String, ok: bool, message: &str) {
        self.send_to_client(client_id, json!(["OK", id, ok, message]).to_string())
            .await;
    }

    async fn send_to_client(&self, client_id: u64, message: String) {
        let sender = {
            let state = self.state.lock().await;
            state.clients.get(&client_id).cloned()
        };
        if let Some(tx) = sender {
            let _ = tx.send(Message::Text(message.into()));
        }
    }
}

pub async fn run_relay_command(args: &[String]) -> Result<()> {
    let host = arg_value(args, "--host").unwrap_or_else(|| {
        env::var("DEV_RELAY_HOST").unwrap_or_else(|_| "127.0.0.1".to_string())
    });
    let port = arg_value(args, "--port")
        .and_then(|value| value.parse::<u16>().ok())
        .or_else(|| env::var("DEV_RELAY_PORT").ok().and_then(|value| value.parse::<u16>().ok()))
        .unwrap_or(8194);
    let purge_interval_secs = arg_value(args, "--purge-interval-secs")
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(|| {
            env::var("DEV_RELAY_PURGE_INTERVAL_SECS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
        });

    let relay = NostrRelay::new(host.clone(), port, purge_interval_secs);
    info!(domain = "relay", host, port, "dev relay starting");
    relay.start().await
}

fn arg_value(args: &[String], key: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == key {
            return args.get(i + 1).cloned();
        }
    }
    None
}

fn match_filter(event: &SignedEvent, filter: &EventFilter) -> bool {
    if let Some(ids) = &filter.ids
        && !ids.iter().any(|id| event.id.starts_with(id))
    {
        return false;
    }
    if let Some(authors) = &filter.authors
        && !authors.iter().any(|author| event.pubkey.starts_with(author))
    {
        return false;
    }
    if let Some(kinds) = &filter.kinds
        && !kinds.contains(&event.kind)
    {
        return false;
    }
    if let Some(since) = filter.since
        && event.created_at < since
    {
        return false;
    }
    if let Some(until) = filter.until
        && event.created_at > until
    {
        return false;
    }
    true
}

fn verify_signed_event(event: &SignedEvent) -> bool {
    let preimage = json!([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
    let encoded = match serde_json::to_vec(&preimage) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let digest = Sha256::digest(encoded);
    if hex::encode(digest) != event.id {
        return false;
    }

    let Ok(pubkey_bytes) = hex::decode(&event.pubkey) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(&event.sig) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(pubkey_bytes.as_slice()) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    key.verify_raw(&digest, &signature).is_ok()
}
