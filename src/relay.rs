use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Debug)]
pub struct RelayPool {
    relays: Vec<RelayHandle>,
}

impl RelayPool {
    pub async fn new(
        relay_urls: Vec<String>,
        filters_json: String,
        inbound: Option<mpsc::UnboundedSender<String>>,
    ) -> Self {
        let mut relays = Vec::new();
        for url in relay_urls {
            let handle = RelayHandle::spawn(url, filters_json.clone(), inbound.clone());
            relays.push(handle);
        }
        Self { relays }
    }

    pub fn empty() -> Self {
        Self { relays: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    pub fn broadcast(&self, frame_json: &str) {
        for r in &self.relays {
            let _ = r.tx.send(frame_json.to_string());
        }
    }
}

#[derive(Clone, Debug)]
struct RelayHandle {
    tx: mpsc::UnboundedSender<String>,
}

impl RelayHandle {
    fn spawn(url: String, filters_json: String, inbound: Option<mpsc::UnboundedSender<String>>) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            loop {
                match connect_async(&url).await {
                    Ok((ws, _)) => {
                        tracing::info!(relay = %url, "relay connected");
                        let (mut write, mut read) = ws.split();

                        if let Err(err) = write.send(Message::Text(filters_json.clone())).await {
                            tracing::warn!(relay = %url, error = %err, "relay send REQ failed");
                            let _ = write.close().await;
                            sleep(Duration::from_secs(2)).await;
                            continue;
                        }

                        loop {
                            tokio::select! {
                                Some(out) = rx.recv() => {
                                    if let Err(err) = write.send(Message::Text(out)).await {
                                        tracing::warn!(relay = %url, error = %err, "relay send failed");
                                        break;
                                    }
                                }
                                msg = read.next() => {
                                    match msg {
                                        Some(Ok(Message::Text(txt))) => {
                                            if let Some(tx) = inbound.as_ref() {
                                                let _ = tx.send(txt.clone());
                                            }
                                            tracing::debug!(relay = %url, frame = %txt, "relay rx");
                                        }
                                        Some(Ok(_)) => {}
                                        Some(Err(err)) => {
                                            tracing::warn!(relay = %url, error = %err, "relay read failed");
                                            break;
                                        }
                                        None => break,
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!(relay = %url, error = %err, "relay connect failed");
                    }
                }
                sleep(Duration::from_secs(3)).await;
            }
        });
        Self { tx }
    }
}
