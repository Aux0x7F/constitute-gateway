use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use constitute_protocol::{
    log_event_id, validate_log_event, LogCategory, LogCorrelationRef, LogEventEnvelope, LogOutcome,
    LogProducerRef, LogRedactionClass, LogSeverity, LogSubjectRef, LOG_SCHEMA_VERSION,
};
use reqwest::Client as HttpClient;
use serde_json::{json, Value};
use tracing::debug;

use crate::util;

pub async fn submit_safe_event(
    client: &HttpClient,
    component: &str,
    category: LogCategory,
    severity: LogSeverity,
    outcome: LogOutcome,
    subject: LogSubjectRef,
    tags: &[&str],
    safe_facts: Value,
) {
    let mut event = LogEventEnvelope {
        schema_version: LOG_SCHEMA_VERSION,
        event_id: String::new(),
        occurred_at: util::now_unix_seconds(),
        received_at: None,
        producer: LogProducerRef {
            service: "gateway".to_string(),
            component: component.to_string(),
            instance_id: None,
            gateway_pk: None,
            service_pk: None,
        },
        category,
        severity,
        outcome,
        subject: Some(subject),
        resource: None,
        correlation: Some(LogCorrelationRef {
            correlation_id: format!("gateway-{}", util::now_unix_seconds()),
            causation_id: None,
            trace_id: None,
        }),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        safe_facts,
        detail_ref: None,
        redaction: vec![LogRedactionClass::Safe],
    };
    event.event_id = match log_event_id(&event) {
        Ok(id) => id,
        Err(_) => return,
    };
    if validate_log_event(&event).is_err() {
        return;
    }
    append_outbox(&event);
    submit_to_logging(client, &event).await;
}

async fn submit_to_logging(client: &HttpClient, event: &LogEventEnvelope) {
    let Some(base_url) = logging_url() else {
        return;
    };
    let request = json!({
        "cursor": event.event_id,
        "events": [event],
    });
    let url = format!(
        "{}/v1/producers/gateway/events",
        base_url.trim_end_matches('/')
    );
    match tokio::time::timeout(
        Duration::from_secs(2),
        client.post(url).json(&request).send(),
    )
    .await
    {
        Ok(Ok(resp)) if resp.status().is_success() => {
            debug!(event_id = %event.event_id, "logging event submitted");
        }
        _ => {}
    }
}

fn append_outbox(event: &LogEventEnvelope) {
    let Some(path) = outbox_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        if let Ok(line) = serde_json::to_string(event) {
            let _ = writeln!(file, "{line}");
        }
    }
}

fn logging_url() -> Option<String> {
    std::env::var("CONSTITUTE_LOGGING_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn outbox_path() -> Option<PathBuf> {
    let override_path = std::env::var("CONSTITUTE_GATEWAY_LOG_OUTBOX")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    Some(override_path.map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(crate::platform::default_data_dir()).join("log-events.jsonl")
    }))
}
