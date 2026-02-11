use anyhow::{Context, Result, anyhow};
use log::{debug, info, trace};
use reqwest::blocking::Client;
use serde_json::Value;
use url::Url;

pub fn create_index(
    client: &Client,
    base_url: &Url,
    username: &str,
    password: &str,
    index_name: &str,
    mapping: &Value,
) -> Result<()> {
    let index_url = base_url.join(index_name)?;

    info!("Creating index '{}' at {}", index_name, index_url);

    let response = client
        .put(index_url.clone())
        .basic_auth(username, Some(password))
        .json(mapping)
        .send()
        .context("Failed to send create index request")?;

    let status = response.status();
    let text = response.text().unwrap_or_default();

    debug!("Elastic response: {} - {}", status, text);

    if !status.is_success() {
        if text.contains("resource_already_exists_exception") {
            info!("Index '{}' already exists.", index_name);
            return Ok(());
        }
        return Err(anyhow!(
            "Failed to create index. Status: {}. Response: {}",
            status,
            text
        ));
    }

    info!("Index '{}' created successfully.", index_name);
    Ok(())
}

pub fn index_event(
    client: &Client,
    base_url: &Url,
    username: &str,
    password: &str,
    index_name: &str,
    event: &Value,
) -> Result<()> {
    let index_url = base_url.join(&format!("{}/_doc", index_name))?;

    let body_str = serde_json::to_string(event)?;
    trace!("Sending event payload: {}", body_str);

    let response = client
        .post(index_url)
        .basic_auth(username, Some(password))
        .header("Content-Type", "application/json")
        .body(body_str) // Use the serialized string
        .send()
        .context("Failed to send index event request")?;

    let status = response.status();
    if !status.is_success() {
        let text = response.text().unwrap_or_default();
        return Err(anyhow!(
            "Failed to index event. Status: {}. Response: {}",
            status,
            text
        ));
    }

    Ok(())
}
