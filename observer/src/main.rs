// Only compile this module on Windows, as ETW is Windows-specific.
#![cfg(windows)]

use clap::{ArgGroup, Parser};
use log::{LevelFilter, error, info, trace};
use std::process::ExitCode;
use url::Url;
use uuid::Uuid;

mod elastic;
mod etw;
mod schema;

use crate::etw::manifest::fetch_manifest_for_provider;
use crate::etw::provider::{process_events, start_trace_session, stop_trace_session};
use reqwest::blocking::Client;
use std::sync::mpsc;
use std::thread;

/// Configuration structure representing the command-line arguments.
///
/// We derive `Parser` to allow Clap to automatically generate the CLI logic.
/// The `ArgGroup` ensures that the user provides either a GUID, a Provider Name, or both,
/// but never neither.
#[derive(Parser, Debug)]
#[command(name = "irontrace")]
#[command(version = "1.0")]
#[command(about = "Captures ETW events and forwards them to a remote URL.")]
#[command(group(
    ArgGroup::new("provider_identity")
        .required(true)
        .args(["etw_guid", "provider_name"])
))]
struct Cli {
    /// The unique identifier (GUID) of the ETW provider.
    ///
    /// Validated automatically into a Uuid type to prevent format errors early.
    #[arg(short = 'g', long, value_parser = clap::value_parser!(Uuid))]
    etw_guid: Option<Uuid>,

    /// The human-readable name of the ETW provider.
    ///
    /// This is required if the GUID is not provided.
    #[arg(short = 'n', long)]
    provider_name: Option<String>,

    /// The destination URL for the telemetry data.
    ///
    /// validated as a standard URL.
    #[arg(short = 'u', long, value_parser = clap::value_parser!(Url))]
    url: Url,

    /// Username for authentication with the remote endpoint.
    #[arg(short = 'U', long)]
    username: String,

    /// Password for authentication.
    ///
    /// In a real-world scenario, consider reading this from stdin or an environment variable
    /// to avoid leaking it in shell history.
    #[arg(short = 'P', long)]
    password: String,
}

fn uuid_to_guid(uuid: &Uuid) -> windows_sys::core::GUID {
    let (data1, data2, data3, data4) = uuid.as_fields();
    windows_sys::core::GUID {
        data1,
        data2,
        data3,
        data4: *data4,
    }
}

fn main() -> ExitCode {
    // Initialize the logger.
    // We default to 'Debug' level so the user sees operation status and parsing warnings.
    let mut builder = env_logger::Builder::from_default_env();
    builder.filter_level(LevelFilter::Trace);
    builder.init();

    info!("Initializing ETW Relay...");

    // Parse arguments. If parsing fails, Clap prints the error and exits automatically.
    let args = Cli::parse();

    if let Err(e) = run(args) {
        // Log the error cleanly and return a non-zero exit code.
        error!("Application failed: {:#}", e);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

/// Core application logic.
///
/// This isolates the "doing" part of the application from the setup/parsing.
fn run(args: Cli) -> anyhow::Result<()> {
    // Determine which identity we are using.
    // The ArgGroup guarantees at least one of these is Some.
    if let Some(guid) = args.etw_guid {
        info!("Targeting ETW Provider GUID: {}", guid);
        let schema = fetch_manifest_for_provider(guid)?;
        trace!("Schema: {:#?}", schema);

        // Generate the Elastic index mapping
        let mapping = elastic::index::generate_index_mapping(&schema);
        info!("Generated Elastic mapping for provider {}.", guid);

        // Create the index in Elasticsearch
        // We use the provider GUID as the index name for uniqueness and clarity
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;
        let index_name = format!("etw-{}", guid).to_lowercase();
        elastic::client::create_index(
            &client,
            &args.url,
            &args.username,
            &args.password,
            &index_name,
            &mapping,
        )?;

        let session_name = "IrontraceSession";
        let provider_guid_sys = uuid_to_guid(&guid);

        // Stop previous session if it exists (restart)
        stop_trace_session(session_name);

        // Start session
        start_trace_session(session_name, &provider_guid_sys)?;

        let (tx, rx) = mpsc::channel();
        let session_name_thread = session_name.to_string();
        let schema_thread = schema.clone();

        // Spawn thread to process events
        thread::spawn(move || {
            if let Err(e) = process_events(&session_name_thread, schema_thread, tx) {
                error!("Event processing failed: {}", e);
            }
        });

        // Handle CTRL+C for graceful shutdown
        let session_name_ctrlc = session_name.to_string();
        ctrlc::set_handler(move || {
            info!("Received shutdown signal. Stopping ETW session...");
            stop_trace_session(&session_name_ctrlc);
            std::process::exit(0);
        })?;

        info!("Starting event listener loop. Press Ctrl+C to stop.");

        while let Ok(event) = rx.recv() {
            if let Err(e) = elastic::client::index_event(
                &client,
                &args.url,
                &args.username,
                &args.password,
                &index_name,
                &event,
            ) {
                error!("Failed to index event: {}", e);
            }
        }
    } else if let Some(_name) = &args.provider_name {
        // TODO: If GUID is missing resolve name string to a GUID.
        todo!("Provider name not implemented yet")
    }

    Ok(())
}
