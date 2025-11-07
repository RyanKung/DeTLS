//! DeTLS CLI application.
//!
//! This binary provides a command-line interface for managing Ed25519 keys and
//! certificates for mTLS authentication.

use clap::{Parser, Subcommand};
use detls::cert::loader::{load_certificate_from_pem, load_certificates_from_pem};
use detls::cert::x509_signing::{create_self_signed_ca, sign_certificate};
use detls::crypto::ed25519::{generate_ed25519_keypair, import_ed25519_from_bytes};
use detls::error::Result;
use detls::net::client::{mtls_request, HttpMethod};
use detls::net::config::build_mtls_config_from_der;
use detls::storage::keystore::{
    create_keystore, delete_key, export_key, get_key, import_key, list_keys,
};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "detls")]
#[command(about = "DeTLS: Decentralized TLS with Ed25519 keys", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Key management operations
    #[command(subcommand)]
    Key(KeyCommands),

    /// Certificate generation operations
    #[command(subcommand)]
    Cert(CertCommands),

    /// Network operations (mTLS client)
    Curl {
        /// URL to request
        #[arg(long)]
        url: String,

        /// Certificate file
        #[arg(long)]
        cert: String,

        /// Key alias
        #[arg(long)]
        key_alias: String,

        /// CA certificate file
        #[arg(long)]
        ca_cert: String,

        /// Keystore path (default: current directory)
        #[arg(long)]
        path: Option<PathBuf>,

        /// HTTP method
        #[arg(long, default_value = "GET")]
        method: String,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Generate a new Ed25519 keypair
    Generate {
        /// Alias name for the key
        #[arg(long)]
        alias: String,

        /// Keystore path (default: current directory)
        #[arg(long)]
        path: Option<PathBuf>,
    },

    /// Import an existing Ed25519 key
    Import {
        /// Alias name for the key
        #[arg(long)]
        alias: String,

        /// Input key file (32 bytes raw)
        #[arg(long)]
        file: PathBuf,

        /// Keystore path (default: current directory)
        #[arg(long)]
        path: Option<PathBuf>,
    },

    /// Export a private key
    Export {
        /// Alias of the key to export
        #[arg(long)]
        alias: String,

        /// Output format: hex, pem, or der
        #[arg(long, default_value = "hex")]
        format: String,

        /// Optional output file (if not specified, prints to stdout)
        #[arg(long)]
        output: Option<PathBuf>,

        /// Keystore path (default: current directory)
        #[arg(long)]
        path: Option<PathBuf>,
    },

    /// List all keys
    List {
        /// Keystore path (default: current directory)
        #[arg(long)]
        path: Option<PathBuf>,
    },

    /// Delete a key
    Delete {
        /// Key alias
        #[arg(long)]
        alias: String,

        /// Keystore path (default: current directory)
        #[arg(long)]
        path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
#[allow(clippy::enum_variant_names)]
enum CertCommands {
    /// Create a Root CA certificate
    CreateRoot {
        /// Key alias for the Root CA
        #[arg(long)]
        key_alias: String,

        /// Certificate subject (e.g., "CN=My Root CA,O=My Org")
        #[arg(long)]
        subject: String,

        /// Output certificate file
        #[arg(long)]
        output: PathBuf,

        /// Validity in days
        #[arg(long, default_value = "3650")]
        validity_days: u32,

        /// Keystore path (default: current directory)
        #[arg(long)]
        path: Option<PathBuf>,
    },

    /// Create an Intermediate CA certificate
    CreateIntermediate {
        /// Root CA key alias
        #[arg(long)]
        root_key: String,

        /// Root CA certificate file
        #[arg(long)]
        root_cert: PathBuf,

        /// Intermediate CA key alias
        #[arg(long)]
        key_alias: String,

        /// Certificate subject
        #[arg(long)]
        subject: String,

        /// Output certificate file
        #[arg(long)]
        output: PathBuf,

        /// Validity in days
        #[arg(long, default_value = "1825")]
        validity_days: u32,

        /// Keystore path (default: current directory)
        #[arg(long)]
        path: Option<PathBuf>,
    },

    /// Create an end-entity certificate
    CreateEntity {
        /// Intermediate CA key alias
        #[arg(long)]
        inter_key: String,

        /// Intermediate CA certificate file
        #[arg(long)]
        inter_cert: PathBuf,

        /// Entity key alias
        #[arg(long)]
        key_alias: String,

        /// Certificate subject
        #[arg(long)]
        subject: String,

        /// Output certificate file
        #[arg(long)]
        output: PathBuf,

        /// Validity in days
        #[arg(long, default_value = "365")]
        validity_days: u32,

        /// Keystore path (default: current directory)
        #[arg(long)]
        path: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Key(key_cmd) => handle_key_command(key_cmd),
        Commands::Cert(cert_cmd) => handle_cert_command(cert_cmd),
        Commands::Curl {
            url,
            cert,
            key_alias,
            ca_cert,
            path,
            method,
        } => handle_curl_command(&url, &cert, &key_alias, &ca_cert, path.as_deref(), &method).await,
    }
}

fn handle_key_command(cmd: KeyCommands) -> Result<()> {
    match cmd {
        KeyCommands::Generate { alias, path } => {
            let keystore_path = path.unwrap_or_else(|| PathBuf::from("."));
            let mut keystore = create_keystore(&keystore_path)?;

            // Generate keypair
            let keypair = generate_ed25519_keypair()?;

            // Prompt for password
            let password = rpassword::prompt_password("Enter password to encrypt key: ")?;

            // Import into keystore
            import_key(
                &mut keystore,
                alias.clone(),
                &keypair.secret_bytes(),
                &password,
            )?;

            println!("Generated and stored key with alias: {}", alias);
            println!("Public key: {}", hex::encode(keypair.public_bytes()));

            Ok(())
        }

        KeyCommands::Import { alias, file, path } => {
            let keystore_path = path.unwrap_or_else(|| PathBuf::from("."));
            let mut keystore = create_keystore(&keystore_path)?;

            // Read key file
            let key_bytes = fs::read(&file)?;

            // Validate and import
            let keypair = import_ed25519_from_bytes(&key_bytes)?;

            // Prompt for password
            let password = rpassword::prompt_password("Enter password to encrypt key: ")?;

            // Import into keystore
            import_key(
                &mut keystore,
                alias.clone(),
                &keypair.secret_bytes(),
                &password,
            )?;

            println!("Imported key with alias: {}", alias);
            println!("Public key: {}", hex::encode(keypair.public_bytes()));

            Ok(())
        }

        KeyCommands::Export {
            alias,
            format,
            output,
            path,
        } => {
            let keystore_path = path.unwrap_or_else(|| PathBuf::from("."));
            let keystore = create_keystore(&keystore_path)?;

            let password = rpassword::prompt_password("Enter password to decrypt key: ")?;
            let key_bytes = export_key(&keystore, &alias, &password)?;

            let formatted_output = match format.to_lowercase().as_str() {
                "hex" => hex::encode(&key_bytes),
                "pem" => {
                    // Ed25519 PKCS#8 format
                    let mut pkcs8_der = vec![
                        0x30, 0x2e, // SEQUENCE (46 bytes)
                        0x02, 0x01, 0x00, // INTEGER 0 (version)
                        0x30, 0x05, // SEQUENCE (algorithm identifier)
                        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
                        0x04, 0x22, // OCTET STRING (34 bytes)
                        0x04, 0x20, // OCTET STRING (32 bytes) - the actual key
                    ];
                    pkcs8_der.extend_from_slice(&key_bytes);
                    pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8_der))
                }
                "der" => {
                    // PKCS#8 DER format - output raw bytes
                    if output.is_none() {
                        return Err(detls::error::DeTlsError::ParseError(
                            "DER format requires --output file (binary data)".to_string(),
                        ));
                    }
                    let mut pkcs8_der = vec![
                        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                        0x04, 0x22, 0x04, 0x20,
                    ];
                    pkcs8_der.extend_from_slice(&key_bytes);
                    // Write binary directly for DER
                    if let Some(ref output_path) = output {
                        fs::write(output_path, &pkcs8_der)?;
                        println!(
                            "Exported key '{}' in DER format to: {}",
                            alias,
                            output_path.display()
                        );
                        return Ok(());
                    }
                    String::new() // Won't reach here due to check above
                }
                _ => {
                    return Err(detls::error::DeTlsError::ParseError(format!(
                        "Unsupported format: '{}'. Use 'hex', 'pem', or 'der'",
                        format
                    )));
                }
            };

            // Write to file or stdout
            if let Some(output_path) = output {
                fs::write(&output_path, formatted_output.as_bytes())?;
                println!(
                    "Exported key '{}' in {} format to: {}",
                    alias,
                    format,
                    output_path.display()
                );
            } else {
                println!("{}", formatted_output);
            }

            Ok(())
        }

        KeyCommands::List { path } => {
            let keystore_path = path.unwrap_or_else(|| PathBuf::from("."));
            let keystore = create_keystore(&keystore_path)?;

            // List keys
            let keys = list_keys(&keystore)?;

            if keys.is_empty() {
                println!("No keys found in keystore.");
            } else {
                println!("Keys in keystore:");
                println!("{:<20} {:<64} Created", "Alias", "Public Key");
                println!("{}", "-".repeat(95));

                for key_info in keys {
                    let created = chrono::DateTime::from_timestamp(key_info.created_at as i64, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_else(|| "Unknown".to_string());

                    println!(
                        "{:<20} {:<64} {}",
                        key_info.alias, key_info.public_key_hex, created
                    );
                }
            }

            Ok(())
        }

        KeyCommands::Delete { alias, path } => {
            let keystore_path = path.unwrap_or_else(|| PathBuf::from("."));
            let mut keystore = create_keystore(&keystore_path)?;

            // Delete key
            delete_key(&mut keystore, &alias)?;

            println!("Deleted key: {}", alias);

            Ok(())
        }
    }
}

fn handle_cert_command(cmd: CertCommands) -> Result<()> {
    match cmd {
        CertCommands::CreateRoot {
            key_alias,
            subject,
            output,
            validity_days,
            path,
        } => {
            let keystore_path = path.unwrap_or_else(|| PathBuf::from("."));
            let keystore = create_keystore(&keystore_path)?;

            let password = rpassword::prompt_password("Enter password to decrypt key: ")?;
            let keypair = get_key(&keystore, &key_alias, &password)?;

            let pem = create_self_signed_ca(&keypair, &subject, validity_days)?;
            fs::write(&output, &pem)?;

            println!("✓ Created Root CA certificate: {}", output.display());
            println!("  Subject: {}", subject);
            println!("  Valid for: {} days", validity_days);

            Ok(())
        }

        CertCommands::CreateIntermediate {
            root_key,
            root_cert,
            key_alias,
            subject,
            output,
            validity_days,
            path,
        } => {
            let keystore_path = path.unwrap_or_else(|| PathBuf::from("."));
            let keystore = create_keystore(&keystore_path)?;

            let password = rpassword::prompt_password("Enter password to decrypt key: ")?;

            // Get intermediate key
            let inter_keypair = get_key(&keystore, &key_alias, &password)?;

            // Load Root CA certificate
            let root_ca_pem = fs::read_to_string(&root_cert)?;

            // Get Root CA key
            let root_ca_keypair = get_key(&keystore, &root_key, &password)?;

            // Sign intermediate certificate with Root CA
            let inter_pem = sign_certificate(
                &inter_keypair,
                &subject,
                &root_ca_keypair,
                &root_ca_pem,
                true, // Is a CA
                validity_days,
            )?;

            fs::write(&output, &inter_pem)?;

            println!(
                "✓ Created Intermediate CA certificate: {}",
                output.display()
            );
            println!("  Subject: {}", subject);
            println!("  Signed by: Root CA ({})", root_cert.display());
            println!("  Valid for: {} days", validity_days);

            Ok(())
        }

        CertCommands::CreateEntity {
            inter_key,
            inter_cert,
            key_alias,
            subject,
            output,
            validity_days,
            path,
        } => {
            let keystore_path = path.unwrap_or_else(|| PathBuf::from("."));
            let keystore = create_keystore(&keystore_path)?;

            // Note: Similar to intermediate, we create a self-signed entity certificate

            // Prompt for password
            let password = rpassword::prompt_password("Enter password to decrypt key: ")?;

            // Get entity key
            let entity_keypair = get_key(&keystore, &key_alias, &password)?;

            // Load CA certificate
            let ca_pem = fs::read_to_string(&inter_cert)?;

            // Get CA key (reuse password from entity key)
            let ca_keypair = get_key(&keystore, &inter_key, &password)?;

            // Sign entity certificate with CA
            let entity_pem = sign_certificate(
                &entity_keypair,
                &subject,
                &ca_keypair,
                &ca_pem,
                false, // Not a CA
                validity_days,
            )?;

            fs::write(&output, &entity_pem)?;

            println!("✓ Created end-entity certificate: {}", output.display());
            println!("  Subject: {}", subject);
            println!("  Signed by: CA ({})", inter_cert.display());
            println!("  Valid for: {} days", validity_days);

            Ok(())
        }
    }
}

async fn handle_curl_command(
    url: &str,
    cert_file: &str,
    key_alias: &str,
    ca_cert_file: &str,
    path: Option<&std::path::Path>,
    method_str: &str,
) -> Result<()> {
    let keystore_path = path.unwrap_or_else(|| std::path::Path::new("."));
    let keystore = create_keystore(keystore_path)?;

    // Parse HTTP method
    let method = match method_str.to_uppercase().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        _ => {
            return Err(detls::error::DeTlsError::ParseError(format!(
                "Unsupported HTTP method: {}",
                method_str
            )))
        }
    };

    // Load client certificate using rustls-pemfile
    println!("Loading client certificate from: {}", cert_file);
    let cert_pem = fs::read_to_string(cert_file)?;
    let client_cert_der = load_certificate_from_pem(&cert_pem)?;

    // Load CA certificate(s)
    println!("Loading CA certificate(s) from: {}", ca_cert_file);
    let ca_pem = fs::read_to_string(ca_cert_file)?;
    let ca_certs_der = load_certificates_from_pem(&ca_pem)?;

    // Get key from keystore
    println!("Loading key: {}", key_alias);
    let password = rpassword::prompt_password("Enter password to decrypt key: ")?;
    let keypair = get_key(&keystore, key_alias, &password)?;

    // Build mTLS configuration
    println!("Building mTLS configuration...");
    let config = build_mtls_config_from_der(client_cert_der, &keypair, ca_certs_der)?;

    // Make request
    println!("\nSending {} request to: {}", method_str, url);
    let response = mtls_request(url, method, config, None).await?;

    // Display response
    println!("\n{}", "=".repeat(60));
    println!("HTTP Status: {}", response.status_code);
    println!("{}", "=".repeat(60));

    println!("\nHeaders:");
    for (key, value) in &response.headers {
        println!("  {}: {}", key, value);
    }

    println!("\nBody ({} bytes):", response.body.len());
    match String::from_utf8(response.body.clone()) {
        Ok(text) => {
            if text.len() > 1000 {
                println!("{}... (truncated)", &text[..1000]);
            } else {
                println!("{}", text);
            }
        }
        Err(_) => println!("<binary data>"),
    }

    Ok(())
}
