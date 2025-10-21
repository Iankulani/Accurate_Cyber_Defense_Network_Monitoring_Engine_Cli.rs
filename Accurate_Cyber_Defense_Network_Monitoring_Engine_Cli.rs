use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;

mod config;
mod database;
mod models;
mod monitor;
mod scanner;
mod telegram;
mod threats;

use config::Config;
use database::DatabaseManager;
use monitor::NetworkMonitor;
use scanner::PortScanner;
use telegram::TelegramBot;

#[derive(Parser)]
#[command(name = "cyber_monitor")]
#[command(about = "Advanced Cyber Security Monitoring System", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start monitoring
    Start {
        #[arg(short, long)]
        ip: Option<String>,
    },
    /// Stop monitoring
    Stop,
    /// View recent threats
    Threats {
        #[arg(short, long, default_value = "24")]
        hours: u32,
    },
    /// Ping an IP address
    Ping {
        ip: String,
    },
    /// Scan ports on an IP
    Scan {
        ip: String,
        #[arg(short, long, default_value = "1-1000")]
        ports: String,
    },
    /// Get IP location
    Location {
        ip: String,
    },
    /// Configure Telegram
    ConfigTelegram {
        token: String,
        chat_id: String,
    },
}

struct CyberSecurityMonitor {
    config: Config,
    db_manager: DatabaseManager,
    network_monitor: NetworkMonitor,
    port_scanner: PortScanner,
    telegram_bot: Option<TelegramBot>,
}

impl CyberSecurityMonitor {
    async fn new() -> Result<Self> {
        let config = Config::load().await?;
        let db_manager = DatabaseManager::new(&config.database_url).await?;
        let network_monitor = NetworkMonitor::new(config.clone(), db_manager.clone());
        let port_scanner = PortScanner::new(config.clone());
        let telegram_bot = if config.telegram_token.is_some() {
            Some(TelegramBot::new(config.clone()))
        } else {
            None
        };

        Ok(Self {
            config,
            db_manager,
            network_monitor,
            port_scanner,
            telegram_bot,
        })
    }

    async fn run_command(&mut self, cmd: Commands) -> Result<()> {
        match cmd {
            Commands::Start { ip } => {
                if let Some(ip_addr) = ip {
                    self.start_monitoring(&ip_addr).await?;
                } else {
                    self.start_monitoring("0.0.0.0").await?;
                }
            }
            Commands::Stop => {
                self.stop_monitoring().await?;
            }
            Commands::Threats { hours } => {
                self.view_threats(hours).await?;
            }
            Commands::Ping { ip } => {
                self.ping_ip(&ip).await?;
            }
            Commands::Scan { ip, ports } => {
                self.scan_ports(&ip, &ports).await?;
            }
            Commands::Location { ip } => {
                self.get_location(&ip).await?;
            }
            Commands::ConfigTelegram { token, chat_id } => {
                self.config_telegram(&token, &chat_id).await?;
            }
        }
        Ok(())
    }

    async fn start_monitoring(&mut self, ip: &str) -> Result<()> {
        println!("{}", self.get_banner());
        println!("🚀 Starting Advanced Cyber Security Monitor...");
        
        self.config.monitored_ips.insert(ip.to_string());
        self.config.save().await?;
        
        self.network_monitor.start().await?;
        
        if let Some(bot) = &self.telegram_bot {
            bot.send_message(&format!("🛡️ Started monitoring IP: `{}`", ip)).await?;
        }
        
        println!("✅ Started monitoring IP: {}", ip);
        Ok(())
    }

    async fn stop_monitoring(&self) -> Result<()> {
        self.network_monitor.stop().await;
        println!("🛑 Monitoring stopped");
        Ok(())
    }

    async fn view_threats(&self, hours: u32) -> Result<()> {
        let threats = self.db_manager.get_recent_threats(hours).await?;
        
        if threats.is_empty() {
            println!("✅ No threats detected in the last {} hours", hours);
            return Ok(());
        }

        println!("🚨 Recent Threats (Last {} hours):", hours);
        println!("{}", "-".repeat(80));

        for threat in threats.iter().take(20) {
            println!("Threat Type: {}", threat.threat_type);
            println!("Source IP: {} -> Target IP: {}", threat.source_ip, threat.target_ip);
            println!("Severity: {}", threat.severity);
            println!("Time: {}", threat.timestamp);
            println!("Description: {}", threat.description);
            println!("Packets: {}", threat.packet_count);
            if let Some(port) = threat.port {
                println!("Port: {}", port);
            }
            if let Some(protocol) = &threat.protocol {
                println!("Protocol: {}", protocol);
            }
            println!("{}", "-".repeat(80));
        }
        Ok(())
    }

    async fn ping_ip(&self, ip: &str) -> Result<()> {
        use tokio::process::Command;
        
        let output = if cfg!(target_os = "windows") {
            Command::new("ping")
                .arg("-n")
                .arg("4")
                .arg(ip)
                .output()
                .await?
        } else {
            Command::new("ping")
                .arg("-c")
                .arg("4")
                .arg(ip)
                .output()
                .await?
        };

        if output.status.success() {
            println!("✅ Ping successful to {}", ip);
            println!("{}", String::from_utf8_lossy(&output.stdout));
        } else {
            println!("❌ Ping failed to {}", ip);
            println!("{}", String::from_utf8_lossy(&output.stderr));
        }
        Ok(())
    }

    async fn scan_ports(&self, ip: &str, ports: &str) -> Result<()> {
        println!("🔍 Scanning {} on ports {}...", ip, ports);
        let results = self.port_scanner.scan(ip, ports).await?;
        
        if results.is_empty() {
            println!("❌ No open ports found or scan failed for {}", ip);
        } else {
            println!("📊 Scan results for {}:", ip);
            for result in results {
                println!("Port {}/{} - {} - {}", result.port, result.protocol, result.status, result.service);
            }
        }
        Ok(())
    }

    async fn get_location(&self, ip: &str) -> Result<()> {
        let client = reqwest::Client::new();
        let response: serde_json::Value = client
            .get(&format!("http://ip-api.com/json/{}", ip))
            .send()
            .await?
            .json()
            .await?;

        if response["status"] == "success" {
            println!("🌍 Location for {}", ip);
            println!("Country: {}", response["country"].as_str().unwrap_or("Unknown"));
            println!("Region: {}", response["regionName"].as_str().unwrap_or("Unknown"));
            println!("City: {}", response["city"].as_str().unwrap_or("Unknown"));
            println!("ISP: {}", response["isp"].as_str().unwrap_or("Unknown"));
            println!("AS: {}", response["as"].as_str().unwrap_or("Unknown"));
            println!("Coordinates: {}, {}", 
                response["lat"].as_f64().unwrap_or(0.0), 
                response["lon"].as_f64().unwrap_or(0.0));
        } else {
            println!("❌ Could not get location for {}", ip);
        }
        Ok(())
    }

    async fn config_telegram(&mut self, token: &str, chat_id: &str) -> Result<()> {
        self.config.telegram_token = Some(token.to_string());
        self.config.telegram_chat_id = Some(chat_id.to_string());
        self.config.save().await?;
        
        self.telegram_bot = Some(TelegramBot::new(self.config.clone()));
        
        println!("✅ Telegram configuration updated");
        println!("Token: {}...", &token[..10.min(token.len())]);
        println!("Chat ID: {}", chat_id);
        Ok(())
    }

    fn get_banner(&self) -> String {
        format!(
            r#"
{}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║    ADVANCED CYBER DEFENSE NETWORK MONITORING ENGINE 🛡️        ║
║                                                                ║
║    • Port Scanning Detection                                   ║
║    • DDoS Attack Monitoring                                    ║
║    • TCP/UDP Flood Detection                                   ║
║    • Real-time Threat Analysis                                 ║
║    • Telegram Bot Integration                                  ║
║                                                                ║
║    Community: https://github.com/Accurate-Cyber-Defense        ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
                                                                  
        "#,
            "PURPLE".purple()
        )
    }

    async fn interactive_mode(&mut self) -> Result<()> {
        println!("{}", self.get_banner());
        println!("💻 Type 'help' for available commands");

        loop {
            print!("{}cyber-monitor> {}", "PURPLE".purple(), "TEXT".clear());
            use std::io::{self, Write};
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();

            if input.is_empty() {
                continue;
            }

            match input {
                "help" => self.show_help(),
                "exit" | "shutdown" => break,
                "clear" => self.clear_screen(),
                _ => {
                    // Parse the input as a command
                    if let Ok(cmd) = clap::Parser::try_parse_from(&["cyber-monitor"].into_iter().chain(input.split_whitespace())) {
                        if let Some(command) = cmd.get_matches().subcommand() {
                            // Handle command parsing would go here
                            println!("Executing: {}", input);
                        }
                    } else {
                        println!("❌ Unknown command: {}. Type 'help' for available commands.", input);
                    }
                }
            }
        }
        Ok(())
    }

    fn show_help(&self) {
        println!(
            r#"
🛡️ Cyber Security Monitor - Available Commands

📊 Monitoring Commands:
  start --ip [IP]        - Start monitoring IP address
  stop                   - Stop monitoring
  threats --hours [HRS]  - View recent security threats

🌐 Network Commands:
  ping [IP]              - Ping IP address
  location [IP]          - Get IP geographical location
  scan [IP]              - Scan common ports
  scan [IP] --ports [RANGE] - Scan specific port range

🔧 Configuration Commands:
  config-telegram [TOKEN] [CHAT_ID] - Configure Telegram

💜 Purple Security Theme Active
        "#
        );
    }

    fn clear_screen(&self) {
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
        println!("{}", self.get_banner());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    let mut monitor = CyberSecurityMonitor::new().await?;

    if let Some(command) = cli.command {
        monitor.run_command(command).await?;
    } else {
        monitor.interactive_mode().await?;
    }

    println!("👋 Goodbye!");
    Ok(())
}