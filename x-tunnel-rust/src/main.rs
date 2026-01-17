use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_tungstenite::{connect_async, WebSocketStream};
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use clap::Parser;
use uuid::Uuid;
use reqwest::Client;
use base64::{Engine as _, engine::general_purpose};
use log::{info, error, warn};
use thiserror::Error;

#[derive(Parser)]
#[command(name = "x-tunnel-client")]
#[command(about = "SOCKS5 proxy client with WebSocket and ECH support")]
struct Args {
    #[arg(short, long)]
    config: Option<String>,

    #[arg(short = 'l', long)]
    listen: Option<String>,

    #[arg(short = 'f', long)]
    forward: Option<String>,

    #[arg(short, long)]
    ip: Option<String>,

    #[arg(short, long, default_value = "443")]
    block: String,

    #[arg(short, long)]
    insecure: bool,

    #[arg(short, long)]
    token: Option<String>,

    #[arg(short, long, default_value = "https://doh.pub/dns-query")]
    dns: String,

    #[arg(short, long, default_value = "cloudflare-ech.com")]
    ech: String,

    #[arg(short, long)]
    fallback: bool,

    #[arg(short = 'n', long, default_value = "3")]
    connection_num: usize,

    #[arg(short, long)]
    ips: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct FileConfig {
    listen: Option<String>,
    forward: Option<String>,
    ip: Option<String>,
    udp_block_ports: Option<String>,
    token: Option<String>,
    connection_num: Option<usize>,
    insecure: Option<bool>,
    ips: Option<String>,
    dns_server: Option<String>,
    ech_domain: Option<String>,
    fallback: Option<bool>,
    dial_timeout: Option<Duration>,
    ws_handshake_timeout: Option<Duration>,
    ws_write_timeout: Option<Duration>,
    ws_read_timeout: Option<Duration>,
    ping_interval: Option<Duration>,
    reconnect_delay: Option<Duration>,
}

#[derive(Debug, Clone)]
struct GlobalConfig {
    dial_timeout: Duration,
    ws_handshake_timeout: Duration,
    ws_write_timeout: Duration,
    ws_read_timeout: Duration,
    ping_interval: Duration,
    reconnect_delay: Duration,
    read_buf_32k: usize,
    read_buf_64k: usize,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            dial_timeout: Duration::from_secs(3),
            ws_handshake_timeout: Duration::from_secs(5),
            ws_write_timeout: Duration::from_secs(5),
            ws_read_timeout: Duration::from_secs(10),
            ping_interval: Duration::from_secs(3),
            reconnect_delay: Duration::from_secs(1),
            read_buf_32k: 32 * 1024,
            read_buf_64k: 64 * 1024,
        }
    }
}

#[derive(Debug, Error)]
enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("ECH not supported in Rust")]
    EchNotSupported,
}

type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, Clone, Copy)]
enum MessageType {
    TcpConnect = 1,
    TcpData,
    TcpClose,
    UdpConnect,
    UdpData,
    UdpClose,
    ConnStatus,
    Uplink,
    SelectDownlink,
}

#[derive(Debug, Clone, Copy)]
enum ConnStatus {
    Ok = 0,
    Err = 1,
}

const HEADER_LEN: usize = 8;

fn encode_message(msg_type: MessageType, conn_id: &str, meta: &[u8], payload: &[u8]) -> Vec<u8> {
    let conn_id = if conn_id.len() > 255 { &conn_id[..255] } else { conn_id };
    let mut buf = vec![0u8; HEADER_LEN + conn_id.len() + meta.len() + payload.len()];
    buf[0] = msg_type as u8;
    buf[1] = conn_id.len() as u8;
    let meta_len = meta.len() as u16;
    let payload_len = payload.len() as u32;
    buf[2..4].copy_from_slice(&meta_len.to_be_bytes());
    buf[4..8].copy_from_slice(&payload_len.to_be_bytes());
    let mut off = HEADER_LEN;
    buf[off..off + conn_id.len()].copy_from_slice(conn_id.as_bytes());
    off += conn_id.len();
    buf[off..off + meta.len()].copy_from_slice(meta);
    off += meta.len();
    buf[off..off + payload.len()].copy_from_slice(payload);
    buf
}

fn decode_message(data: &[u8]) -> Result<(MessageType, String, Vec<u8>, Vec<u8>)> {
    if data.len() < HEADER_LEN {
        return Err(AppError::Parse("frame too short".to_string()));
    }
    let msg_type = match data[0] {
        1 => MessageType::TcpConnect,
        2 => MessageType::TcpData,
        3 => MessageType::TcpClose,
        4 => MessageType::UdpConnect,
        5 => MessageType::UdpData,
        6 => MessageType::UdpClose,
        7 => MessageType::ConnStatus,
        8 => MessageType::Uplink,
        9 => MessageType::SelectDownlink,
        _ => return Err(AppError::Parse("invalid message type".to_string())),
    };
    let id_len = data[1] as usize;
    let meta_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let payload_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let total = HEADER_LEN + id_len + meta_len + payload_len;
    if total > data.len() {
        return Err(AppError::Parse("invalid length".to_string()));
    }
    let mut off = HEADER_LEN;
    let conn_id = String::from_utf8_lossy(&data[off..off + id_len]).to_string();
    off += id_len;
    let meta = data[off..off + meta_len].to_vec();
    off += meta_len;
    let payload = data[off..off + payload_len].to_vec();
    Ok((msg_type, conn_id, meta, payload))
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let mut cfg = GlobalConfig::default();

    // Load config from file if specified
    if let Some(config_file) = &args.config {
        let data = std::fs::read(config_file)?;
        let file_config: FileConfig = serde_yaml::from_slice(&data)?;
        // Apply file config to args and cfg
        // Similar to Go code
    }

    let listen_addr = args.listen.as_deref().unwrap_or_else(|| {
        eprintln!("Listen address required");
        std::process::exit(1);
    });

    let forward_addr = args.forward.as_deref().unwrap_or_else(|| {
        eprintln!("Forward address required");
        std::process::exit(1);
    });

    let ip_strategy = parse_ip_strategy(args.ips.as_deref().unwrap_or(""));
    let target_ips: Vec<String> = args.ip.as_ref().map(|s| s.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default();
    let udp_block_ports: HashMap<u16, ()> = args.block.split(',').filter_map(|s| s.trim().parse().ok()).map(|p| (p, ())).collect();

    let client_id = Uuid::new_v4().to_string();
    info!("Client ID: {}", client_id);

    // ECH preparation - placeholder since rustls doesn't support ECH
    if !args.fallback {
        warn!("ECH not supported in this Rust implementation, falling back to standard TLS");
    }

    let ech_pool = Arc::new(EchPool::new(forward_addr.to_string(), args.connection_num, target_ips, client_id));
    ech_pool.start().await;

    run_socks5_listener(listen_addr, ech_pool).await?;

    Ok(())
}

fn parse_ip_strategy(s: &str) -> u8 {
    match s {
        "4" => 1,
        "6" => 2,
        "4,6" => 3,
        "6,4" => 4,
        _ => 0,
    }
}

async fn run_socks5_listener(addr: &str, pool: Arc<EchPool>) -> Result<()> {
    let addr = addr.strip_prefix("socks5://").unwrap_or(addr);
    let listener = TcpListener::bind(addr).await?;
    info!("SOCKS5 proxy listening on: {}", addr);

    loop {
        let (socket, _) = listener.accept().await?;
        let pool = pool.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks5(socket, &pool).await {
                error!("SOCKS5 handle error: {:?}", e);
            }
        });
    }
}

async fn handle_socks5(mut socket: TcpStream, pool: &EchPool) -> Result<()> {
    // Implement SOCKS5 protocol
    // This is simplified, need full implementation
    // For brevity, assume connect command

    // Read version and methods
    let mut buf = [0u8; 2];
    socket.read_exact(&mut buf).await?;
    if buf[0] != 0x05 {
        return Ok(());
    }
    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    socket.read_exact(&mut methods).await?;

    // No auth
    socket.write_all(&[0x05, 0x00]).await?;

    // Read request
    let mut head = [0u8; 4];
    socket.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x01 {
        return Ok(());
    }

    let target = match head[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            socket.read_exact(&mut ip).await?;
            format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], 0)
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            socket.read_exact(&mut domain).await?;
            let domain = String::from_utf8_lossy(&domain);
            let mut port = [0u8; 2];
            socket.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            format!("{}:{}", domain, port)
        }
        0x04 => {
            let mut ip = [0u8; 16];
            socket.read_exact(&mut ip).await?;
            let ip = std::net::Ipv6Addr::from(ip);
            let mut port = [0u8; 2];
            socket.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            format!("[{}]:{}", ip, port)
        }
        _ => return Ok(()),
    };

    // Send success response
    socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    let conn_id = Uuid::new_v4().to_string();
    pool.register_and_broadcast_tcp(conn_id.clone(), &target, None, socket).await;

    // Handle data forwarding
    // This needs more implementation

    Ok(())
}

struct EchPool {
    ws_server_addr: String,
    connection_num: usize,
    target_ips: Vec<String>,
    client_id: String,
    ws_conns: Mutex<Vec<Option<WebSocketStream<tokio::net::TcpStream>>>>,
    write_queues: Vec<tokio::sync::mpsc::Sender<WriteJob>>,
    conns: Mutex<HashMap<String, ClientConnState>>,
    global_queue_bytes: std::sync::atomic::AtomicI64,
    global_queue_limit: i64,
}

struct WriteJob {
    msg_type: u8,
    data: Vec<u8>,
    size: i64,
}

struct ClientConnState {
    tcp_conn: Option<TcpStream>,
    udp_assoc: Option<Arc<UdpAssociation>>,
    uplink: Option<usize>,
    downlink: Option<usize>,
    start: std::time::Instant,
    target: String,
    req_type: String,
    client_addr: Option<SocketAddr>,
    closed: bool,
}

impl EchPool {
    fn new(addr: String, n: usize, ips: Vec<String>, client_id: String) -> Self {
        let total = if ips.is_empty() { n } else { ips.len() * n };
        let mut write_queues = Vec::with_capacity(total);
        for _ in 0..total {
            let (tx, _) = tokio::sync::mpsc::channel(4096);
            write_queues.push(tx);
        }
        Self {
            ws_server_addr: addr,
            connection_num: n,
            target_ips: ips,
            client_id,
            ws_conns: Mutex::new(vec![None; total]),
            write_queues,
            conns: Mutex::new(HashMap::new()),
            global_queue_bytes: std::sync::atomic::AtomicI64::new(0),
            global_queue_limit: (64 * 1024 * 512) as i64,
        }
    }

    async fn start(&self) {
        for i in 0..self.write_queues.len() {
            let ip = if self.target_ips.is_empty() {
                None
            } else {
                Some(self.target_ips[i / self.connection_num].clone())
            };
            let pool = // need Arc<Self>
            // This needs refactoring to Arc
        }
    }

    async fn register_and_broadcast_tcp(&self, conn_id: String, target: &str, first: Option<&[u8]>, tcp_conn: TcpStream) {
        let mut conns = self.conns.lock().await;
        let state = ClientConnState {
            tcp_conn: Some(tcp_conn),
            udp_assoc: None,
            uplink: None,
            downlink: None,
            start: std::time::Instant::now(),
            target: target.to_string(),
            req_type: "SOCKS5".to_string(),
            client_addr: None,
            closed: false,
        };
        conns.insert(conn_id.clone(), state);

        let meta = vec![0u8; 1 + target.len()]; // ip_strategy + target
        // copy
        let msg = encode_message(MessageType::TcpConnect, &conn_id, &meta, first.unwrap_or(&[]));
        self.broadcast_write(Message::Binary(msg)).await;
    }

    async fn broadcast_write(&self, msg: Message) {
        // Implement broadcasting
    }
}

async fn dial_websocket(addr: &str, client_id: &str, token: Option<&str>) -> Result<WebSocketStream<tokio::net::TcpStream>> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let mut request = addr.into_client_request()?;
    {
        let headers = request.headers_mut();
        let mut url = reqwest::Url::parse(addr)?;
        let mut query = url.query_pairs_mut();
        query.append_pair("client_id", client_id);
        drop(query);
        *request.uri_mut() = url.as_str().parse()?;
        if let Some(token) = token {
            headers.insert("Sec-WebSocket-Protocol", token.parse()?);
        }
    }

    let (ws, _) = connect_async(request).await?;
    Ok(ws)
}

async fn fetch_ech_keys(doh_url: &str, domain: &str) -> Result<Vec<u8>> {
    let client = Client::new();
    let mut query = build_dns_query(domain, 65); // HTTPS type
    let dns_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&query);
    let url = format!("{}?dns={}", doh_url, dns_b64);
    let resp = client.get(&url).header("Accept", "application/dns-message").send().await?;
    let body = resp.bytes().await?;
    parse_dns_response(&body)
}

fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut query = vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);
    query.extend_from_slice(&(qtype as u16).to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

fn parse_dns_response(response: &[u8]) -> Result<String> {
    if response.len() < 12 {
        return Err(AppError::Parse("response too short".to_string()));
    }
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    if ancount == 0 {
        return Err(AppError::Parse("no answer".to_string()));
    }
    let mut offset = 12;
    // Skip question
    while offset < response.len() && response[offset] != 0 {
        offset += response[offset] as usize + 1;
    }
    offset += 5;
    for _ in 0..ancount {
        if offset >= response.len() {
            break;
        }
        if response[offset] & 0xC0 == 0xC0 {
            offset += 2;
        } else {
            while offset < response.len() && response[offset] != 0 {
                offset += response[offset] as usize + 1;
            }
            offset += 1;
        }
        if offset + 10 > response.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        offset += 8;
        let data_len = u16::from_be_bytes([response[offset], response[offset + 1]]);
        offset += 2;
        if offset + data_len as usize > response.len() {
            break;
        }
        let data = &response[offset..offset + data_len as usize];
        offset += data_len as usize;
        if rr_type == 65 {
            if let Some(ech) = parse_https_record(data) {
                return Ok(ech);
            }
        }
    }
    Err(AppError::Parse("no HTTPS record".to_string()))
}

fn parse_https_record(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let mut offset = 2;
    if offset < data.len() && data[offset] == 0 {
        offset += 1;
    } else {
        while offset < data.len() && data[offset] != 0 {
            offset += data[offset] as usize + 1;
        }
        offset += 1;
    }
    while offset + 4 <= data.len() {
        let key = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
        if offset + length as usize > data.len() {
            break;
        }
        let value = &data[offset..offset + length as usize];
        offset += length as usize;
        if key == 5 {
            return Some(general_purpose::STANDARD.encode(value));
        }
    }
    None
}