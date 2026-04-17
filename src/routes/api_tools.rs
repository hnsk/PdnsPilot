use axum::{
    extract::State,
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::repositories::{pdns_server_repo, zone_assignment_repo};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/tools/axfr", post(axfr_endpoint))
        .route("/api/tools/lookup", post(lookup_endpoint))
}

#[derive(Deserialize)]
struct AXFRRequest {
    zone_id: String,
    #[serde(default)]
    server_ids: Vec<i64>,
    #[serde(default)]
    custom_hosts: Vec<String>,
}

#[derive(Deserialize)]
struct LookupRequest {
    name: String,
    rtype: String,
    #[serde(default)]
    server_ids: Vec<i64>,
    #[serde(default)]
    custom_hosts: Vec<String>,
}

fn host_from_url(url: &str) -> Option<String> {
    // Extract hostname from http(s)://host:port/...
    let without_scheme = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = without_scheme.split('/').next()?;
    let host = host.split(':').next()?;
    Some(host.to_string())
}

// ─── Simple DNS wire-format helpers ──────────────────────────────────────────

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let name = name.trim_end_matches('.');
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0u8);
    out
}

fn build_query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    // Header
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    pkt.extend_from_slice(&encode_name(name));
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN class
    pkt
}

fn parse_name(pkt: &[u8], mut pos: usize) -> (String, usize) {
    let mut parts = Vec::new();
    let mut jumped = false;
    let mut end_pos = pos;
    loop {
        if pos >= pkt.len() { break; }
        let len = pkt[pos] as usize;
        if len == 0 {
            if !jumped { end_pos = pos + 1; }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= pkt.len() { break; }
            let ptr = (((len & 0x3F) as usize) << 8) | pkt[pos + 1] as usize;
            if !jumped { end_pos = pos + 2; }
            jumped = true;
            pos = ptr;
        } else {
            pos += 1;
            if pos + len > pkt.len() { break; }
            parts.push(String::from_utf8_lossy(&pkt[pos..pos + len]).to_string());
            pos += len;
        }
    }
    if !jumped { end_pos = pos + 1; }
    (parts.join("."), end_pos)
}

fn read_u16(pkt: &[u8], pos: usize) -> u16 {
    if pos + 1 >= pkt.len() { return 0; }
    u16::from_be_bytes([pkt[pos], pkt[pos + 1]])
}
fn read_u32(pkt: &[u8], pos: usize) -> u32 {
    if pos + 3 >= pkt.len() { return 0; }
    u32::from_be_bytes([pkt[pos], pkt[pos + 1], pkt[pos + 2], pkt[pos + 3]])
}

fn rtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        _ => format!("TYPE{t}"),
    }
}

fn rtype_num(name: &str) -> u16 {
    match name.to_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "ANY" => 255,
        "AXFR" => 252,
        _ => 1,
    }
}

fn parse_rdata(pkt: &[u8], pos: usize, len: usize, rtype: u16) -> String {
    match rtype {
        1 => { // A
            if len >= 4 {
                format!("{}.{}.{}.{}", pkt[pos], pkt[pos+1], pkt[pos+2], pkt[pos+3])
            } else { "<invalid>".into() }
        }
        28 => { // AAAA
            if len >= 16 {
                let mut parts = Vec::new();
                for i in 0..8 {
                    parts.push(format!("{:x}", read_u16(pkt, pos + i * 2)));
                }
                parts.join(":")
            } else { "<invalid>".into() }
        }
        2 | 5 | 12 => { // NS, CNAME, PTR
            let (name, _) = parse_name(pkt, pos);
            name + "."
        }
        15 => { // MX
            let pref = read_u16(pkt, pos);
            let (name, _) = parse_name(pkt, pos + 2);
            format!("{pref} {name}.")
        }
        16 => { // TXT
            let mut result = String::new();
            let mut i = pos;
            while i < pos + len {
                let slen = pkt[i] as usize;
                i += 1;
                if i + slen <= pkt.len() {
                    result.push('"');
                    result.push_str(&String::from_utf8_lossy(&pkt[i..i+slen]));
                    result.push('"');
                }
                i += slen;
            }
            result
        }
        6 => { // SOA
            let (mname, p2) = parse_name(pkt, pos);
            let (rname, p3) = parse_name(pkt, p2);
            let serial = read_u32(pkt, p3);
            let refresh = read_u32(pkt, p3 + 4);
            let retry = read_u32(pkt, p3 + 8);
            let expire = read_u32(pkt, p3 + 12);
            let minimum = read_u32(pkt, p3 + 16);
            format!("{mname}. {rname}. {serial} {refresh} {retry} {expire} {minimum}")
        }
        _ => hex::encode(&pkt[pos..pos+len.min(pkt.len()-pos)])
    }
}

async fn do_lookup(name: &str, rtype_str: &str, host: &str) -> anyhow::Result<Vec<Value>> {
    let qtype = rtype_num(rtype_str);
    let pkt = build_query(name, qtype, 1);
    let addr: SocketAddr = format!("{host}:53").parse()?;

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&pkt, addr).await?;

    let mut buf = vec![0u8; 4096];
    let timeout = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await
        .map_err(|_| anyhow::anyhow!("Timeout"))??;
    let (n, _) = timeout;
    let resp = &buf[..n];

    if resp.len() < 12 { anyhow::bail!("Short response"); }
    let ancount = read_u16(resp, 6) as usize;
    let qdcount = read_u16(resp, 4) as usize;

    // Skip header (12) + questions
    let mut pos = 12;
    for _ in 0..qdcount {
        let (_, new_pos) = parse_name(resp, pos);
        pos = new_pos + 4; // skip qtype + qclass
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        if pos >= resp.len() { break; }
        let (rname, p2) = parse_name(resp, pos);
        let rt = read_u16(resp, p2);
        let _class = read_u16(resp, p2 + 2);
        let ttl = read_u32(resp, p2 + 4);
        let rdlen = read_u16(resp, p2 + 8) as usize;
        let rdpos = p2 + 10;
        let rdata = parse_rdata(resp, rdpos, rdlen, rt);
        answers.push(json!({
            "name": rname + ".",
            "ttl": ttl,
            "rtype": rtype_name(rt),
            "rdata": rdata,
        }));
        pos = rdpos + rdlen;
    }

    Ok(answers)
}

async fn do_axfr(zone_id: &str, host: &str) -> anyhow::Result<(String, Vec<Value>)> {
    let pkt = build_query(zone_id, 252, 1); // AXFR = 252
    // AXFR over TCP
    let addr: SocketAddr = format!("{host}:53").parse()?;
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(addr),
    ).await.map_err(|_| anyhow::anyhow!("Connection timeout"))??;

    // TCP DNS: 2-byte length prefix
    let len_prefix = (pkt.len() as u16).to_be_bytes();
    stream.write_all(&len_prefix).await?;
    stream.write_all(&pkt).await?;

    let mut records = Vec::new();
    let mut text_lines = vec![
        format!("; <<>> DiG <<>> {zone_id} AXFR @{host}"),
        ";; global options: +cmd".to_string(),
    ];

    let mut soa_count = 0;
    loop {
        let mut lenbuf = [0u8; 2];
        if tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut lenbuf)).await.is_err() {
            break;
        }
        let msg_len = u16::from_be_bytes(lenbuf) as usize;
        if msg_len == 0 { break; }
        let mut buf = vec![0u8; msg_len];
        if stream.read_exact(&mut buf).await.is_err() { break; }

        if buf.len() < 12 { break; }
        let ancount = read_u16(&buf, 6) as usize;
        let qdcount = read_u16(&buf, 4) as usize;
        let mut pos = 12;
        for _ in 0..qdcount {
            let (_, p2) = parse_name(&buf, pos);
            pos = p2 + 4;
        }
        let mut done = false;
        for _ in 0..ancount {
            if pos >= buf.len() { break; }
            let (rname, p2) = parse_name(&buf, pos);
            let rt = read_u16(&buf, p2);
            let _class = read_u16(&buf, p2 + 2);
            let ttl = read_u32(&buf, p2 + 4);
            let rdlen = read_u16(&buf, p2 + 8) as usize;
            let rdpos = p2 + 10;
            let rdata = parse_rdata(&buf, rdpos, rdlen, rt);
            let rtype_str = rtype_name(rt);
            let fqdn = format!("{rname}.");

            if rtype_str == "SOA" {
                soa_count += 1;
                if soa_count == 2 { done = true; break; }
            }

            let line = format!("{fqdn}\t{ttl}\tIN\t{rtype_str}\t{rdata}");
            text_lines.push(line);
            records.push(json!({
                "name": fqdn,
                "ttl": ttl,
                "rtype": rtype_str,
                "rdata": rdata,
            }));
            pos = rdpos + rdlen;
        }
        if done { break; }
    }

    Ok((text_lines.join("\n"), records))
}

async fn run_axfr(zone_id: &str, server_id: Option<i64>, server_name: &str, host: &str) -> Value {
    match do_axfr(zone_id, host).await {
        Ok((text, records)) => json!({
            "server_id": server_id,
            "server_name": server_name,
            "text": text,
            "records": records,
            "error": null,
        }),
        Err(e) => json!({
            "server_id": server_id,
            "server_name": server_name,
            "text": null,
            "records": [],
            "error": e.to_string(),
        }),
    }
}

async fn run_lookup(name: &str, rtype: &str, server_id: Option<i64>, server_name: &str, host: &str) -> Value {
    match do_lookup(name, rtype, host).await {
        Ok(answers) => json!({
            "server_id": server_id,
            "server_name": server_name,
            "answers": answers,
            "error": null,
        }),
        Err(e) => json!({
            "server_id": server_id,
            "server_name": server_name,
            "answers": [],
            "error": e.to_string(),
        }),
    }
}

async fn axfr_endpoint(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(body): Json<AXFRRequest>,
) -> Result<Json<Value>, AppError> {
    let all_servers: std::collections::HashMap<i64, pdns_server_repo::PdnsServer> =
        pdns_server_repo::list_servers(&state.db)
            .await
            .map_err(AppError::Internal)?
            .into_iter()
            .filter(|s| s.is_active)
            .map(|s| (s.id, s))
            .collect();

    let servers: Vec<&pdns_server_repo::PdnsServer> = body
        .server_ids
        .iter()
        .filter_map(|id| all_servers.get(id))
        .collect();

    let custom_hosts: Vec<String> = body
        .custom_hosts
        .iter()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .collect();

    if servers.is_empty() && custom_hosts.is_empty() {
        return Err(AppError::BadRequest("No valid active servers selected".into()));
    }

    if user.role != "admin" {
        let assignments = zone_assignment_repo::get_user_zone_assignments(&state.db, user.id)
            .await
            .map_err(AppError::Internal)?;
        let allowed: std::collections::HashSet<String> =
            assignments.into_iter().map(|a| a.zone_name).collect();
        if !allowed.contains(&body.zone_id) {
            return Err(AppError::Forbidden);
        }
    }

    let mut tasks: Vec<tokio::task::JoinHandle<Value>> = Vec::new();
    for srv in &servers {
        let zone_id = body.zone_id.clone();
        let sid = srv.id;
        let sname = srv.name.clone();
        let host = host_from_url(&srv.api_url).unwrap_or_else(|| srv.name.clone());
        tasks.push(tokio::spawn(async move {
            run_axfr(&zone_id, Some(sid), &sname, &host).await
        }));
    }
    for h in &custom_hosts {
        let zone_id = body.zone_id.clone();
        let host = h.clone();
        tasks.push(tokio::spawn(async move {
            run_axfr(&zone_id, None, &host, &host).await
        }));
    }

    let mut results = Vec::new();
    for t in tasks {
        results.push(t.await.unwrap_or_else(|e| json!({"error": e.to_string()})));
    }

    Ok(Json(json!({"results": results})))
}

async fn lookup_endpoint(
    State(state): State<AppState>,
    AuthUser(_user): AuthUser,
    Json(body): Json<LookupRequest>,
) -> Result<Json<Value>, AppError> {
    let all_servers: std::collections::HashMap<i64, pdns_server_repo::PdnsServer> =
        pdns_server_repo::list_servers(&state.db)
            .await
            .map_err(AppError::Internal)?
            .into_iter()
            .filter(|s| s.is_active)
            .map(|s| (s.id, s))
            .collect();

    let servers: Vec<&pdns_server_repo::PdnsServer> = body
        .server_ids
        .iter()
        .filter_map(|id| all_servers.get(id))
        .collect();

    let custom_hosts: Vec<String> = body
        .custom_hosts
        .iter()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .collect();

    if servers.is_empty() && custom_hosts.is_empty() {
        return Err(AppError::BadRequest("No valid active servers selected".into()));
    }

    let mut tasks: Vec<tokio::task::JoinHandle<Value>> = Vec::new();
    for srv in &servers {
        let name = body.name.clone();
        let rtype = body.rtype.clone();
        let sid = srv.id;
        let sname = srv.name.clone();
        let host = host_from_url(&srv.api_url).unwrap_or_else(|| srv.name.clone());
        tasks.push(tokio::spawn(async move {
            run_lookup(&name, &rtype, Some(sid), &sname, &host).await
        }));
    }
    for h in &custom_hosts {
        let name = body.name.clone();
        let rtype = body.rtype.clone();
        let host = h.clone();
        tasks.push(tokio::spawn(async move {
            run_lookup(&name, &rtype, None, &host, &host).await
        }));
    }

    let mut results = Vec::new();
    for t in tasks {
        results.push(t.await.unwrap_or_else(|e| json!({"error": e.to_string()})));
    }

    Ok(Json(json!({"results": results})))
}
