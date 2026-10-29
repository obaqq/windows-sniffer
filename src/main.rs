use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::os::windows::ffi::OsStringExt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::*;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

struct Wsa;
impl Wsa {
    fn start() -> Result<Self> {
        let mut d = WSADATA::default();
        if unsafe { WSAStartup(0x202, &mut d) } != 0 {
            return Err(anyhow!("WSAStartup failed"));
        }
        Ok(Wsa)
    }
}
impl Drop for Wsa {
    fn drop(&mut self) {
        unsafe { WSACleanup() };
    }
}

fn local_ip() -> Result<Ipv4Addr> {
    unsafe {
        let s = socket(AF_INET as i32, SOCK_DGRAM, IPPROTO_UDP);
        if s == INVALID_SOCKET {
            return Err(anyhow!("socket failed"));
        }
        let mut dst: SOCKADDR_IN = std::mem::zeroed();
        dst.sin_family = AF_INET as u16;
        dst.sin_port = 80u16.to_be();
        dst.sin_addr.S_un.S_addr = u32::from(Ipv4Addr::new(8, 8, 8, 8)).to_be();
        let sl = std::mem::size_of::<SOCKADDR_IN>() as i32;
        let mut me: SOCKADDR_IN = std::mem::zeroed();
        let mut l = sl;
        let ok = connect(s, &dst as *const _ as *const SOCKADDR, sl) == 0
            && getsockname(s, &mut me as *mut _ as *mut SOCKADDR, &mut l) == 0;
        let err = std::io::Error::last_os_error();
        closesocket(s);
        if !ok {
            return Err(anyhow!("interface detection failed: {}", err));
        }
        Ok(Ipv4Addr::from(u32::from_be(me.sin_addr.S_un.S_addr)))
    }
}

fn pid_of(proto: u8, ip: Ipv4Addr, port: u16) -> Option<u32> {
    unsafe {
        let a = u32::from_ne_bytes(ip.octets());
        let p = (port.to_be() as u32) & 0xFFFF;
        let mut sz = 0u32;
        match proto {
            6 => {
                GetExtendedTcpTable(std::ptr::null_mut(), &mut sz, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0);
                let mut b = vec![0u8; sz as usize];
                if GetExtendedTcpTable(b.as_mut_ptr() as *mut _, &mut sz, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0) != 0 {
                    return None;
                }
                let n = *(b.as_ptr() as *const u32) as usize;
                let rows = b.as_ptr().add(4) as *const MIB_TCPROW_OWNER_PID;
                (0..n)
                    .map(|i| &*rows.add(i))
                    .find(|r| r.dwLocalAddr == a && (r.dwLocalPort & 0xFFFF) == p)
                    .map(|r| r.dwOwningPid)
            }
            17 => {
                GetExtendedUdpTable(std::ptr::null_mut(), &mut sz, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0);
                let mut b = vec![0u8; sz as usize];
                if GetExtendedUdpTable(b.as_mut_ptr() as *mut _, &mut sz, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0) != 0 {
                    return None;
                }
                let n = *(b.as_ptr() as *const u32) as usize;
                let rows = b.as_ptr().add(4) as *const MIB_UDPROW_OWNER_PID;
                (0..n)
                    .map(|i| &*rows.add(i))
                    .find(|r| r.dwLocalAddr == a && (r.dwLocalPort & 0xFFFF) == p)
                    .map(|r| r.dwOwningPid)
            }
            _ => None,
        }
    }
}

struct Procs {
    map: HashMap<(u8, Ipv4Addr, u16), (String, Instant)>,
    ttl: Duration,
}
impl Procs {
    fn new() -> Self {
        Self { map: HashMap::new(), ttl: Duration::from_secs(120) }
    }
    fn get(&mut self, proto: u8, ip: Ipv4Addr, port: u16) -> String {
        let k = (proto, ip, port);
        if let Some((n, t)) = self.map.get(&k) {
            if t.elapsed() < self.ttl {
                return n.clone();
            }
        }
        let n = pid_of(proto, ip, port)
            .map(|pid| unsafe {
                let h: HANDLE = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                if h.is_null() {
                    return format!("<pid {}>", pid);
                }
                let mut b = [0u16; 1024];
                let mut sz = b.len() as u32;
                let ok = QueryFullProcessImageNameW(h, 0, b.as_mut_ptr(), &mut sz) != 0;
                CloseHandle(h);
                if !ok || sz == 0 {
                    return format!("<pid {}>", pid);
                }
                let p = OsString::from_wide(&b[..sz as usize]);
                std::path::Path::new(&p)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("<invalid>")
                    .to_string()
            })
            .unwrap_or_else(|| "<unknown>".into());
        self.map.insert(k, (n.clone(), Instant::now()));
        n
    }
}

type Flow = (u8, u16, Ipv4Addr, u16);
struct Conns {
    map: HashMap<Flow, (&'static str, String, Instant)>,
    ttl: Duration,
}
impl Conns {
    fn new() -> Self {
        Self { map: HashMap::new(), ttl: Duration::from_secs(120) }
    }
    fn get(&self, k: &Flow) -> Option<(&'static str, String)> {
        self.map
            .get(k)
            .filter(|(_, _, t)| t.elapsed() < self.ttl)
            .map(|(tag, d, _)| (*tag, d.clone()))
    }
    fn set(&mut self, k: Flow, tag: &'static str, d: String) {
        self.map.insert(k, (tag, d, Instant::now()));
    }
}

struct Ip {
    hl: usize,
    proto: u8,
    ttl: u8,
    len: u16,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    df: bool,
    mf: bool,
}

fn parse_ip(b: &[u8]) -> Option<Ip> {
    if b.len() < 20 || b[0] >> 4 != 4 {
        return None;
    }
    let hl = (b[0] as usize & 0xF) * 4;
    if hl < 20 || b.len() < hl {
        return None;
    }
    let ff = u16::from_be_bytes([b[6], b[7]]);
    Some(Ip {
        hl,
        proto: b[9],
        ttl: b[8],
        len: u16::from_be_bytes([b[2], b[3]]),
        src: Ipv4Addr::new(b[12], b[13], b[14], b[15]),
        dst: Ipv4Addr::new(b[16], b[17], b[18], b[19]),
        df: ff & 0x4000 != 0,
        mf: ff & 0x2000 != 0,
    })
}

#[derive(Clone, Copy)]
enum Kind {
    Tcp(u8),
    Udp,
    Other,
}

fn classify(ip: &Ip, b: &[u8], me: Ipv4Addr) -> Option<(bool, Ipv4Addr, u16, Ipv4Addr, u16, usize, Kind)> {
    let out = if ip.src == me {
        true
    } else if ip.dst == me {
        false
    } else {
        return None;
    };
    let (lip, rip) = if out { (ip.src, ip.dst) } else { (ip.dst, ip.src) };
    match ip.proto {
        6 => {
            if b.len() < ip.hl + 20 {
                return None;
            }
            let t = &b[ip.hl..];
            let hl = ((t[12] >> 4) as usize) * 4;
            if hl < 20 {
                return None;
            }
            let (sp, dp) = (
                u16::from_be_bytes([t[0], t[1]]),
                u16::from_be_bytes([t[2], t[3]]),
            );
            let (lp, rp) = if out { (sp, dp) } else { (dp, sp) };
            Some((out, lip, lp, rip, rp, ip.hl + hl, Kind::Tcp(t[13])))
        }
        17 => {
            if b.len() < ip.hl + 8 {
                return None;
            }
            let u = &b[ip.hl..];
            let (sp, dp) = (
                u16::from_be_bytes([u[0], u[1]]),
                u16::from_be_bytes([u[2], u[3]]),
            );
            let (lp, rp) = if out { (sp, dp) } else { (dp, sp) };
            Some((out, lip, lp, rip, rp, ip.hl + 8, Kind::Udp))
        }
        1 => Some((out, lip, 0, rip, 0, ip.hl, Kind::Other)),
        _ => None,
    }
}

fn tls_sni(p: &[u8]) -> Option<String> {
    if p.len() < 6 || p[0] != 0x16 {
        return None;
    }
    let hs = &p[5..];
    if hs.len() < 4 || hs[0] != 0x01 || hs.len() < 4 + 2 + 32 + 1 {
        return None;
    }
    let mut pos = 4 + 2 + 32;
    pos += 1 + hs[pos] as usize;
    if pos + 2 > hs.len() {
        return None;
    }
    pos += 2 + u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    if pos + 1 > hs.len() {
        return None;
    }
    pos += 1 + hs[pos] as usize;
    if pos + 2 > hs.len() {
        return None;
    }
    let end = (pos + 2 + u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize).min(hs.len());
    pos += 2;
    while pos + 4 <= end {
        let ty = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ln = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;
        if pos + ln > end {
            break;
        }
        if ty == 0 && ln >= 5 {
            let nl = u16::from_be_bytes([hs[pos + 3], hs[pos + 4]]) as usize;
            if pos + 5 + nl <= end {
                return Some(String::from_utf8_lossy(&hs[pos + 5..pos + 5 + nl]).into_owned());
            }
        }
        pos += ln;
    }
    None
}

fn http_host(p: &[u8]) -> Option<String> {
    if p.len() < 16 {
        return None;
    }
    let t = String::from_utf8_lossy(&p[..p.len().min(4096)]);
    if !["GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "HTTP/"]
        .iter()
        .any(|v| t.starts_with(v))
    {
        return None;
    }
    t.lines()
        .find_map(|l| l.strip_prefix("Host:"))
        .map(|h| h.trim().to_string())
}

fn dns_q(p: &[u8], tcp: bool) -> Option<String> {
    let p = if tcp && p.len() >= 2 { &p[2..] } else { p };
    if p.len() < 16 || u16::from_be_bytes([p[4], p[5]]) == 0 {
        return None;
    }
    let mut pos = 12;
    let mut name = String::new();
    loop {
        if pos >= p.len() {
            return None;
        }
        let n = p[pos] as usize;
        pos += 1;
        if n == 0 {
            break;
        }
        if n > 63 || pos + n > p.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&p[pos..pos + n]));
        pos += n;
    }
    if name.is_empty() {
        return None;
    }
    let ty = if pos + 2 <= p.len() {
        u16::from_be_bytes([p[pos], p[pos + 1]])
    } else {
        0
    };
    let ty = match ty {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 12 => "PTR",
        15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV", 65 => "HTTPS",
        _ => "?",
    };
    Some(format!("{} ({})", name, ty))
}

fn main() -> Result<()> {
    let _wsa = Wsa::start()?;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let verbose = args.iter().any(|a| a == "-v" || a == "--verbose");
    let explicit: Option<Ipv4Addr> = args.iter().find_map(|a| a.parse().ok());
    let me = match explicit {
        Some(ip) => ip,
        None => local_ip()?,
    };

    let sock = unsafe { socket(AF_INET as i32, SOCK_RAW, IPPROTO_IP) };
    if sock == INVALID_SOCKET {
        return Err(anyhow!("socket failed: {}", std::io::Error::last_os_error()));
    }

    let mut addr: SOCKADDR_IN = unsafe { std::mem::zeroed() };
    addr.sin_family = AF_INET as u16;
    addr.sin_addr.S_un.S_addr = u32::from(me).to_be();
    let sl = std::mem::size_of::<SOCKADDR_IN>() as i32;
    if unsafe { bind(sock, &addr as *const _ as *const SOCKADDR, sl) } != 0 {
        return Err(anyhow!("bind {}: {}", me, std::io::Error::last_os_error()));
    }

    let mut on: u32 = RCVALL_ON as u32;
    let mut br: u32 = 0;
    if unsafe {
        WSAIoctl(
            sock, SIO_RCVALL,
            &mut on as *mut u32 as *mut _, 4,
            std::ptr::null_mut(), 0,
            &mut br, std::ptr::null_mut(), None,
        )
    } != 0 {
        return Err(anyhow!("SIO_RCVALL: {} (elevated?)", std::io::Error::last_os_error()));
    }

    println!(
        "Interface : {}  |  Mode : {}",
        me,
        if verbose { "verbose" } else { "interesting (use -v for all)" }
    );
    println!("Columns   : time dir process remote [proto] detail size");
    println!();

    let fit = |s: &str, w: usize| -> String {
        if s.chars().count() <= w {
            format!("{:<w$}", s, w = w)
        } else {
            format!("{}~", s.chars().take(w - 1).collect::<String>())
        }
    };

    let mut procs = Procs::new();
    let mut conns = Conns::new();
    let mut buf = vec![0u8; 65536];

    loop {
        let n = unsafe { recv(sock, buf.as_mut_ptr(), buf.len() as i32, 0) };
        if n <= 0 {
            if n < 0 {
                eprintln!("recv error: {}", std::io::Error::last_os_error());
            }
            continue;
        }
        let n = n as usize;

        let Some(ip) = parse_ip(&buf[..n]) else { continue };
        let Some((out, lip, lport, rip, rport, poff, kind)) = classify(&ip, &buf[..n], me) else {
            continue;
        };

        let end = (ip.len as usize).min(n);
        let payload = if end > poff && poff <= n { &buf[poff..end] } else { &[] };

        if !verbose && payload.is_empty() && matches!(kind, Kind::Tcp(f) if f & 0x17 == 0x10) {
            continue;
        }

        let proc = match kind {
            Kind::Tcp(_) => procs.get(6, lip, lport),
            Kind::Udp => procs.get(17, lip, lport),
            Kind::Other => "<system>".into(),
        };

        let flow: Flow = (ip.proto, lport, rip, rport);
        let (tag, detail) = if let Some(s) = tls_sni(payload) {
            let d = format!("SNI={}", s);
            conns.set(flow, "TLS", d.clone());
            ("TLS", d)
        } else if let Some(h) = http_host(payload) {
            let d = format!("Host={}", h);
            conns.set(flow, "HTTP", d.clone());
            ("HTTP", d)
        } else if lport == 53 || rport == 53 {
            ("DNS", dns_q(payload, matches!(kind, Kind::Tcp(_))).map(|q| format!("Q={}", q)).unwrap_or_default())
        } else if let Some((t, d)) = conns.get(&flow) {
            (t, d)
        } else if payload.first() == Some(&0x17) {
            ("TLS", "[encrypted]".into())
        } else {
            let tag: &'static str = match rport {
                22 => "SSH", 53 => "DNS", 80 => "HTTP", 123 => "NTP", 443 => "TLS",
                445 => "SMB", 19132 | 19133 => "MC-BE", 25565 => "MC-JE",
                3478 | 3479 => "STUN", 4070 => "Spotify", 5353 => "mDNS",
                _ => if ip.proto == 6 { "TCP" } else { "UDP" },
            };
            let d = match kind {
                Kind::Tcp(f) if payload.is_empty() => {
                    let mut v = Vec::new();
                    for (b, n) in [
                        (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
                        (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
                    ] {
                        if f & b != 0 { v.push(n); }
                    }
                    if v.is_empty() { "-".into() } else { v.join(",") }
                }
                _ => String::new(),
            };
            (tag, d)
        };

        let (d, a) = if out { ("OUT", ">") } else { ("IN ", "<") };
        let remote = format!("{}:{}", rip, rport);
        let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = t.as_secs() % 86400;
        let ts = format!(
            "{:02}:{:02}:{:02}.{:03}",
            secs / 3600, (secs % 3600) / 60, secs % 60, t.subsec_millis()
        );
        let line = format!(
            "{} {} {} {} {} [{:<5}]",
            ts, d, fit(&proc, 22), a, fit(&remote, 22), tag
        );
        println!(
            "{} ({}B)",
            if detail.is_empty() { line } else { format!("{} {:<48}", line, detail) },
            ip.len
        );

        if verbose && !payload.is_empty() && !matches!(tag, "TLS" | "HTTP" | "DNS") {
            let nn = payload.len().min(24);
            let hex = payload[..nn]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            let asc = payload[..nn]
                .iter()
                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                .collect::<String>();
            let tail = if payload.len() > nn { " …" } else { "" };
            let fl = match (ip.df, ip.mf) {
                (true, true) => "DF,MF",
                (true, false) => "DF",
                (false, true) => "MF",
                (false, false) => "-",
            };
            println!(
                "{:>34} hex[{}{}] ascii=\"{}\"  (ttl={} flags={})",
                "", hex, tail, asc, ip.ttl, fl
            );
        }
    }
}