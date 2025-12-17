use reqwest::blocking::Client;
use std::net::{UdpSocket, TcpStream};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use std::collections::HashMap;
use regex::Regex;
use rustls::{ClientConnection, RootCertStore, StreamOwned};
use webpki_roots::TLS_SERVER_ROOTS;
use std::sync::Arc;
use std::io::Write;
use x509_parser::parse_x509_certificate;
use std::process::Command;

fn main() {
    let host = "taisen.fr";
    let url = format!("https://{}", host);

    let resolver_config = ResolverConfig::default();
    let resolver = Resolver::new(resolver_config.clone(), ResolverOpts::default()).unwrap();
    let dns_server = resolver_config.name_servers().first().unwrap();
    println!("Serveur DNS: {}:{}", dns_server.socket_addr.ip(), dns_server.socket_addr.port());
    let dest_ip = resolver.lookup_ip(host).unwrap().iter().next().unwrap();
    println!("IP du serveur: {}\n", dest_ip);

    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect(format!("{}:443", dest_ip)).unwrap();
    let local_addr = socket.local_addr().unwrap();
    println!("IP Source: {}\nPort Source: {}\n", local_addr.ip(), local_addr.port());
    println!("IP Destination: {}\nPort Destination: 443\n", dest_ip);

    let client = Client::builder().build().unwrap();
    let res = client.get(&url).send().unwrap();

    let security_headers = [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy"
    ];
    let mut found = false;
    for (key, value) in res.headers().iter() {
        let k = key.as_str().to_lowercase();
        for sh in &security_headers {
            if k.contains(sh) {
                if !found { println!("Headers de sécurité:"); found = true; }
                println!("{}: {}", key, value.to_str().unwrap());
            }
        }
    }
    if !found {
        println!("Aucun header de sécurité sur {}.\nRécupération depuis google.fr:", host);
        let gres = client.get("https://google.fr").send().unwrap();
        for (key, value) in gres.headers().iter() {
            let k = key.as_str().to_lowercase();
            for sh in &security_headers {
                if k.contains(sh) {
                    println!("{}: {}", key, value.to_str().unwrap());
                }
            }
        }
    }
    println!();

    if let Some(content_type) = res.headers().get("content-type") {
        let ct = content_type.to_str().unwrap();
        println!("Content-Type: {}", ct);
        if ct.contains("text/html") { println!("Utilité: Page web HTML"); }
        else if ct.contains("text/") { println!("Utilité: Fichier texte"); }
        else if ct.contains("application/json") { println!("Utilité: Données JSON"); }
        else if ct.contains("application/octet-stream") { println!("Utilité: Fichier binaire générique"); }
        else { println!("Utilité: Type générique"); }
    }
    println!();

    let balises_array = ["html","head","body","title","meta","link","script","h1","h2","p","a","img"];
    let mut balises_map = HashMap::new();
    balises_map.insert("titre","title");
    balises_map.insert("paragraphe","p");
    balises_map.insert("lien","a");
    balises_map.insert("image","img");
    balises_map.insert("entete1","h1");
    balises_map.insert("entete2","h2");
    println!("Balises (array): {:?}\nBalises (map): {:?}\n", balises_array, balises_map);

    let body = res.text().unwrap();
    let re = Regex::new(r"(?is)<h1[^>]*>(.*?)</h1>").unwrap();
    match re.captures(&body) {
        Some(cap) => println!("Titre H1: {}\n", cap[1].trim()),
        None => println!("Pas de H1 trouvé\n"),
    }

    let addr = format!("{}:443", dest_ip);
    let tcp = TcpStream::connect(&addr).unwrap();
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
    }));
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let rc_config = Arc::new(config);
    let server_name = host.try_into().unwrap();
    let conn = ClientConnection::new(rc_config, server_name).unwrap();
    let mut tls_stream = StreamOwned::new(conn, tcp);
    let _ = tls_stream.write_all(b"GET / HTTP/1.0\r\n\r\n");
    let certs = tls_stream.conn.peer_certificates().unwrap_or(&[]);
    if !certs.is_empty() {
        let der = &certs[0].0;
        let (_, cert) = parse_x509_certificate(der).unwrap();
        println!("===== Certificat =====");
        println!("Sujet: {}", cert.subject());
        println!("Émetteur: {}", cert.issuer());
        println!("Valide du {} au {}", cert.validity().not_before, cert.validity().not_after);
        println!("Numéro de série: {}", cert.raw_serial_as_string());
        println!("Algorithme de signature: {:?}", cert.signature_algorithm);
        println!("Extensions:");
        for ext in cert.extensions() {
            println!("  - {:?} = {:?}", ext.oid, ext.parsed_extension());
        }
        println!("Clé publique:");
        if let Ok(pk) = cert.public_key().parsed() {
            match pk {
                x509_parser::public_key::PublicKey::RSA(rsa) => {
                    println!("  RSA {} bits", rsa.modulus.len() * 8);
                    print!("  Modulus (hex): ");
                    for b in rsa.modulus { print!("{:02X}", b); }
                    println!();
                    print!("  Exposant (hex): ");
                    for b in rsa.exponent { print!("{:02X}", b); }
                    println!();
                }
                x509_parser::public_key::PublicKey::EC(ec) => {
                    print!("  EC Public Key (hex): ");
                    for b in ec.data() { print!("{:02X}", b); }
                    println!();
                }
                _ => {}
            }
        }
        print!("Signature brute (hex): ");
        for b in cert.signature_value.data.iter() { print!("{:02X}", b); }
        println!("\n======================\n");
    }

    println!("Traceroute vers {}:", host);
    let output = if cfg!(target_os = "windows") {
        Command::new("tracert").arg("-d").arg("-h").arg("15").arg(host).output()
    } else {
        Command::new("traceroute").arg("-n").arg("-m").arg("15").arg(host).output()
    };
    if let Ok(result) = output {
        let text = String::from_utf8_lossy(&result.stdout);
        let lines: Vec<&str> = text.lines().collect();
        let re_ip = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
        for line in lines {
            if let Some(cap) = re_ip.captures(line) {
                println!("  {}", cap[1].trim());
            }
        }
    }
}
