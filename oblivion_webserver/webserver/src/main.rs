use actix_web::{web, App, HttpResponse, HttpServer, Responder, HttpRequest, post, get};
use actix_web::middleware::Logger;
use actix_multipart::Multipart;
use futures_util::stream::StreamExt;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde_json;
use std::fs;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::process::Command;

use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::PKey;
use openssl::x509::X509;
use std::path::Path;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

mod models;
use models::auth::verify_cert_hash;
use uuid::Uuid;

use actix_web::cookie::{Cookie, time::Duration as CookieDuration};
struct AppState {
    sessions: Mutex<HashMap<String, String>>,
}

static ASN_CACHE: Lazy<DashMap<String, serde_json::Value>> = Lazy::new(DashMap::new);
static OBSERVED_IPS: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

fn load_cache_from_disk() {
    if let Ok(contents) = fs::read_to_string("/data/asn_cache.json") {
        match serde_json::from_str::<HashMap<String, serde_json::Value>>(&contents) {
            Ok(parsed_map) => {
                for (k, v) in parsed_map {
                    ASN_CACHE.insert(k, v);
                }
            }
            Err(e) => {
                eprintln!("Failed to parse asn_cache.json: {}", e);
            }
        }
    }
}

fn persist_cache_to_disk() {
    let map: HashMap<_, _> = ASN_CACHE
        .iter()
        .map(|entry| (entry.key().clone(), entry.value().clone()))
        .collect();

    if let Ok(json) = serde_json::to_string_pretty(&map) {
        let _ = fs::create_dir_all("/data");
        let _ = fs::write("/data/asn_cache.json", json);
    }
}



#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
    .content_type("text/html")
    .body(include_str!("./views/splash.html"))

}

#[post("/login")]
async fn login(mut payload: Multipart, data: web::Data<AppState>) -> impl Responder {
    std::env::set_var("OPENSSL_FORCE_FIPS_MODE", "1");

    let mut uploaded_key = vec![];
    let mut password = String::new();

    // Parse multipart form fields
    while let Some(Ok(mut field)) = payload.next().await {
        if let Some(cd) = field.content_disposition() {
            match cd.get_name() {
                Some("cert") => {
                    while let Some(chunk_result) = field.next().await {
                        if let Ok(chunk) = chunk_result {
                            uploaded_key.extend_from_slice(&chunk);
                        }
                    }
                }
                Some("password") => {
                    let mut pw_bytes = vec![];
                    while let Some(chunk_result) = field.next().await {
                        if let Ok(chunk) = chunk_result {
                            pw_bytes.extend_from_slice(&chunk);
                        }
                    }
                    password = String::from_utf8_lossy(&pw_bytes).to_string();
                }
                _ => {}
            }
        }
    }

    // Decrypt the private key from uploaded PEM with password
    let pkey = match PKey::private_key_from_pem_passphrase(&uploaded_key, password.as_bytes()) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::Unauthorized().body("❌ Invalid password or private key"),
    };

    // Hash public key for fingerprint
    let pubkey_der = match pkey.public_key_to_der() {
        Ok(bytes) => bytes,
        Err(_) => return HttpResponse::InternalServerError().body("❌ Failed to DER encode pubkey"),
    };

    let mut hasher = match Hasher::new(MessageDigest::sha512()) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().body("❌ Hasher error"),
    };

    if hasher.update(&pubkey_der).is_err() {
        return HttpResponse::InternalServerError().body("❌ Failed to update hasher");
    }

    let digest = match hasher.finish() {
        Ok(d) => d,
        Err(_) => return HttpResponse::InternalServerError().body("❌ Failed to finish hash"),
    };

    let hex_digest = hex::encode(digest);
    println!("🔍 Computed SHA-512 pubkey digest: {}", hex_digest);

    // Extract CN from PEM to determine user directory
    let user = match X509::from_pem(&uploaded_key) {
        Ok(cert) => cert.subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        Err(_) => return HttpResponse::BadRequest().body("❌ Unable to parse X509 certificate"),
    };

    println!("🔍 Extracted CN (username): {}", user);

    let user_dir = format!("./certs/users/{}", user);
    if !Path::new(&user_dir).exists() {
        return HttpResponse::Forbidden().body("❌ No cert records found for user");
    }

    // Construct expected cert path + hash path to verify
    let cert_path = format!("{}/{}.pem", user_dir, &hex_digest[..12]);
    let hash_path = format!("{}/{}.hash", user_dir, &hex_digest[..12]);

    match verify_cert_hash(&cert_path, &hash_path) {
        Ok(true) => {
            println!(" Certificate fingerprint matched known hash");
            // Generate session
        let session_id = Uuid::new_v4().to_string();
        data.sessions.lock().unwrap().insert(session_id.clone(), user.clone());

        let cookie = Cookie::build("session", session_id.clone())
            .path("/")
            .max_age(CookieDuration::minutes(30))
            .http_only(true)
            .finish();

        let splash_html = format!(r#"
            <html>
            <head>
                <meta http-equiv="refresh" content="3;url=/dashboard" />
                <style>
                    body {{ background: #0f0f0f; color: #f0f0f0; font-family: monospace; text-align: center; margin-top: 10%; }}
                    h1 {{ font-size: 3em; color: #44ff88; }}
                    .box {{ border: 1px solid #44ff88; display: inline-block; padding: 2em; border-radius: 8px; }}
                </style>
            </head>
            <body>
                <div class="box">
                    <h1> Welcome, {}</h1>
                    <p> Certificate verified successfully</p>
                    <p> Redirecting to dashboard...</p>
                </div>
            </body>
            </html>
        "#, user);

        HttpResponse::Ok()
            .content_type("text/html")
            .cookie(cookie)
            .body(splash_html)
        
        }
        Ok(false) => {
            println!("❌ Certificate mismatch or tampered");
            HttpResponse::Unauthorized().body("❌ Certificate integrity check failed")
        }
        Err(e) => {
            eprintln!("❌ Error in verification: {}", e);
            HttpResponse::InternalServerError().body("❌ Verification error")
        }
    }

}

#[get("/lookup/asn/{ip}")]
async fn asn_lookup(req: HttpRequest, path: web::Path<String>, data: web::Data<AppState>) -> impl Responder {
    let ip = path.into_inner();

    let session_id = req.cookie("session").map(|c| c.value().to_string()).unwrap_or_default();
    if !data.sessions.lock().unwrap().contains_key(&session_id) {
        return HttpResponse::Unauthorized().body("❌ Unauthorized");
    }

    if let Some(cached) = ASN_CACHE.get(&ip) {
        return HttpResponse::Ok().json(cached.clone());
    }

    let output = Command::new("whois")
        .args(["-h", "whois.cymru.com", "-v", &ip])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            let lines: Vec<&str> = stdout.lines().collect();

            if lines.len() >= 2 {
                let parts: Vec<&str> = lines[1].split('|').map(|s| s.trim()).collect();
                if parts.len() >= 7 {
                    let asn_data = serde_json::json!({
                        "asn": parts[0],
                        "ip": parts[1],
                        "prefix": parts[2],
                        "country": parts[3],
                        "registry": parts[4],
                        "allocated": parts[5],
                        "org": parts[6]
                    });

                    ASN_CACHE.insert(ip.clone(), asn_data.clone());
                    OBSERVED_IPS.lock().unwrap().push(ip);
                    persist_cache_to_disk();
                    return HttpResponse::Ok().json(asn_data);
                }
            }

            HttpResponse::NotFound().body("❌ No ASN info")
        }
        _ => HttpResponse::InternalServerError().body("❌ Whois query failed"),
    }
}



#[get("/logout")]
async fn logout(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    if let Some(cookie) = req.cookie("session") {
        let session_id = cookie.value().to_string();
        data.sessions.lock().unwrap().remove(&session_id);
    }

    let expired_cookie = actix_web::cookie::Cookie::build("session", "")
        .path("/")
        .max_age(actix_web::cookie::time::Duration::seconds(0))
        .finish();

    let response_html = r#"
        <html>
        <head>
            <meta http-equiv="refresh" content="5;url=/" />
            <style>
                body {
                    background-color: #0f0f0f;
                    color: #eeeeee;
                    font-family: monospace;
                    text-align: center;
                    margin-top: 10%;
                }
                .box {
                    border: 1px solid #ff6666;
                    display: inline-block;
                    padding: 2em;
                    border-radius: 10px;
                }
                a {
                    color: #ff6666;
                    text-decoration: none;
                }
            </style>
        </head>
        <body>
            <div class="box">
                <h1> Logged Out</h1>
                <p>Your session has been closed securely.</p>
                <p><a href="/"> Return to Login</a></p>
                <p><em>Redirecting in 5 seconds...</em></p>
            </div>
        </body>
        </html>
    "#;

    HttpResponse::Ok()
        .content_type("text/html")
        .cookie(expired_cookie)
        .body(response_html)
}

#[get("/dashboard")]
async fn dashboard(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let session_cookie = req.cookie("session").map(|c| c.value().to_string()).unwrap_or_default();
    let sessions = data.sessions.lock().unwrap();

    if let Some(user) = sessions.get(&session_cookie) {
        HttpResponse::Ok().body(format!(r#"
<html>
    <head>
        <title>Oblivion Edge Dashboard</title>
        <meta charset=\"utf-8\">
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
        <link rel=\"stylesheet\" href=\"https://unpkg.com/leaflet@1.9.3/dist/leaflet.css\" />
        <style>
            body {{
                background-color: #1e1e1e;
                color: #eaeaea;
                font-family: monospace;
                margin: 0;
    }}
            #map {{
                height: 80vh;
                width: 100%;
    }}
            .header {{
                padding: 1em;
                background: #2e2e2e;
    }}
            .logout {{
                float: right;
                margin-top: -1.5em;
    }}
            ul {{
                padding-left: 2em;
    }}
        </style>
    </head>
    <body>
    <div class=\"header\">
        <h1>🌐 Oblivion Edge :: Global Dashboard</h1>
        <a href=\"/logout\" class=\"logout\">🚪 Logout</a>
    </div>
    <div id=\"map\"></div>
    <script src=\"https://unpkg.com/leaflet@1.9.3/dist/leaflet.js\"></script>
    <script>
        const map = L.map('map').setView([20, 0], 2);
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            attribution: '&copy; OpenStreetMap contributors',
            maxZoom: 6
        }}).addTo(map);

            async function populateGlobalMap() {
                try {{
                    const res = await fetch(\"/api/observed_ips\");
                    const data = await res.json();
                    data.forEach(entry => {
                        const lat = entry.lat || 0;
                        const lon = entry.lon || 0;
                        const popup = `
                            <strong>ASN ${entry.asn}</strong><br>
                            ${entry.org}<br>
                            ${entry.ip} (${entry.country})
                        `;
                        L.circleMarker([lat, lon], {
                            radius: 6,
                            color: \"lime\",
                            fillColor: '#0f0',
                            fillOpacity: 0.5
                        }).bindPopup(popup).addTo(map);
                    });
    }} catch (err) {
                    console.error(\"Map load failed:\", err);
                }
            }

            populateGlobalMap();
        </script>
    </body>
</html>
"#, user))
    } else {
        HttpResponse::Unauthorized().body("❌ Not authorized")
    }
}

#[get("/api/observed_ips")]
async fn observed_ips(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let session_id = req.cookie("session").map(|c| c.value().to_string()).unwrap_or_default();
    if !data.sessions.lock().unwrap().contains_key(&session_id) {
        return HttpResponse::Unauthorized().body("❌ Unauthorized");
    }

    let ips = OBSERVED_IPS.lock().unwrap();
    let mut result = Vec::new();

    for ip in ips.iter() {
        if let Some(data) = ASN_CACHE.get(ip) {
            let mut enriched = data.clone();

            let (lat, lon) = match enriched["country"].as_str().unwrap_or("ZZ") {
                "US" => (37.77, -122.41),
                "CN" => (39.90, 116.40),
                "IN" => (28.61, 77.20),
                _ => (20.0, 0.0)
            };

            enriched["lat"] = serde_json::json!(lat);
            enriched["lon"] = serde_json::json!(lon);

            result.push(enriched);
        }
    }

    HttpResponse::Ok().json(result)
}




#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();
    

    // Load SSL cert and key
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();

    // Set TLS 1.2 ciphers (FIPS-safe)
    builder.set_cipher_list("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256").unwrap();

    // Set TLS 1.3 ciphers explicitly
    builder.set_ciphersuites("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256").unwrap();

    // Set cert + key
    builder.set_private_key_file("/certs/key.pem", SslFiletype::PEM).unwrap();
    builder.set_certificate_chain_file("/certs/cert.pem").unwrap();


    let state = Arc::new(AppState {
        sessions: Mutex::new(HashMap::new()),
    });

    // load cache from disk
    load_cache_from_disk();


    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::from(state.clone()))
            .wrap(Logger::default())
            .service(index)
            .service(login)
            .service(dashboard)
            .service(logout)
            .service(asn_lookup)
            .service(observed_ips)
    })
    .bind_openssl(("0.0.0.0", 8443), builder)?
    .run()
    .await
}
