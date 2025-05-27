use actix_web::{web, App, HttpResponse, HttpServer, Responder, HttpRequest, post, get};
use actix_web::middleware::Logger;
use actix_multipart::Multipart;
use futures_util::stream::StreamExt;
// use std::fs;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

mod models;
// use models::auth::{verify_cert_hash};

struct AppState {
    sessions: Mutex<HashMap<String, String>>,
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
    .content_type("text/html")
    .body(include_str!("./views/splash.html"))

}

#[post("/login")]
async fn login(mut payload: Multipart, data: web::Data<AppState>) -> impl Responder {
    use openssl::pkey::PKey;
    use openssl::hash::{Hasher, MessageDigest};
    use openssl::x509::X509;
    use std::fs;

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
                },
                Some("password") => {
                    let mut pw_bytes = vec![];
                    while let Some(chunk_result) = field.next().await {
                        if let Ok(chunk) = chunk_result {
                            pw_bytes.extend_from_slice(&chunk);
                        }
                    }
                    password = String::from_utf8_lossy(&pw_bytes).to_string();
                },
                _ => {}
            }
        }
    }

    // Decrypt private key using password
    let pkey = match PKey::private_key_from_pem_passphrase(&uploaded_key, password.as_bytes()) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::Unauthorized().body("❌ Invalid password or private key format"),
    };

    // Optional: try to extract CN from a matching public cert if available
    let pubkey_der = match pkey.public_key_to_der() {
        Ok(der) => der,
        Err(_) => return HttpResponse::InternalServerError().body("❌ Failed DER encoding of public key"),
    };

    let mut hasher = match Hasher::new(MessageDigest::sha512()) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().body("❌ Hasher error"),
    };

    if let Err(_) = hasher.update(&pubkey_der) {
        return HttpResponse::InternalServerError().body("❌ Failed to update hash");
    }

    let digest = match hasher.finish() {
        Ok(d) => d,
        Err(_) => return HttpResponse::InternalServerError().body("❌ Failed to finish hash"),
    };

    // Attempt to extract CN from an optional X509 certificate
    // Extract CN immediately as String to avoid lifetime issues
let user = match X509::from_pem(&uploaded_key) {
        Ok(cert) => cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "default".to_string()),
        Err(_) => "default".to_string(),
    }; 

    let hash_file = format!("certs/users/{}/{}.cert.sha512", user, user);
    let stored_hash = match fs::read_to_string(&hash_file) {
        Ok(s) => s,
        Err(_) => return HttpResponse::Unauthorized().body("❌ No hash found for user"),
    };
    let expected = stored_hash.split_whitespace().next().unwrap_or("");
    let actual_hex = hex::encode(digest);

    if actual_hex == expected {
        data.sessions.lock().unwrap().insert("session-token-123".into(), user.clone());
        HttpResponse::Ok()
            .append_header(("Set-Cookie", "session=session-token-123; Path=/"))
            .body(format!(r#"<html><body>✅ Welcome, {}! <a href='/dashboard'>Go to Dashboard</a></body></html>"#, user))
    } else {
        HttpResponse::Unauthorized().body("❌ Public key hash mismatch")
    }
}

#[get("/dashboard")]
async fn dashboard(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let session_cookie = req.cookie("session").map(|c| c.value().to_string()).unwrap_or_default();
    let sessions = data.sessions.lock().unwrap();
    if sessions.contains_key(&session_cookie) {
        HttpResponse::Ok().body(r#"
            <html><body>
            <h1>Oblivion Edge Admin Dashboard</h1>
            <ul>
              <li>🔐 VPN Status</li>
              <li>🧱 Firewall Status</li>
              <li>📈 Traffic Charts</li>
              <li>⚙️ Kernel ZTA Modules</li>
            </ul>
            </body></html>
        "#)
    } else {
        HttpResponse::Unauthorized().body("Not authorized")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let state = Arc::new(AppState {
        sessions: Mutex::new(HashMap::new()),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::from(state.clone()))
            .wrap(Logger::default())
            .service(index)
            .service(login)
            .service(dashboard)
    })
    .bind(("0.0.0.0", 8443))?
    .run()
    .await
}
