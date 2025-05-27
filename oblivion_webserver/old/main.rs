use actix_web::{web, App, HttpResponse, HttpServer, Responder};

async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html")
        .body("<html><body><h1>Oblivion Edge Router Web UI</h1></body></html>")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Web UI running on https://localhost:8443");

    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(index))
    })
    .bind(("0.0.0.0", 8443))?
    .run()
    .await
}
