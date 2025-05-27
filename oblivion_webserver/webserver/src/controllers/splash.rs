use actix_web::{HttpResponse, Responder};

pub async fn index() -> impl Responder {
    HttpResponse::Ok().content_type("text/html").body(include_str!("../views/splash.html"))
}
