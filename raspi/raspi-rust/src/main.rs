mod controllers {
    pub mod log_controller;
}

mod services {
    pub mod logs_service;
}

use actix_web::{get, App, HttpResponse, HttpServer, Responder};

use crate::controllers::log_controller::{delete_log, get_log_content, list_logs, send_log_to_server};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting Raspi Rust API on 0.0.0.0:8080");

    HttpServer::new(|| {
        App::new()
            .service(default_route)
            .service(list_logs)
            .service(get_log_content)
            .service(delete_log)
            .service(send_log_to_server)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

#[get("/")]
async fn default_route() -> impl Responder {
    HttpResponse::Ok().body("Raspi Rust API - Suricata Log Access")
}
