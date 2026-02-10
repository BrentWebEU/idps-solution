mod logs;

use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use logs::{get_logs, read_log_file};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting Raspi Rust API on 0.0.0.0:8080");
    
    HttpServer::new(|| {
        App::new()
            .service(default_route)
            .service(list_logs)
            .service(get_log_content)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

#[get("/")]
async fn default_route() -> impl Responder {
    HttpResponse::Ok().body("Raspi Rust API - Suricata Log Access")
}

#[get("/logs")]
async fn list_logs() -> impl Responder {
    match get_logs() {
        Ok(files) => HttpResponse::Ok().json(files),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error reading logs: {}", e))
    }
}

#[get("/logs/{filename}")]
async fn get_log_content(path: web::Path<String>) -> impl Responder {
    let filename = path.into_inner();
    
    match read_log_file(&filename) {
        Ok(content) => HttpResponse::Ok().body(content),
        Err(e) => HttpResponse::NotFound().body(format!("Error reading log file: {}", e))
    }
}
