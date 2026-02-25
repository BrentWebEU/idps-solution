use actix_web::{HttpResponse, Responder, delete, get, post, web};
use reqwest;
use crate::services::logs_service::{delete_log_file, get_logs, read_log_file};
use std::env;

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

#[delete("/logs/{filename}")]
async fn delete_log(path: web::Path<String>) -> impl Responder {
    let filename = path.into_inner();
    
    match delete_log_file(&filename) {
        Ok(_) => HttpResponse::Ok().body("Log file deleted"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error deleting log file: {}", e))
    }
}

#[post("/logs/send/{filename}")]
async fn send_log_to_server(path: web::Path<String>) -> impl Responder {
    let filename = path.into_inner();
    
    let content = match read_log_file(&filename) {
        Ok(content) => content,
        Err(e) => return HttpResponse::NotFound().body(format!("Error reading log file: {}", e)),
    };

    let client = reqwest::Client::new();
    // resolve the VPS_API_URL environment variable, returning an error response if it's missing
    let vps_api_url = match env::var("VPS_API_URL") {
        Ok(url) => url,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Missing VPS_API_URL: {}", e)),
    };

    let resp = client.post(format!("{}/logs", vps_api_url))
        .header("Content-Type", "application/json")
        .body(content)
        .send()
        .await;

    match resp {
        Ok(response) => {
            if response.status().is_success() {
                match response.text().await {
                    Ok(text_body) => {
                        match serde_json::from_str::<serde_json::Value>(&text_body) {
                            Ok(json_body) => HttpResponse::Ok().json(json_body),
                            Err(e) => HttpResponse::InternalServerError().body(format!("Failed to parse JSON response: {}", e)),
                        }
                    },
                    Err(e) => HttpResponse::InternalServerError().body(format!("Failed to read response text: {}", e)),
                }
            } else {
                let status = response.status();
                let text = response.text().await.unwrap_or_else(|_| "Could not get response text".to_string());
                HttpResponse::build(actix_web::http::StatusCode::from_u16(status.as_u16()).unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR)).body(format!("Server responded with error: {}", text))
            }
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to send log to server: {}", e)),
    }
}
