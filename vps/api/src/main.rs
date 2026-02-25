mod controllers {
    pub mod log_controller;
}

mod services {
    pub mod log_service;
}

use actix_web::{get, App, HttpResponse, HttpServer, Responder};

use crate::controllers::log_controller::{get_log, receive_logs};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(default_route)
            .service(receive_logs)
            .service(get_log)
            .service(get_api_status)
    })
    .bind(("0.0.0.0", 8081))?
    .run()
    .await
}

#[get("/")]
async fn default_route() -> impl Responder {
    HttpResponse::Ok().body(format!(
        "API running on version {}",
        env!("CARGO_PKG_VERSION")
    ))
}

#[get("/status")]
async fn get_api_status() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

#[cfg(test)]
mod tests {
    use actix_web::{http::header::ContentType, test, App};

    use std::path::Path;

    use crate::controllers::log_controller::receive_logs;

    use super::*;

    #[actix_web::test]
    async fn test_index_get() {
        let app = test::init_service(App::new().service(default_route)).await;

        let req = test::TestRequest::default()
            .insert_header(ContentType::plaintext())
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_receive_logs() {
        let log_path = Path::new("src/test_logs/eve.json");
        let payload = std::fs::read_to_string(log_path).expect("failed to read test log");
        let app = test::init_service(App::new().service(receive_logs)).await;
        let req = test::TestRequest::get()
            .uri("/logs")
            .insert_header(ContentType::json())
            .set_payload(payload.clone())
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let body = test::read_body(resp).await;
        let resp_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let expected = serde_json::json!({ "data": payload });
        assert_eq!(resp_json, expected);
    }
}
