use actix_web::{Error, HttpResponse, Responder, get, post, web};
use futures::StreamExt;

use crate::services::log_service::{save_log, load_log};

#[post("/logs")]
pub async fn receive_logs(
    query: web::Query<std::collections::HashMap<String, String>>,
    mut body: web::Payload,
) -> Result<HttpResponse, Error> {
    let path = "/app/data/";

    let mut bytes = web::BytesMut::new();
    while let Some(item) = body.next().await {
        let item = item?;
        bytes.extend_from_slice(&item);
    }

    let data = String::from_utf8_lossy(&bytes).trim().to_string();
    let json_value = serde_json::from_str(&data).unwrap_or(serde_json::Value::String(data.clone()));
    let payload = serde_json::json!({ "path": path, "data": json_value });

    let value = payload.to_string();
    let _ = save_log(&path, &value);
    return Ok(HttpResponse::Ok().json((payload, path)));
}

#[get("/logs/{filename}")]
pub async fn get_log(path: web::Path<String>) -> impl Responder {
    let file_path = web::Path::from(format!("/app/data/{}", path));
    match load_log(file_path.into_inner()) {
        Ok(_data) => HttpResponse::Ok().finish(),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}
