use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};
use std::env;
use tokio::process::Command;
use bollard::Docker;
use serde::{Deserialize, Serialize};
use futures_util::stream::StreamExt; // Required for stream.next().await

// This struct will hold the Docker client instance
struct DockerClient {
    docker: Docker,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: String,
    pub args: Vec<String>,
}

#[post("/suricata/exec")]
async fn execute_suricata_command(
    req_body: web::Json<ExecRequest>,
    docker_client: web::Data<DockerClient>,
) -> impl Responder {
    let container_name = "suricata"; // The name of the Suricata service in docker-compose.yml

    // Create an exec instance
    let config = bollard::exec::CreateExecOptions {
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        cmd: Some(vec![req_body.command.clone()].into_iter().chain(req_body.args.clone().into_iter()).collect()),
        ..Default::default()
    };

    let exec_instance = match docker_client.docker.create_exec(container_name, config).await {
        Ok(exec) => exec.id,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to create exec instance: {}", e)),
    };

    // Start the exec instance
    let start_exec_options = bollard::exec::StartExecOptions {
        detach: false,
        ..Default::default()
    };

    let response = match docker_client.docker.start_exec(&exec_instance, Some(start_exec_options)).await {
        Ok(response) => response,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to start exec instance: {}", e)),
    };

    let mut stdout = String::new();
    let mut stderr = String::new();

    if let bollard::exec::StartExecResults::Attached { mut output, .. } = response {
        while let Some(Ok(msg)) = output.next().await {
            use bollard::container::LogOutput::*;
            match msg {
                StdOut { message } => stdout.push_str(&String::from_utf8_lossy(&message)),
                StdErr { message } => stderr.push_str(&String::from_utf8_lossy(&message)),
                _ => {}
            }
        }
    } else {
        return HttpResponse::InternalServerError().body("Failed to get output from exec instance.");
    }

    HttpResponse::Ok().json(serde_json::json!({
        "command": format!("{} {}", req_body.command, req_body.args.join(" ")),
        "stdout": stdout,
        "stderr": stderr,
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let listen_address = env::var("LISTEN_ADDRESS").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_address = format!("{}:{}", listen_address, port);

    println!("Starting server on http://{}", bind_address);

    let docker = Docker::connect_with_http_defaults()
        .expect("Failed to connect to Docker daemon");

    let docker_client = web::Data::new(DockerClient { docker });

    HttpServer::new(move || {
        App::new()
            .app_data(docker_client.clone())
            .service(execute_suricata_command)
            .service(root)
    })
    .bind(&bind_address)?
    .run()
    .await
}

#[get("/")]
async fn root() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Suricata API",
        "example": {
            "endpoint": "/suricata/exec",
            "method": "POST",
            "body": {
                "command": "suricata",
                "args": ["-V"]
            }
        }
    }))
}
