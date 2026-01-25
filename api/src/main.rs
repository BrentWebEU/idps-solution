use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};
use actix_cors::Cors;
use bollard::Docker;
use bollard::container::StopContainerOptions;
use futures_util::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::env;

// Struct om de Docker client instantie te bewaren
// Deze wordt gebruikt om commando's uit te voeren op Docker containers
struct DockerClient {
    docker: Docker,
}

// Request struct voor het uitvoeren van commando's
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: String,
    pub args: Vec<String>,
}

// Response struct voor container status informatie
#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerStatus {
    pub id: String,
    pub name: String,
    pub status: String,
    pub state: String,
    pub running: bool,
}

// Response struct voor algemene API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

// Root endpoint - geeft informatie over de API
#[get("/")]
async fn root() -> impl Responder {
    let response = serde_json::json!({
        "message": "Suricata IDPS API",
        "version": "1.0.0",
        "endpoints": {
            "GET /": "API informatie",
            "GET /api/status": "Status van de Suricata container",
            "POST /api/suricata/start": "Start de Suricata container",
            "POST /api/suricata/stop": "Stop de Suricata container",
            "POST /api/suricata/restart": "Herstart de Suricata container",
            "POST /api/suricata/exec": "Voer een commando uit in de Suricata container",
            "GET /api/suricata/logs": "Haal de logs op van de Suricata container"
        }
    });
    
    HttpResponse::Ok().json(response)
}

// Haal de status op van de Suricata container
#[get("/api/status")]
async fn get_status(docker_client: web::Data<DockerClient>) -> impl Responder {
    let container_name = "suricata";
    
    // Haal alle containers op
    let containers = match docker_client
        .docker
        .list_containers::<String>(None)
        .await
    {
        Ok(containers) => containers,
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Fout bij ophalen containers: {}", e),
                data: None,
            });
        }
    };
    
    // Zoek de Suricata container
    let suricata_container = containers
        .iter()
        .find(|c| {
            c.names.as_ref()
                .map(|names| names.iter().any(|n| n.contains(container_name)))
                .unwrap_or(false)
        });
    
    match suricata_container {
        Some(container) => {
            let status = ContainerStatus {
                id: container.id.as_ref().unwrap_or(&"unknown".to_string()).clone(),
                name: container
                    .names
                    .as_ref()
                    .and_then(|n| n.first())
                    .map(|n| n.trim_start_matches('/').to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                status: container.status.as_ref().unwrap_or(&"unknown".to_string()).clone(),
                state: container.state.as_ref().unwrap_or(&"unknown".to_string()).clone(),
                running: container.state.as_ref().map(|s| s == "running").unwrap_or(false),
            };
            
            HttpResponse::Ok().json(ApiResponse {
                success: true,
                message: "Container status succesvol opgehaald".to_string(),
                data: Some(serde_json::to_value(status).unwrap()),
            })
        }
        None => HttpResponse::NotFound().json(ApiResponse {
            success: false,
            message: format!("Container '{}' niet gevonden", container_name),
            data: None,
        }),
    }
}

// Start de Suricata container
#[post("/api/suricata/start")]
async fn start_suricata(docker_client: web::Data<DockerClient>) -> impl Responder {
    let container_name = "suricata";
    
    match docker_client.docker.start_container::<String>(container_name, None).await {
        Ok(_) => HttpResponse::Ok().json(ApiResponse {
            success: true,
            message: format!("Container '{}' succesvol gestart", container_name),
            data: None,
        }),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: format!("Fout bij starten container: {}", e),
            data: None,
        }),
    }
}

// Stop de Suricata container
#[post("/api/suricata/stop")]
async fn stop_suricata(docker_client: web::Data<DockerClient>) -> impl Responder {
    let container_name = "suricata";
    
    let stop_options = StopContainerOptions {
        t: 10i64, // Timeout van 10 seconden
    };
    
    match docker_client
        .docker
        .stop_container(container_name, Some(stop_options))
        .await
    {
        Ok(_) => HttpResponse::Ok().json(ApiResponse {
            success: true,
            message: format!("Container '{}' succesvol gestopt", container_name),
            data: None,
        }),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: format!("Fout bij stoppen container: {}", e),
            data: None,
        }),
    }
}

// Herstart de Suricata container
#[post("/api/suricata/restart")]
async fn restart_suricata(docker_client: web::Data<DockerClient>) -> impl Responder {
    let container_name = "suricata";
    
    // Eerst stoppen
    let stop_options = StopContainerOptions {
        t: 10i64,
    };
    
    let stop_result = docker_client
        .docker
        .stop_container(container_name, Some(stop_options))
        .await;
    
    // Wacht even voordat we opnieuw starten
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    // Dan starten
    let start_result = docker_client
        .docker
        .start_container::<String>(container_name, None)
        .await;
    
    match (stop_result, start_result) {
        (Ok(_), Ok(_)) => HttpResponse::Ok().json(ApiResponse {
            success: true,
            message: format!("Container '{}' succesvol herstart", container_name),
            data: None,
        }),
        (Err(e), _) => HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: format!("Fout bij stoppen container: {}", e),
            data: None,
        }),
        (_, Err(e)) => HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: format!("Fout bij starten container: {}", e),
            data: None,
        }),
    }
}

// Voer een commando uit in de Suricata container
#[post("/api/suricata/exec")]
async fn execute_suricata_command(
    req_body: web::Json<ExecRequest>,
    docker_client: web::Data<DockerClient>,
) -> impl Responder {
    let container_name = "suricata";
    
    // Maak een exec instantie aan
    // Dit is nodig om commando's uit te voeren in een draaiende container
    let config = bollard::exec::CreateExecOptions {
        attach_stdout: Some(true),  // Capture stdout output
        attach_stderr: Some(true),   // Capture stderr output
        cmd: Some(
            vec![req_body.command.clone()]
                .into_iter()
                .chain(req_body.args.clone().into_iter())
                .collect(),
        ),
        ..Default::default()
    };
    
    let exec_instance = match docker_client
        .docker
        .create_exec(container_name, config)
        .await
    {
        Ok(exec) => exec.id,
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Fout bij aanmaken exec instantie: {}", e),
                data: None,
            });
        }
    };
    
    // Start de exec instantie
    let start_exec_options = bollard::exec::StartExecOptions {
        detach: false, // We willen de output direct zien
        ..Default::default()
    };
    
    let response = match docker_client
        .docker
        .start_exec(&exec_instance, Some(start_exec_options))
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Fout bij starten exec instantie: {}", e),
                data: None,
            });
        }
    };
    
    // Verzamel de output van het commando
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
        return HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: "Fout bij ophalen output van exec instantie".to_string(),
            data: None,
        });
    }
    
    HttpResponse::Ok().json(ApiResponse {
        success: true,
        message: "Commando succesvol uitgevoerd".to_string(),
        data: Some(serde_json::json!({
            "command": format!("{} {}", req_body.command, req_body.args.join(" ")),
            "stdout": stdout,
            "stderr": stderr,
        })),
    })
}

// Haal de logs op van de Suricata container
#[get("/api/suricata/logs")]
async fn get_logs(docker_client: web::Data<DockerClient>) -> impl Responder {
    let container_name = "suricata";
    
    // Configureer opties voor het ophalen van logs
    let log_options = bollard::container::LogsOptions::<String> {
        stdout: true,  // Include stdout logs
        stderr: true,   // Include stderr logs
        tail: "100".to_string(),    // Laatste 100 regels
        ..Default::default()
    };
    
    let mut logs = String::new();
    
    // Haal de logs op als een stream
    // De logs() methode retourneert direct een Stream, geen Future
    let mut stream = docker_client
        .docker
        .logs(container_name, Some(log_options));
    
    // Verwerk de stream
    while let Some(result) = stream.next().await {
        match result {
            Ok(msg) => {
                use bollard::container::LogOutput::*;
                match msg {
                    StdOut { message } => logs.push_str(&String::from_utf8_lossy(&message)),
                    StdErr { message } => logs.push_str(&String::from_utf8_lossy(&message)),
                    _ => {}
                }
            }
            Err(e) => {
                return HttpResponse::InternalServerError().json(ApiResponse {
                    success: false,
                    message: format!("Fout bij lezen logs stream: {}", e),
                    data: None,
                });
            }
        }
    }
    
    HttpResponse::Ok().json(ApiResponse {
        success: true,
        message: "Logs succesvol opgehaald".to_string(),
        data: Some(serde_json::json!({
            "logs": logs,
        })),
    })
}

// Hoofdfunctie - start de HTTP server
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Haal de listen address en port op uit environment variabelen
    // Standaard: 0.0.0.0:8080 (luistert op alle interfaces)
    let listen_address = env::var("LISTEN_ADDRESS").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_address = format!("{}:{}", listen_address, port);
    
    println!("Server wordt gestart op http://{}", bind_address);
    
    // Maak verbinding met de Docker daemon
    // In een Docker container gebruiken we de Unix socket (/var/run/docker.sock)
    // Dit is de standaard manier om te verbinden vanuit een container
    // We proberen eerst de Unix socket, en vallen terug op HTTP als dat niet werkt
    let docker = if std::path::Path::new("/var/run/docker.sock").exists() {
        // Unix socket bestaat, gebruik deze
        match Docker::connect_with_local("/var/run/docker.sock", 120, bollard::API_DEFAULT_VERSION) {
            Ok(docker) => {
                println!("Verbonden met Docker daemon via Unix socket");
                docker
            }
            Err(e) => {
                eprintln!("Fout bij verbinden met Docker daemon via socket: {}", e);
                eprintln!("Proberen alternatieve verbindingsmethode...");
                Docker::connect_with_http_defaults()
                    .expect("Fout bij verbinden met Docker daemon (fallback)")
            }
        }
    } else {
        // Unix socket bestaat niet, gebruik HTTP (voor lokale ontwikkeling)
        println!("Unix socket niet gevonden, gebruik HTTP verbinding");
        Docker::connect_with_http_defaults()
            .expect("Fout bij verbinden met Docker daemon via HTTP")
    };
    
    // Maak een gedeelde state aan voor de Docker client
    let docker_client = web::Data::new(DockerClient { docker });
    
    // Start de HTTP server met alle endpoints
    HttpServer::new(move || {
        // Configureer CORS om requests van de Angular frontend toe te staan
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials();
        
        App::new()
            .wrap(cors)
            .app_data(docker_client.clone())
            .service(root)
            .service(get_status)
            .service(start_suricata)
            .service(stop_suricata)
            .service(restart_suricata)
            .service(execute_suricata_command)
            .service(get_logs)
    })
    .bind(&bind_address)?
    .run()
    .await
}
