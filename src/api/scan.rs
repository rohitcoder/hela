use actix_web::{post, web, HttpResponse, Responder};
use mongodb::bson::document;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::api::connection;

#[derive(Debug, Deserialize)]
struct ScanRequest {
    scan_type: String,
    git_url: String,
}

#[derive(Debug, Serialize)]
struct ScanResponse {
    id: String,
    scan_type: String,
    git_url: String,
}

pub fn config(cfg: & mut actix_web::web::ServiceConfig) {
    cfg.service(create_scan);
}

#[post("/scans")]
async fn create_scan(scan_request: web::Json<ScanRequest>) -> impl Responder {
    let database = connection::MyDatabase::new().await.expect("Failed to connect to MongoDB");
    println!("Running create_scan function");
    let scan_type = scan_request.scan_type.clone();
    let git_url = scan_request.git_url.clone();
    let id = "1234".to_string();
    
    let response = ScanResponse {
        id,
        scan_type: scan_type,
        git_url: git_url,
    };

    let collection_name = "my_collection";
    let document = json!(response);
    // convert to Document and insert into collection
    let document = mongodb::bson::to_document(&document).expect("Failed to convert to BSON");
    connection::MyDatabase::insert(&database, collection_name, document).await.expect("Failed to insert document into MongoDB");
    HttpResponse::Ok().json(response)
}
