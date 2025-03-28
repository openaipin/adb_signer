use serde::Serialize;
use worker::Response;

#[derive(Serialize)]
pub struct SignResponse {
    pub token: String,
    pub public_key: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    error: String,
}

impl ErrorResponse {
    pub fn new(error: &str, status_code: u16) -> Response {
        match Response::from_json(&ErrorResponse {
            error: error.to_string(),
        }) {
            Ok(response) => response.with_status(status_code),
            Err(_) => Response::error(format!("Failed to serialize error: {error}"), 500).unwrap(),
        }
    }
}
