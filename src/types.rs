use serde::Serialize;

#[derive(Serialize)]
pub struct SignResponse {
    pub token: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
