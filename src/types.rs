use serde::Serialize;

#[derive(Serialize)]
pub struct SignResponse {
    pub token: String,
    pub public_key: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
