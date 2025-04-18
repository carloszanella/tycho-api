use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

// Define Axum-specific error types
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Simulation error: {0}")]
    SimulationError(String),

    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
}

// Implement IntoResponse for Axum
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::SimulationError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::InvalidArgument(msg) => (StatusCode::BAD_REQUEST, msg),
        };

        let body = Json(json!({
            "success": false,
            "error": error_message
        }));

        (status, body).into_response()
    }
}
