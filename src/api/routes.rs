use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::json;
use alloy_primitives::Address;
use std::str::FromStr;

use crate::errors::ApiError;
use crate::simulation::state::SimulationState;

use super::ws::ws_handler;

pub fn get_routes(state: SimulationState) -> Router {
    Router::new()
        .route("/", get(health_check))
        .route("/api/simulate", post(simulate_transaction))
        .route("/api/limits", post(get_limits))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "simulation-api",
    }))
}

#[derive(Debug, Deserialize)]
struct SimulationRequest {
    sell_token: String,
    pools: Vec<String>,
    amount: f64,
}

#[derive(Debug, Serialize)]
struct SimulationResponse {
    success: bool,
    input_amount: f64,
    output_amount: f64,
    gas_estimate: BigUint,
}

// Use Result with your existing ApiError
async fn simulate_transaction(
    State(state): State<SimulationState>,
    Json(request): Json<SimulationRequest>,
) -> Result<Json<SimulationResponse>, ApiError> {
    // Parse amount
    let input_amount = request.amount;

    let mut current_amount = None;
    let mut total_gas = BigUint::from(0u64);
    let mut next_sell_token = request.sell_token;
    let mut decimals = 0;

    for pool_address in request.pools.iter() {
        let (component, pool_state) = state.get_pool_state(pool_address).await;

        match pool_state {
            Some(pool) => {
                let sell_token;
                let buy_token;
                match component {
                    Some(component) => {
                        if component.tokens[0].address.to_string() == next_sell_token {
                            sell_token = component.tokens[0].clone();
                            buy_token = component.tokens[1].clone();
                        } else {
                            sell_token = component.tokens[1].clone();
                            buy_token = component.tokens[0].clone();
                        }
                    }
                    None => {
                        return Err(ApiError::NotFound(format!(
                            "Component not found: {}",
                            pool_address
                        )));
                    }
                }
                if current_amount.is_none() {
                    current_amount = Some(BigUint::from(
                        (input_amount * 10f64.powi(sell_token.decimals as i32)) as u64,
                    ));
                }
                let result = pool
                    .get_amount_out(current_amount.unwrap(), &sell_token, &buy_token)
                    .map_err(|e| ApiError::SimulationError(format!("Simulation error: {}", e)))?;

                // Assuming result is a tuple of (amount_out, gas)
                current_amount = Some(result.amount);
                total_gas += result.gas;
                next_sell_token = buy_token.address.to_string();
                decimals = buy_token.decimals;
            }
            None => {
                return Err(ApiError::NotFound(format!(
                    "Pool not found: {}",
                    pool_address
                )));
            }
        }
    }

    let amount_out: f64 = current_amount
        .ok_or_else(|| ApiError::SimulationError("No output amount calculated".to_string()))?
        .to_string()
        .parse::<f64>()
        .unwrap_or(0.0)
        / 10f64.powi(decimals as i32);

    Ok(Json(SimulationResponse {
        success: true,
        input_amount: request.amount,
        output_amount: amount_out,
        gas_estimate: total_gas,
    }))
}

#[derive(Debug, Deserialize)]
struct LimitsRequest {
    pool_address: String,
    sell_token: String,
    buy_token: String,
}

#[derive(Debug, Serialize)]
struct LimitsResponse {
    success: bool,
    min_amount: String,
    max_amount: String,
}

async fn get_limits(
    State(state): State<SimulationState>,
    Json(request): Json<LimitsRequest>,
) -> Result<Json<LimitsResponse>, ApiError> {
    tracing::info!("Received get_limits request for pool: {}, sell_token: {}, buy_token: {}", 
        request.pool_address, request.sell_token, request.buy_token);
    
    let (component, pool_state) = state.get_pool_state(&request.pool_address).await;
    tracing::info!("Pool lookup results - found component: {}, found pool state: {}", 
        component.is_some(), pool_state.is_some());
    
    let pool = match pool_state {
        Some(p) => {
            tracing::info!("Found pool state for {}", request.pool_address);
            p
        },
        None => {
            let err_msg = format!("Pool not found: {}", request.pool_address);
            tracing::error!("{}", err_msg);
            return Err(ApiError::NotFound(err_msg));
        }
    };
    
    // Parse addresses to alloy_primitives::Address format
    tracing::info!("Attempting to parse sell token address: {}", request.sell_token);
    let sell_token_address = match Address::from_str(&request.sell_token) {
        Ok(addr) => {
            tracing::info!("Successfully parsed sell token address");
            addr
        },
        Err(e) => {
            let err_msg = format!("Invalid sell token address format: {}. Ensure it's a valid Ethereum address (0x followed by 40 hex chars)", request.sell_token);
            tracing::error!("{}: {:?}", err_msg, e);
            return Err(ApiError::InvalidArgument(err_msg));
        }
    };
    
    tracing::info!("Attempting to parse buy token address: {}", request.buy_token);
    let buy_token_address = match Address::from_str(&request.buy_token) {
        Ok(addr) => {
            tracing::info!("Successfully parsed buy token address");
            addr
        },
        Err(e) => {
            let err_msg = format!("Invalid buy token address format: {}. Ensure it's a valid Ethereum address (0x followed by 40 hex chars)", request.buy_token);
            tracing::error!("{}: {:?}", err_msg, e);
            return Err(ApiError::InvalidArgument(err_msg));
        }
    };
    
    // Get limits from the pool
    tracing::info!("Calling get_limits on pool");
    let limits_result = pool.get_limits(sell_token_address, buy_token_address);
    
    match limits_result {
        Ok((min, max)) => {
            tracing::info!("Successfully got limits: min={}, max={}", min, max);
            Ok(Json(LimitsResponse {
                success: true,
                min_amount: min.to_string(),
                max_amount: max.to_string(),
            }))
        },
        Err(e) => {
            let err_msg = format!("Error getting limits: {}", e);
            tracing::error!("{}", err_msg);
            Err(ApiError::SimulationError(err_msg))
        }
    }
}
