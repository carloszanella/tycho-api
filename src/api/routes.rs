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
    tracing::info!("Received simulate request for sell_token: {}, pools: {:?}, amount: {}", 
        request.sell_token, request.pools, request.amount);
    
    // Parse amount
    let input_amount = request.amount;

    let mut current_amount = None;
    let mut total_gas = BigUint::from(0u64);
    let mut next_sell_token = request.sell_token;
    let mut decimals = 0;

    for (index, pool_address) in request.pools.iter().enumerate() {
        tracing::info!("Processing pool {}/{}: {}", index + 1, request.pools.len(), pool_address);
        let (component, pool_state) = state.get_pool_state(pool_address).await;
        tracing::info!("Pool lookup results - found component: {}, found pool state: {}", 
            component.is_some(), pool_state.is_some());

        match pool_state {
            Some(pool) => {
                let sell_token;
                let buy_token;
                match component {
                    Some(component) => {
                        if component.tokens[0].address.to_string().to_lowercase() == next_sell_token.to_lowercase() {
                            sell_token = component.tokens[0].clone();
                            buy_token = component.tokens[1].clone();
                            tracing::info!("Using token0 as sell token: {} (decimals: {})", 
                                sell_token.address.to_string(), sell_token.decimals);
                            tracing::info!("Using token1 as buy token: {} (decimals: {})", 
                                buy_token.address.to_string(), buy_token.decimals);
                        } else {
                            sell_token = component.tokens[1].clone();
                            buy_token = component.tokens[0].clone();
                            tracing::info!("Using token1 as sell token: {} (decimals: {})", 
                                sell_token.address.to_string(), sell_token.decimals);
                            tracing::info!("Using token0 as buy token: {} (decimals: {})", 
                                buy_token.address.to_string(), buy_token.decimals);
                        }
                    }
                    None => {
                        let err_msg = format!("Component not found: {}", pool_address);
                        tracing::error!("{}", err_msg);
                        return Err(ApiError::NotFound(err_msg));
                    }
                }
                if current_amount.is_none() {
                    let raw_amount = (input_amount * 10f64.powi(sell_token.decimals as i32)) as u64;
                    current_amount = Some(BigUint::from(raw_amount));
                    tracing::info!("Initial input amount: {} {} (raw: {})", 
                        input_amount, sell_token.address.to_string(), raw_amount);
                }
                
                tracing::info!("Calling get_amount_out with input: {}", current_amount.as_ref().unwrap());
                let result = pool
                    .get_amount_out(current_amount.unwrap(), &sell_token, &buy_token)
                    .map_err(|e| {
                        let err_msg = format!("Simulation error: {}", e);
                        tracing::error!("{}", err_msg);
                        ApiError::SimulationError(err_msg)
                    })?;

                // Assuming result is a tuple of (amount_out, gas)
                tracing::info!("Got amount_out: {}, gas: {}", result.amount, result.gas);
                current_amount = Some(result.amount);
                total_gas += result.gas;
                next_sell_token = buy_token.address.to_string();
                decimals = buy_token.decimals;
            }
            None => {
                let err_msg = format!("Pool not found: {}", pool_address);
                tracing::error!("{}", err_msg);
                return Err(ApiError::NotFound(err_msg));
            }
        }
    }

    let amount_out: f64 = current_amount
        .ok_or_else(|| {
            let err_msg = "No output amount calculated";
            tracing::error!("{}", err_msg);
            ApiError::SimulationError(err_msg.to_string())
        })?
        .to_string()
        .parse::<f64>()
        .unwrap_or(0.0)
        / 10f64.powi(decimals as i32);

    tracing::info!("Simulation complete - input_amount: {}, output_amount: {}, gas_estimate: {}", 
        request.amount, amount_out, total_gas);
        
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
    max_input: String, 
    max_output: String
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
    
    // Get component for token info
    let component = match component {
        Some(c) => {
            tracing::info!("Found component for {}", request.pool_address);
            c
        },
        None => {
            let err_msg = format!("Component not found: {}", request.pool_address);
            tracing::error!("{}", err_msg);
            return Err(ApiError::NotFound(err_msg));
        }
    };
    
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
    
    // Find token decimal information from component
    let (sell_token_decimals, buy_token_decimals) = {
        let mut sell_decimals = None;
        let mut buy_decimals = None;
        
        for token in &component.tokens {
            let token_addr_str = token.address.to_string().to_lowercase();
            let sell_addr_str = sell_token_address.to_string().to_lowercase();
            let buy_addr_str = buy_token_address.to_string().to_lowercase();
            
            tracing::info!("Comparing token: {}, with sell_token: {}", token_addr_str, sell_addr_str);
            
            if token_addr_str == sell_addr_str {
                tracing::info!("Found matching sell token with decimals: {}", token.decimals);
                sell_decimals = Some(token.decimals);
            } else if token_addr_str == buy_addr_str {
                tracing::info!("Found matching buy token with decimals: {}", token.decimals);
                buy_decimals = Some(token.decimals);
            }
        }
        
        let sell_decimals = sell_decimals.ok_or_else(|| {
            let err_msg = format!("Sell token not found in component: {}", request.sell_token);
            tracing::error!("{}", err_msg);
            ApiError::NotFound(err_msg)
        })?;
        
        let buy_decimals = buy_decimals.ok_or_else(|| {
            let err_msg = format!("Buy token not found in component: {}", request.buy_token);
            tracing::error!("{}", err_msg);
            ApiError::NotFound(err_msg)
        })?;
        
        (sell_decimals, buy_decimals)
    };
    
    // Get limits from the pool
    tracing::info!("Calling get_limits on pool");
    let limits_result = pool.get_limits(sell_token_address, buy_token_address);
    
    match limits_result {
        Ok((max_input, max_output)) => {
            tracing::info!("Successfully got limits: max_input={}, max_output={}", max_input, max_output);
            
            // Convert to human-readable form by dividing by their respective decimals
            let max_input_float = max_input.to_string().parse::<f64>().unwrap_or(0.0) 
                / 10f64.powi(sell_token_decimals as i32);
            let max_output_float = max_output.to_string().parse::<f64>().unwrap_or(0.0) 
                / 10f64.powi(buy_token_decimals as i32);
            
            tracing::error!("sell_token_decimals: {}, sell_token_address: {}", sell_token_decimals, sell_token_address);
            tracing::error!("buy_token_decimals: {}, buy_token_address: {}", buy_token_decimals, buy_token_address);
            Ok(Json(LimitsResponse {
                success: true,
                max_input: max_input_float.to_string(),
                max_output: max_output_float.to_string(),
            }))
        },
        Err(e) => {
            let err_msg = format!("Error getting limits: {}", e);
            tracing::error!("{}", err_msg);
            Err(ApiError::SimulationError(err_msg))
        }
    }
}
