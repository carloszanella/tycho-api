use axum::{
    extract::{State, WebSocketUpgrade},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast;
use tracing::{error, info};

use crate::simulation::state::SimulationState;

pub async fn ws_handler(
    State(state): State<SimulationState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(|websocket| handle_socket(websocket, state))
}

async fn handle_socket(websocket: axum::extract::ws::WebSocket, state: SimulationState) {
    info!("New WebSocket connection established");

    // Split the socket into sender and receiver
    let (mut sender, mut receiver) = websocket.split();

    // Subscribe to simulation updates
    let mut update_rx = state.subscribe_to_updates();

    // Create a channel to signal connection closure
    let (close_tx, close_rx) = tokio::sync::oneshot::channel();

    // Send current state immediately when a client connects
    let latest_block = state.get_full_state().await;
    if let Ok(msg) = serde_json::to_string(&latest_block) {
        if let Err(e) = sender.send(axum::extract::ws::Message::Text(msg)).await {
            error!("Error sending initial state: {}", e);
            return;
        }
    }

    // Spawn a task to handle sending updates to the client
    let send_task = tokio::spawn(async move {
        let mut close_rx = close_rx;
        
        loop {
            tokio::select! {
                // Check if we should stop sending (connection closed)
                _ = &mut close_rx => {
                    info!("Send task shutting down due to connection closure");
                    break;
                }
                update_result = update_rx.recv() => {
                    // Receive the next update from the broadcast channel
                    let update = match update_result {
                        Ok(update) => update,
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("Update channel closed");
                            break;
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            error!("Client lagging behind, skipped {} messages", skipped);
                            continue;
                        }
                    };

                    // Serialize the update to send to the client
                    let msg = match serde_json::to_string(&update) {
                        Ok(msg) => msg,
                        Err(e) => {
                            error!("Error serializing update: {}", e);
                            continue;
                        }
                    };

                    // Send the update to the client
                    if let Err(e) = sender.send(axum::extract::ws::Message::Text(msg)).await {
                        error!("Error sending message: {}", e);
                        break;
                    }
                }
            }
        }
    });

    // Handle messages from the client
    let receive_task = tokio::spawn(async move {
        let close_tx = close_tx;
        
        while let Some(result) = receiver.next().await {
            match result {
                Ok(axum::extract::ws::Message::Text(text)) => {
                    info!("Received message: {}", text);

                    // Here you could handle client requests
                    // For example, client could request historical data
                }
                Ok(axum::extract::ws::Message::Close(_)) => {
                    info!("Client initiated close");
                    let _ = close_tx.send(());
                    break;
                }
                // Also handle connection errors
                Err(_) => {
                    info!("Connection error");
                    let _ = close_tx.send(());
                    break;
                }
                _ => {}
            }
        }
        
        // If we got here without matching a close frame, the connection was dropped
        info!("Client disconnected");
    });

    // Wait for either task to finish
    tokio::select! {
        _ = send_task => info!("Send task completed"),
        _ = receive_task => info!("Receive task completed"),
    }

    info!("WebSocket connection closed");
}
