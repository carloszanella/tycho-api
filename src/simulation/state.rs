use serde::Serialize;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{broadcast, RwLock};
use tycho_simulation::{
    models::Token,
    protocol::{
        models::{BlockUpdate, ProtocolComponent},
        state::ProtocolSim,
    },
};

/// Represents the current state of the simulation
#[derive(Debug, Clone)]
pub struct SimulationState {
    states: Arc<RwLock<HashMap<String, Box<dyn ProtocolSim>>>>,
    components: Arc<RwLock<HashMap<String, ProtocolComponent>>>,
    current_block: u64,
    // A broadcast channel to notify listeners of new updates
    updates: broadcast::Sender<ClientUpdate>,
}

// Define your custom update struct
#[derive(Serialize, Clone)]
pub struct ClientUpdate {
    pub block_number: u64,
    pub new_pairs: HashMap<String, ProtocolComponent>,
    pub spot_prices: HashMap<String, f64>,
    pub tvl_updates: HashMap<String, f64>,
}

impl From<BlockUpdate> for ClientUpdate {
    fn from(update: BlockUpdate) -> Self {
        // Extract spot prices from states
        let spot_prices = HashMap::new();
        let mut tvl_updates = HashMap::new();
        for address in update.states.keys() {
            tvl_updates.insert(address.clone(), 0 as f64);
        }

        ClientUpdate {
            block_number: update.block_number,
            new_pairs: update.new_pairs,
            spot_prices,
            tvl_updates,
        }
    }
}

impl SimulationState {
    pub fn new() -> Self {
        // Create a channel with a maximum buffer size of 100 messages
        let (tx, _) = broadcast::channel(100);

        SimulationState {
            states: Arc::new(RwLock::new(HashMap::new())),
            components: Arc::new(RwLock::new(HashMap::new())),
            current_block: 0,
            updates: tx,
        }
    }

    /// Update the state with a new block update
    pub async fn update(&self, update: BlockUpdate) {
        // Add the update to our storage
        {
            self.states.write().await.extend(update.states.clone());
            self.components
                .write()
                .await
                .extend(update.new_pairs.clone());
        }

        let mut spot_prices = HashMap::new();
        for (addr, state) in update.states.clone() {
            if let Some(tokens) = self.get_tokens(&addr).await {
                let spot_price = state.spot_price(&tokens[0], &tokens[1]).unwrap();
                spot_prices.insert(addr.clone(), spot_price);
            }
        }

        // Create the update message with the calculated spot prices
        let mut update_msg = ClientUpdate::from(update);
        update_msg.spot_prices = spot_prices;

        // Broadcast the update to all subscribers
        let _ = self.updates.send(update_msg);
    }

    pub async fn get_tokens(&self, address: &str) -> Option<Vec<Token>> {
        self.components
            .read()
            .await
            .get(address)
            .map(|c| c.tokens.clone())
    }

    /// Method to get pool state for simulation
    pub async fn get_pool_state(
        &self,
        address: &str,
    ) -> (Option<ProtocolComponent>, Option<Box<dyn ProtocolSim>>) {
        let pool_state = self.states.read().await.get(address).cloned();
        let component = self.components.read().await.get(address).cloned();
        (component, pool_state)
    }

    pub async fn get_full_state(&self) -> ClientUpdate {
        let all_states = self.states.read().await.clone();
        let mut spot_prices = HashMap::new();
        for (addr, state) in all_states {
            if let Some(tokens) = self.get_tokens(&addr).await {
                let spot_price = state.spot_price(&tokens[0], &tokens[1]).unwrap();
                spot_prices.insert(addr.clone(), spot_price);
            }
        }
        return ClientUpdate {
            block_number: self.current_block,
            new_pairs: self.components.read().await.clone(),
            spot_prices,
            tvl_updates: HashMap::new(),
        };
    }

    /// Subscribe to receive all future block updates
    pub fn subscribe_to_updates(&self) -> broadcast::Receiver<ClientUpdate> {
        self.updates.subscribe()
    }
}

impl Default for SimulationState {
    fn default() -> Self {
        Self::new()
    }
}
