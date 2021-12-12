use std::f64;
use serde::{Serialize, Deserialize};
use ovz_derive::chain::evaluate_polynomial_at_index;

/// A client who can send and receive messages.
#[derive(Serialize, Deserialize, Debug)]
struct ChainClient {
    coefficient_set: Vec<f64>,
    next_x: f64,
}


/// A formatted message including an embedded changelog
#[derive(Serialize, Deserialize, Debug)]
struct ChainMessage {
    content: std::string::String,
    changelog: Vec<ovz_derive::chain::ChangeLogEntry>,
}

impl ChainClient {
    /// Create a ChainClient from a keymaster
    fn from_keymaster(keymaster: &ChainClient) -> ChainClient {
        ChainClient {
            coefficient_set: keymaster.coefficient_set.clone(),
            next_x: keymaster.next_x,
        }
    }

    /// Load an encrypted message and update he internal state
    fn load_message(&mut self, message: std::string::String) {
        let local_coefficient_set = self.coefficient_set.clone();
        let split_coefficient_set = ovz_derive::chain::split_coefficient_vector(local_coefficient_set.clone());
        let key = ovz_derive::crypto::get_key_from_coefficient_set(split_coefficient_set.clone(), self.next_x.clone());
        let nonce = ovz_derive::crypto::combine_to_nonce(ovz_derive::chain::evaluate_polynomial_at_index(
            split_coefficient_set[4].clone(), self.next_x.clone()),
                                                         ovz_derive::chain::evaluate_polynomial_at_index(split_coefficient_set[5].clone(),
                                                                                                         self.next_x.clone()));

        let decoded_message = base64::decode(&message).unwrap();
        let decrypted_message = ovz_derive::crypto::aes_decrypt(key.clone(), nonce.clone(), decoded_message);
        let message_content = std::string::String::from_utf8(decrypted_message).unwrap();
        let deserialized_message: ChainMessage = serde_json::from_str(&*message_content).unwrap();
        println!("Message: {:?}", deserialized_message.content);
        let mut local_next_x = evaluate_polynomial_at_index(split_coefficient_set[6].clone(), self.next_x.clone());

        if local_next_x.is_nan() || local_next_x.is_infinite() {
            local_next_x = 0.5f64;
        }
        if local_next_x >= 1.0 || local_next_x <= -1.0 {
            local_next_x = 1f64/local_next_x;
        }
        println!("New x: {}", local_next_x);
        self.next_x = local_next_x;

        let new_coefficient_set = ovz_derive::chain::apply_changelog(deserialized_message.changelog, local_coefficient_set);
        self.coefficient_set = new_coefficient_set;


    }

    /// Write an encrypted message including a ratchet
    fn write_message(&mut self, message: std::string::String) -> std::string::String{
        let local_coefficient_set = self.coefficient_set.clone();
        let split_coefficient_set = ovz_derive::chain::split_coefficient_vector(local_coefficient_set.clone());
        let key = ovz_derive::crypto::get_key_from_coefficient_set(split_coefficient_set.clone(), self.next_x.clone());
        let nonce = ovz_derive::crypto::combine_to_nonce(ovz_derive::chain::evaluate_polynomial_at_index(
            split_coefficient_set[4].clone(), self.next_x.clone()),
                                                         ovz_derive::chain::evaluate_polynomial_at_index(split_coefficient_set[5].clone(),
                                                                                                         self.next_x.clone()));

        let random_changelog = ovz_derive::chain::generate_changelog(local_coefficient_set.clone(), local_coefficient_set.len()/16, local_coefficient_set.len()/8);
        let serialized_message = serde_json::to_string(&ChainMessage {
            changelog: random_changelog,
            content: message,
        }).unwrap();
        let encrypted_message = ovz_derive::crypto::aes_encrypt(key.clone(), nonce.clone(), &*std::string::String::from(serialized_message).into_bytes());
        let encoded_message = base64::encode(&encrypted_message);
        encoded_message
    }
}

fn main() {
    let coefficients: Vec<f64> = ovz_derive::chain::generate_random_coefficient_set(1024, 8192);
    println!("Coefficients length: {}", coefficients.len());

    let mut keymaster = ChainClient {
        coefficient_set: coefficients,
        next_x: 0.0,
    };
    let mut client_1 = ChainClient::from_keymaster(&keymaster);
    let mut client_2 = ChainClient::from_keymaster(&keymaster);


    let message_1 = client_1.write_message("Round 1".to_string());
    client_1.load_message(message_1.clone());
    client_2.load_message(message_1.clone());
    keymaster.load_message(message_1.clone());
    let message_2 = client_2.write_message("Round 2".to_string());
    let coeffients_1 = client_1.coefficient_set.clone();
    client_1.load_message(message_2.clone());
    client_2.load_message(message_2.clone());
    keymaster.load_message(message_2.clone());
    println!("Coefficients match between rounds: {} SHOULD BE: false", (coeffients_1 == client_1.coefficient_set).to_string());
    let message_3 = client_1.write_message("Round 3".to_string());
    client_1.load_message(message_3.clone());
    client_2.load_message(message_3.clone());
    keymaster.load_message(message_3.clone());
    let coeffients_3 = client_1.coefficient_set.clone();

    let message_4 = client_2.write_message("Round 4".to_string());
    client_1.load_message(message_4.clone());
    client_2.load_message(message_4.clone());
    keymaster.load_message(message_4.clone());
    println!("Coefficients match between rounds: {} SHOULD BE: false", (coeffients_3 == client_1.coefficient_set).to_string());
    println!("Coefficients match at same round: {} SHOULD BE: true", (client_1.coefficient_set == client_2.coefficient_set).to_string());



}
