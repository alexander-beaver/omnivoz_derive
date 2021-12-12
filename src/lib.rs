
pub mod crypto{
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{Aead, NewAead};
    use crate::chain::evaluate_polynomial_at_index;

    pub fn convert_f64_to_bytes(f: f64) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&f.to_le_bytes());
        bytes
    }

    /// Generate a key given the coefficient sets
    /// Take in a vector of four vector of f64s and an x value (f64)
    /// Evaluate each of the coefficient sets at the given x value
    /// Combine the four sets of coefficients into a single key
    pub fn get_key_from_coefficient_set(coefficients: [Vec<f64>; 8], x: f64) -> [u8; 32] {
        let mut key = [0u8; 32];
        for i in 0..4 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&evaluate_polynomial_at_index(coefficients[i].clone(), x).to_le_bytes());
            key[i*8..(i+1)*8].copy_from_slice(&bytes);
        }
        key


    }

    /// Combine four arrays of 8 bytes into one array of bytes
    /// Returns an array of 256 bits for AES-256 key
    pub fn combine_to_key(a: [u8; 8], b: [u8; 8], c: [u8; 8], d: [u8; 8]) -> [u8; 32] {
        let mut combined = [0u8; 32];
        combined[0..8].copy_from_slice(&a);
        combined[8..16].copy_from_slice(&b);
        combined[16..24].copy_from_slice(&c);
        combined[24..32].copy_from_slice(&d);
        combined
    }

    /// Take two f64 values and combine them into a array of 12 bytes
    /// Returns an array of 96 bits for AES-256 nonce
    pub fn combine_to_nonce(a: f64, b: f64) -> [u8; 12] {
        let mut combined = [0u8; 16];
        combined[0..8].copy_from_slice(&convert_f64_to_bytes(a));
        combined[8..16].copy_from_slice(&convert_f64_to_bytes(b));

        let mut ret: [u8; 12] = [0u8; 12];
        ret.copy_from_slice(&combined[0..12]);

        ret.clone()
    }

    pub fn aes_encrypt(key: [u8; 32], nonce: [u8; 12], plaintext: &[u8]) -> Vec<u8> {
      let local_key = Key::from_slice(&key);
      let local_nonce = Nonce::from_slice(&nonce);
        let cipher = Aes256Gcm::new(local_key);
        let ciphertext = cipher.encrypt(local_nonce, plaintext).expect("Encryption failed");
        ciphertext
    }

    pub fn aes_decrypt(key: [u8; 32], nonce: [u8; 12], ciphertext: Vec<u8>) -> Vec<u8> {
      let local_key = Key::from_slice(&key);
      let local_nonce = Nonce::from_slice(&nonce);
        let cipher = Aes256Gcm::new(local_key);
        let plaintext = cipher.decrypt(local_nonce, ciphertext.as_ref()).expect("Decryption failed");
        plaintext
    }

}

/// chain contains all code responsible for manipulating the chain
pub mod chain{

    use std::fmt::{Debug};
    use rand::distributions::{Distribution, Uniform};
    use rand::Rng;
    use serde::{Serialize, Deserialize};


    /// A specific action that a changelog entry can perform
    #[derive(Serialize, Deserialize, Debug)]
    pub enum ChangeLogAction{
        Insert,
        Remove,
        Update,
    }

    /// A single modification made to the changelog
    #[derive(Serialize, Deserialize, Debug)]
    pub struct ChangeLogEntry{
        pub action: ChangeLogAction,
        pub index: usize,
        pub value: f64,
    }

    /// Take a vector of ChangeLogEntry and a vector of f64 coefficients, and apply the changes to the coefficients
    pub fn apply_changelog(changelog: Vec<ChangeLogEntry>, coefficients: Vec<f64>) -> Vec<f64>{
        let mut new_coefficients = coefficients.clone();
        for entry in changelog {
            if entry.index < new_coefficients.len() {
                match entry.action {
                    ChangeLogAction::Insert => {
                        new_coefficients.insert(entry.index, entry.value);
                    },
                    ChangeLogAction::Remove => {
                        new_coefficients.remove(entry.index);
                    },
                    ChangeLogAction::Update => {
                        new_coefficients[entry.index] = entry.value;
                    },
                }
            }
        }


        return new_coefficients.clone();
    }

    /// Generate a random changelog entry
    fn generate_changelog_entry(coefficients: Vec<f64>) -> ChangeLogEntry{
        let mut rng = rand::thread_rng();
        let distribution = Uniform::from(0..coefficients.len());
        let index = distribution.sample(&mut rng);
        let mut rng = rand::thread_rng();
        let distribution = Uniform::from(-1.0..1.0);
        let value = distribution.sample(&mut rng);
        let mut rng = rand::thread_rng();
        let distribution = Uniform::from(0..3);
        let action = distribution.sample(&mut rng);
        let action = match action {
            0 => ChangeLogAction::Insert,
            1 => ChangeLogAction::Remove,
            2 => ChangeLogAction::Update,
            _ => ChangeLogAction::Update,
        };

        return ChangeLogEntry{
            action,
            index,
            value,
        };
    }

    /// Generate a random changelog given a min and max number of entries
    pub fn generate_changelog(coefficients: Vec<f64>, min_num_entries: usize, max_num_entries: usize)->Vec<ChangeLogEntry>{
        let mut local_coefficients = coefficients.clone();
        let mut rng = rand::thread_rng();
        let distribution = Uniform::from(min_num_entries..max_num_entries);
        let num_entries = distribution.sample(&mut rng);
        let mut changelog = Vec::new();
        for _ in 0..num_entries {
            let entry = generate_changelog_entry(local_coefficients.clone());
            local_coefficients = apply_changelog(vec![entry.clone()], local_coefficients);
            changelog.push(entry);
        }

        return changelog;
    }

    /// Take a vector of f64, split it into eight vectors of f64, and return the eight vectors
    ///
    /// The vectors are configured to contribute as follows:
    /// 0..3: key curves
    /// 4..5: nonce
    /// 6   : next x
    /// 7   : open for future use (potentially next database IDs)
    pub fn split_coefficient_vector(coefficients: Vec<f64>)->[Vec<f64>;8]{
        let mut result = [Vec::new(),Vec::new(),Vec::new(),Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        for i in 0..coefficients.len(){
            result[i%8].push(coefficients[i]);
        }
        return result.clone();
    }

    /// Evaluate a polynomial at a given x value, and return the result
    pub fn evaluate_polynomial_at_index(coefficients: Vec<f64>, x: f64) -> f64{
        let mut res:f64 = 0.0;
        for i in 0..coefficients.len() {
            let dyn_i = &i;
            let coef = coefficients.get(i);
            match coef{
                None => {println!("Invalid Coefficient")}
                Some(p) => {res = res + p * x.powf((coefficients.len()-*dyn_i - 1) as f64)}
            }
        }
        return res.clone();
    }

    /// Generate a vector of random length between min and max of f64 values whereby -1<= x < 1
    pub fn generate_random_coefficient_set(min_len: usize, max_len: usize) -> Vec<f64>{
        let mut result = Vec::new();
        let mut rng = rand::thread_rng();


        // Use this because more efficient than using rand::thread_rng()

        let die = Uniform::from(-1.0..1.0);

        for _ in 0..rng.gen_range(min_len..max_len){
            result.push(die.sample(&mut rng));
        }
        return result.clone();
    }

    //////////////////////////////////////////////////////////////////////////////////////
    // Utilities                                                                        //
    //////////////////////////////////////////////////////////////////////////////////////

    impl Clone for ChangeLogEntry{
        fn clone(&self) -> ChangeLogEntry{
            return ChangeLogEntry{
                action: self.action.clone(),
                index: self.index.clone(),
                value: self.value.clone(),
            };
        }
    }

    impl Clone for ChangeLogAction{
        fn clone(&self) -> ChangeLogAction{
            return match self {
                ChangeLogAction::Insert => ChangeLogAction::Insert,
                ChangeLogAction::Remove => ChangeLogAction::Remove,
                ChangeLogAction::Update => ChangeLogAction::Update,
            };
        }
    }



}
