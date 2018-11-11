use database;
use crypto;
use error::SuperError;

/// Initializes the chain with a genesis hash
/// and an original coinbase utxo
pub fn init_chain() -> Result<bool, SuperError> {
	/// Set the chain params 
	let difficulty: [u8; 32] = [0;32];
	let prev_hash: [u8; 32] = [0;32];

	/// Initial utxo
	let intial_receiver: [u8; 32] = [0;32]; //Todo
	init_utxo(&mut intial_receiver.to_vec())?;

	return Ok(true);
}

/// Create the first utxo
fn init_utxo(receiver: &mut Vec<u8>) -> Result<bool, SuperError> {
	/// Need to generate pedersen commitment
	/// With the blinding factor as a common known scalar
	/// Which is 0x01 padded with 32 bytes
	let mut pedersen_commitment = crypto::generate_known_pedersen(100)?.to_vec();

	/// Construct the intial utxo byte vector
	/// > reciever [32 bytes]
	/// > pedersen_commitment [32 bytes]
	let mut utxo: Vec<u8> = Vec::new();
	utxo.append(receiver);
	utxo.append(&mut pedersen_commitment);

	// Write the utxo into the database
	

	return Ok(true);
}