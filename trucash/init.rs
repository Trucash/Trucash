use database;
use crypto;
use error::SuperError;

extern crate curve25519_dalek;
use self::curve25519_dalek::{ 	constants, scalar::Scalar,
								ristretto::{ RistrettoPoint, CompressedRistretto }
							};

/// Initializes the chain with a genesis hash
/// and an original coinbase utxo
pub fn init_chain() -> Result<bool, SuperError> {
	/// Set the chain params 
	let difficulty: [u8; 32] = [0;32];
	let prev_hash: [u8; 32] = [0;32];

	/// Initial utxo
	let intial_receiver: [u8; 32] = [0;32]; //Todo
	//init_utxo(&mut intial_receiver.to_vec())?;

	return Ok(true);
}

/// Create the first utxo
pub fn init_utxo(receiver: RistrettoPoint) -> Result<bool, SuperError> {
	/// Need to generate pedersen commitment
	/// With the blinding factor as a common known scalar
	/// Which is 0x01 padded with 32 bytes

	/// First generate a common keypair (0x01 padded with 32 bytes)
	/// This keypair will act as the tx pubkey as well as the 
	/// blinding key for the pedersen commitment
	let (private_key, public_key) = crypto::generate_scalar_one_keypair();

	/// Generate the pedersen commitment
	let mut pedersen_commitment = crypto::generate_pedersen(1_000_000u64, &private_key)?.to_vec();

	/// Generate the diffie-hellman public key
	/// This is the shared secret between the reciever and the
	/// network (because its scalar is just 0x01 padded with 32 bytes)
	let mut diffie_hellman_key = (private_key * receiver).compress();

	/// Serialize the diffie-hellman key into a scalar so that
	/// its ready to be added/subtracted to and can
	/// encrypt amounts etc.
	let diffie_hellman_serialized = Scalar::from_bytes_mod_order(diffie_hellman_key.to_bytes());

	/// The amount we want to mask
	let amount: Scalar = 1_000_000u64.into();
	
	/// Mask the amount/blinding key by adding to it to the serialized
	/// diffie-hellman key. This can be reversed by anyone
	/// who knows the diffie-hellman key secret. To caluclate, all one has
	/// to do is, 
	/// 1) secret = Scalar::from_bytes_mod_order(private_key_receiver * public_key.compress().to_bytes());
	/// 2) masked_amount - secret = amount;
	let masked_amount = diffie_hellman_serialized + amount;
	let masked_blinding_factor = diffie_hellman_serialized + private_key;

	/// Construct the intial utxo byte vector for storing in the database
	/// > reciever [32 bytes]
	/// > pedersen_commitment [32 bytes]
	/// > masked_blinding_factor [32 bytes]
	/// > masked_amount [32 bytes]
	let mut utxo: Vec<u8> = Vec::new();
	utxo.append(&mut receiver.compress().to_bytes().to_vec());
	utxo.append(&mut pedersen_commitment);
	utxo.append(&mut masked_blinding_factor.to_bytes().to_vec());
	utxo.append(&mut masked_amount.to_bytes().to_vec());

	// Write the utxo into the database


	return Ok(true);
}