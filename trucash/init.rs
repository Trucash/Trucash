use database;
use crypto;
use error::SuperError;

extern crate curve25519_dalek;
use self::curve25519_dalek::{ 	constants, scalar::Scalar,
								ristretto::{ RistrettoPoint, CompressedRistretto }
							};

extern crate byteorder;
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt, BigEndian, ByteOrder};

/// Initializes the chain with a genesis hash,
/// difficulty, and an original coinbase utxo
pub fn init_chain() -> Result<bool, SuperError> {
	/// Set the chain params 
	let difficulty: [u8; 32] = [254;32];
	let prev_hash: [u8; 32] = [0;32];

	database::write_chain_params_db(vec![0,0], vec![1]);
	database::write_chain_params_db(vec![0,1], vec![0,0,0,0,0,0,0,0]);
	database::write_chain_params_db(vec![0,2], difficulty.to_vec());
	database::write_chain_params_db(vec![0,3], prev_hash.to_vec());

	/// Initial utxo
	let (intial_receiver_raw_address1, intial_receiver_raw_address2) = ([222, 239, 177, 184, 14, 231, 248, 119, 169, 130, 170, 244, 181, 193, 22, 62, 86, 213, 98, 124, 51, 78, 70, 157, 75, 79, 132, 5, 71, 65, 14, 111], [254, 83, 66, 243, 220, 113, 105, 66, 180, 206, 111, 227, 225, 128, 249, 4, 105, 123, 192, 242, 154, 6, 13, 178, 3, 191, 36, 175, 76, 93, 11, 95]);
	let intial_receiver = [CompressedRistretto(intial_receiver_raw_address1), CompressedRistretto(intial_receiver_raw_address2)];
	init_utxo(&intial_receiver)?;

	return Ok(true);
}

/// Create the first utxo;
/// receiver = inputted pub key
/// pedersen_commitment = (0x01 * G) + (1_000_000 * H)
/// mask_blinding = 0x01 * G + 0x01
/// mask_amount = 0x01 * G + 1_000_000
/// tx_pub_key = 0x01 * G
pub fn init_utxo(receiver: &[CompressedRistretto]) -> Result<bool, SuperError> {
	/// First generate a common keypair (0x01 padded with 32 bytes)
	/// This keypair will act as the tx pubkey as well as the 
	/// blinding key for the pedersen commitment
	let (private_key, public_key) = crypto::generate_scalar_one_keypair();

	let mut pedersen_commitment = crypto::generate_pedersen(1_000_000u64, private_key.clone()).compress()
																							  .to_bytes()
																							  .to_vec();

	/// Generate the diffie-hellman public key
	/// This is the shared secret between the reciever and the
	/// network (because its scalar is just 0x01 padded with 32 bytes)
	let mut diffie_hellman_key = crypto::create_diffie_hellman(private_key, receiver[0]);

	/// Serialize the diffie-hellman key into a scalar so that
	/// its ready to be added/subtracted to and can
	/// encrypt amounts etc.
	let diffie_hellman_serialized = Scalar::from_bytes_mod_order(diffie_hellman_key.to_bytes());

	let amount: Scalar = 1_000_000u64.into();
	
	/// Mask the amount/blinding key by adding to it to the serialized
	/// diffie-hellman key. This can be reversed by anyone
	/// who knows the diffie-hellman key secret. To caluclate, all one has
	/// to do is, 
	/// 1) secret = Scalar::from_bytes_mod_order((private_key_receiver * public_key).compress().to_bytes());
	/// 2a) masked_amount - (secret * secret) = amount;
	/// 2b) masked_amount - secret = private_key;
	let masked_amount = (diffie_hellman_serialized * diffie_hellman_serialized) + amount;
	let masked_blinding_factor = diffie_hellman_serialized + private_key;

	let stealth_address: CompressedRistretto = crypto::generate_stealth_address(receiver, private_key);

	/// Construct the intial utxo byte vector for storing in the database
	/// > reciever [32 bytes]
	/// > pedersen_commitment [32 bytes]
	/// > masked_blinding_factor [32 bytes]
	/// > masked_amount [32 bytes]
	/// > public_key [32 bytes]
	let mut utxo: Vec<u8> = Vec::new();
	utxo.append(&mut stealth_address.to_bytes().to_vec()); //0..32
	utxo.append(&mut public_key.to_bytes().to_vec()); //32..64
	utxo.append(&mut masked_amount.to_bytes().to_vec()); //64..96
	utxo.append(&mut masked_blinding_factor.to_bytes().to_vec());  //96..128
	utxo.append(&mut pedersen_commitment);  //128..160

	/// Write the utxo into the database
	let mut utxo_count = database::read_chain_params_db(vec![0,1])?;
	database::write_utxos_db(utxo_count.clone(), utxo);

	/// Update the utxo count
	let mut n_utxo_count = BigEndian::read_u64(&mut utxo_count);
	BigEndian::write_u64(&mut utxo_count, n_utxo_count+1);
	database::write_chain_params_db(vec![0,1], utxo_count);

	return Ok(true);
}