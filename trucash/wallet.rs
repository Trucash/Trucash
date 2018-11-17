extern crate curve25519_dalek;
use self::curve25519_dalek::{ 	constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar, 
								ristretto::{ CompressedRistretto }
							};

extern crate rand;
use self::rand::OsRng;

extern crate byteorder;
use byteorder::{LittleEndian, ReadBytesExt, ByteOrder};

use crypto;
use crypto::sha2::Sha512;
use database;
use error::SuperError;
use transaction::*;

pub fn get_balance(priv_key1: Scalar, pub_key2: CompressedRistretto) -> Result<u64, SuperError> {
	let (balance, utxos) = database::get_balance(priv_key1, pub_key2)?;
	database::write_wallet_db(vec![0,1], utxos);
	return Ok(balance);
}


// get utxos from wallet db
// get amounts that add up to/more than needed
// get to address
// create tx keyapir <- in tx
// create diffie hellman w/ tx pub key
// create pedersen/mask amount/mask blinding w/ diffie hellman <- in tx
// create to_stealth_address w/ diffie hellman <- in tx

//serialize the tx

//send the tx

pub fn create_raw_tx(priv_keys: &[Scalar], to_address: &[ ([CompressedRistretto; 2], u64) ], version: &[u8;2], amount_u64: u64) -> Result<bool, SuperError> {
	let utxos = match database::read_wallet_db(vec![0,1]) {
		Ok(i) => i,
		Err(i) => return Err(i)
	};

	let mut account_tally: u64 = 0;
	let mut spend_bucket: Vec<u8> = Vec::new();

	let mut csprng: OsRng = OsRng::new().unwrap();
	let blinding_key: Scalar = Scalar::random(&mut csprng);

	let mut inputs: Vec<Input> = Vec::new();

	/// tally amount and get utxos
	/// create the inputs
	let mut i = 0;
	while i < utxos.len() {
		let utxo = &utxos[i..i+136]; //increase by 136 because thats the length of each utxo byte vector
		let mut amount_vec = &utxo[32..64];
		let amount_in_utxo = LittleEndian::read_u64(&mut amount_vec);
		account_tally += amount_in_utxo;

		let pedersen_commit = crypto::generate_pedersen(amount_in_utxo, blinding_key).compress();

		//get old blinding key for generating new key
		let mut old_blinding_key: [u8;32] = [0;32];
		old_blinding_key.copy_from_slice(&utxo[64..96]);
		let old_blinding_key = Scalar::from_bytes_mod_order(old_blinding_key);

		let key_for_signing_commit = old_blinding_key - blinding_key;

		//recover stealth priv_key
		let mut utxo_ref_pub_key: [u8;32] = [0;32];
		utxo_ref_pub_key.copy_from_slice(&utxos[96..128]);
		let utxo_ref_pub_key = CompressedRistretto(utxo_ref_pub_key);
		let private_key_for_stealth = crypto::recover_stealth_private_key(utxo_ref_pub_key, priv_keys);

		// Note: (old_blinding_key - blinding_key) * pc_gens.B_blinding == old_commit - new_commit

		let input = Input {
			utxo_reference: utxo[128..136].to_vec(),
			commit: pedersen_commit.to_bytes().to_vec(),
			commit_key: key_for_signing_commit.to_bytes().to_vec(),
			commit_sig: Vec::new(),
			owner_key: private_key_for_stealth.to_bytes().to_vec(),
			owner_sig: Vec::new()
		};

		spend_bucket.extend_from_slice(utxo);

		if account_tally >= amount_u64 {
			break;
		}

		i += 136;
	}

	let mut outputs: Vec<Output> = Vec::new();

	/// used for diffie-hellman exchange
	let tx_priv_key: Scalar = Scalar::random(&mut csprng);
	let blinding_key: Scalar = Scalar::random(&mut csprng);

	/// create the outputs
	for s in to_address {
		let destination = s.0;
		let amount: Scalar = s.1.into();

		let diffie_hellman_key = crypto::create_diffie_hellman(tx_priv_key, destination[0]);
		let diffie_hellman_serialized = Scalar::from_bytes_mod_order(diffie_hellman_key.to_bytes());
		
		let masked_amount = amount + Scalar::hash_from_bytes::<Sha512>(&diffie_hellman_serialized.to_bytes());
		let masked_blinding = diffie_hellman_serialized + blinding_key;

		let one_time_address = crypto::generate_stealth_address(&destination, tx_priv_key);

		let commit = crypto::generate_pedersen(s.1, blinding_key);
		let output = Output {
			to_owner: one_time_address.to_bytes().to_vec(),
			tx_pub_key: (tx_priv_key * RISTRETTO_BASEPOINT_POINT).compress().to_bytes().to_vec(),
			masked_amount: masked_amount.to_bytes().to_vec(),
			masked_blinding: masked_blinding.to_bytes().to_vec(),
			commit: commit.compress().to_bytes().to_vec()
		};
	}

	return Ok(true);
}

pub fn send_tx() {

}

pub fn generate_to_address() {

}

pub fn create_wallet() {

}