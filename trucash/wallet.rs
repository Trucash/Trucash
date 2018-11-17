extern crate curve25519_dalek;
use self::curve25519_dalek::{ 	constants, scalar::Scalar, 
								ristretto::{ CompressedRistretto }
							};

extern crate rand;
use self::rand::OsRng;

extern crate byteorder;
use byteorder::{LittleEndian, ReadBytesExt, ByteOrder};

use crypto;
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

pub fn create_raw_tx(priv_keys: &[Scalar], to_address: &[CompressedRistretto], version: &[u8;2], amount_u64: u64) -> Result<bool, SuperError> {
	let utxos = match database::read_wallet_db(vec![0,1]) {
		Ok(i) => i,
		Err(i) => return Err(i)
	};

	let mut message_to_sign: Vec<u8> = Vec::new();
	for i in to_address {
		message_to_sign.extend_from_slice(&i.to_bytes());
	}

	println!("{:?}", message_to_sign);

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

		//(old_blinding_key - blinding_key) * pc_gens.B_blinding == old_commit - new_commit

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

	return Ok(true);
}

pub fn send_tx() {

}

pub fn generate_to_address() {

}

pub fn create_wallet() {

}