use database;
use error::SuperError;

extern crate curve25519_dalek;
use self::curve25519_dalek::{ 	constants, scalar::Scalar, 
								traits::MultiscalarMul, 
								ristretto::{ RistrettoPoint, CompressedRistretto }
							};

extern crate byteorder;
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt, BigEndian, ByteOrder};

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

pub fn create_raw_tx(/*priv_keys: &[Scalar], to_address: &[CompressedRistretto], version: &[u8;2],*/ amount_u64: u64) -> Result<bool, SuperError> {
	let utxos = match database::read_wallet_db(vec![0,1]) {
		Ok(i) => i,
		Err(i) => return Err(i)
	};

	let mut account_tally: u64 = 0;
	let mut spend_bucket: Vec<u8> = Vec::new();

	let mut i = 0;
	while i < utxos.len() {
		let utxo = &utxos[i..i+128];
		let mut amount_vec = &utxo[32..64];
		account_tally += LittleEndian::read_u64(&mut amount_vec);

		spend_bucket.extend_from_slice(utxo);
		if account_tally >= amount_u64 {
			break;
		}

		i += 128;
	}

	return Ok(true);
}

pub fn send_tx() {

}

pub fn generate_to_address() {

}

pub fn create_wallet() {

}