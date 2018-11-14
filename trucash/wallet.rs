use database;
use error::SuperError;

extern crate curve25519_dalek;
use self::curve25519_dalek::{ 	constants, scalar::Scalar, 
								traits::MultiscalarMul, 
								ristretto::{ RistrettoPoint, CompressedRistretto }
							};

extern crate byteorder;
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt, BigEndian, ByteOrder};

pub fn get_balance(priv_key1: Scalar, pub_key2: CompressedRistretto) -> Result<(u64, Vec<Vec<u8>>), SuperError> {
	let (balance, utxo_keys) = database::get_balance(priv_key1, pub_key2)?;
	return Ok((balance, utxo_keys));
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

pub fn create_raw_tx() {

}

pub fn send_tx() {

}

pub fn generate_to_address() {

}

pub fn create_wallet() {

}