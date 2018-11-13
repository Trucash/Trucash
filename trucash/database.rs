extern crate rkv;

use self::rkv::{Manager, Rkv, Store, Value};
use std::{fmt::Debug, path::Path, fs};

extern crate curve25519_dalek;
use self::curve25519_dalek::{ 	scalar::Scalar,
								ristretto::{CompressedRistretto, RistrettoPoint}
							};
extern crate byteorder;
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt, BigEndian, ByteOrder};
use crypto;

use error::SuperError;

///! Constant Keys:
///! chain_params_db:
///! is_initialized -> [0,0]
///! utxo count -> [0,1]
///! difficulty -> [0,2]
///! prev hash -> [0,3]

/// Writes data to the `blocks` file in the database
pub fn write_blocks_db(key: Vec<u8>, data: Vec<u8>) {
	let path = Path::new("./db/blocks");
	let created_arc = Manager::singleton().write().unwrap().get_or_create(path, Rkv::new).unwrap();
	let env = created_arc.read().unwrap();
	let store: Store = env.open_or_create_default().unwrap(); 

	let mut writer = env.write().unwrap(); //create write tx
	writer.put(&store, key,  &Value::Blob(&data)).unwrap();
	writer.commit().unwrap();
}

/// Writes data to the `chain_params` file in the database
pub fn write_chain_params_db(key: Vec<u8>, data: Vec<u8>) {
	let path = Path::new("./db/chain_params");
	let created_arc = Manager::singleton().write().unwrap().get_or_create(path, Rkv::new).unwrap();
	let env = created_arc.read().unwrap();
	let store: Store = env.open_or_create_default().unwrap(); 

	let mut writer = env.write().unwrap(); //create write tx
	writer.put(&store, key,  &Value::Blob(&data)).unwrap();
	writer.commit().unwrap();
}

/// Writes data to the `utxos` file in the database
/// `key` should be the utxo offset read from the `chain_params` database
pub fn write_utxos_db(key: Vec<u8>, data: Vec<u8>) {
	let path = Path::new("./db/utxos");
	let created_arc = Manager::singleton().write().unwrap().get_or_create(path, Rkv::new).unwrap();
	let env = created_arc.read().unwrap();
	let store: Store = env.open_or_create_default().unwrap(); 

	let mut writer = env.write().unwrap(); //create write tx
	writer.put(&store, key,  &Value::Blob(&data)).unwrap();
	writer.commit().unwrap();
}

pub fn read_blocks_db() {

}


pub fn get_balance(priv_key1: Scalar, pub_key2: CompressedRistretto) -> Result<u64, SuperError> {
	let path = Path::new("./db/utxos");
	let created_arc = Manager::singleton().write().unwrap().get_or_create(path, Rkv::new).unwrap();
	let env = created_arc.read().unwrap();
	let store: Store = env.open_or_create_default().unwrap(); 
	let reader = env.read().expect("reader");

	let _ = reader.iter_from(&store, &[1]);

	let mut iterator = match reader.iter_start(&store) {
		Ok(i) => i,
		Err(i) => return Err(SuperError {
			description: String::from("No data exists in this db"),
			place: String::from("`get_chain_params_db_cursor()` in `database.rs`")
		})
	};

	let mut balance: u64 = 0;
	while true {
		match iterator.next() {
			Some(i) => if let Value::Blob(s) = i.1.unwrap().unwrap() {
				let mut stealth_address: [u8;32] = [0;32];
				stealth_address.copy_from_slice(&s[0..32]);
				let mut utxo_key: [u8;32] = [0;32];
				utxo_key.copy_from_slice(&s[32..64]);

				let stealth_address: CompressedRistretto = CompressedRistretto(stealth_address);
				let utxo_key: CompressedRistretto = CompressedRistretto(utxo_key);

				//priv key1 * utxo_key + pub key 2 == stealth_address
				//[utxokey, pubkey2] privkey1
				//check if utxo stealth address matches that of the wallet address
				if crypto::generate_stealth_address(&[utxo_key, pub_key2], priv_key1) != stealth_address {
					continue;
				}

				let mut masked_amount: [u8;32] = [0;32];
				masked_amount.copy_from_slice(&s[64..96]);
				let masked_amount = Scalar::from_bytes_mod_order(masked_amount);

				//get the diffie hellman and check the amount
				let diffie_hellman_key = crypto::create_diffie_hellman(priv_key1, utxo_key);
				let diffie_hellman_serialized = Scalar::from_bytes_mod_order(diffie_hellman_key.to_bytes());

				//reverse the diffie hellman masked amount
				let amount = masked_amount - (diffie_hellman_serialized * diffie_hellman_serialized);
				let amount = LittleEndian::read_u64(&mut amount.to_bytes());

				balance += amount;
			},
			_ => break
		}
	}

	return Ok(balance);
}

pub fn read_chain_params_db(key: Vec<u8>) -> Result<Vec<u8>, SuperError> {
	let path = Path::new("./db/chain_params");
	let created_arc = Manager::singleton().write().unwrap().get_or_create(path, Rkv::new).unwrap();
	let env = created_arc.read().unwrap();
	let store: Store = env.open_or_create_default().unwrap(); 
	let reader = env.read().expect("reader");

	let read_data = match reader.get(&store, key).unwrap().unwrap_or(Value::Bool(false)) {
		Value::Blob(i) => i.to_vec(),
		_ => { 
			return Err(SuperError { 
						description: String::from("No data exists at this key"),
						place: String::from("`read_chain_params_db()` in `database.rs`")
					}); 
		}
	};
	return Ok(read_data);
}

pub fn read_utxos_db(key: Vec<u8>) -> Result<Vec<u8>, SuperError> {	
	let path = Path::new("./db/utxos");
	let created_arc = Manager::singleton().write().unwrap().get_or_create(path, Rkv::new).unwrap();
	let env = created_arc.read().unwrap();
	let store: Store = env.open_or_create_default().unwrap(); 
	let reader = env.read().expect("reader");

	let read_data = match reader.get(&store, key).unwrap().unwrap_or(Value::Bool(false)) {
		Value::Blob(i) => i.to_vec(),
		_ => { 
			return Err(SuperError { 
						description: String::from("No data exists at this key"),
						place: String::from("`read_utxos_db()` in `database.rs`")
					}); 
		}
	};

	return Ok(read_data);
}