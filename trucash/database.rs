extern crate rkv;

use self::rkv::{Manager, Rkv, Store, Value};
use std::{fmt::Debug, path::Path, fs};

use error::SuperError;


/// Writes data to the `blocks` file in the database
pub fn write_blocks_db(key: Vec<u8>, data: Vec<u8>) {
	let path = Path::new("../db/blocks");
	let created_arc = Manager::singleton().write().unwrap().get_or_create(path, Rkv::new).unwrap();
	let env = created_arc.read().unwrap();
	let store: Store = env.open_or_create_default().unwrap(); 

	let mut writer = env.write().unwrap(); //create write tx
	writer.put(&store, key,  &Value::Blob(&data)).unwrap();
	writer.commit().unwrap();
}

/// Writes data to the `chain_params` file in the database
pub fn write_chain_params_db(key: Vec<u8>, data: Vec<u8>) {
	let path = Path::new("../db/chain_params");
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
	let path = Path::new("../db/utxos");
	let created_arc = Manager::singleton().write().unwrap().get_or_create(path, Rkv::new).unwrap();
	let env = created_arc.read().unwrap();
	let store: Store = env.open_or_create_default().unwrap(); 

	let mut writer = env.write().unwrap(); //create write tx
	writer.put(&store, key,  &Value::Blob(&data)).unwrap();
	writer.commit().unwrap();
}

pub fn read_blocks_db() {

}

pub fn read_chain_params_db(key: Vec<u8>) -> Result<Vec<u8>, SuperError> {
	let path = Path::new("../db/chain_params");
	let created_arc = Manager::singleton().write().unwrap().get_or_create(path, Rkv::new).unwrap();
	let env = created_arc.read().unwrap();
	let store: Store = env.open_or_create_default().unwrap(); 
	let reader = env.read().expect("reader");

	let read_data = match reader.get(&store, key).unwrap().unwrap() {
		Value::Blob(i) => i.to_vec(),
		_ => { 
			return Err(SuperError { 
						description: String::from("No data exists at this key"),
						place: String::from("`read_chain_params_db()`")
					}); 
		}
	};
	return Ok(read_data);
}

pub fn read_utxos_db(key: Vec<u8>) -> Result<Vec<u8>, SuperError> {	
	let path = Path::new("../db/utxos");
	let created_arc = Manager::singleton().write().unwrap().get_or_create(path, Rkv::new).unwrap();
	let env = created_arc.read().unwrap();
	let store: Store = env.open_or_create_default().unwrap(); 
	let reader = env.read().expect("reader");

	let read_data = match reader.get(&store, key).unwrap().unwrap() {
		Value::Blob(i) => i.to_vec(),
		_ => { 
			return Err(SuperError { 
						description: String::from("No data exists at this key"),
						place: String::from("`read_utxos_db()`")
					}); 
		}
	};

	return Ok(read_data);
}