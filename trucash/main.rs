mod init;
mod database;
mod crypto;
mod error;
mod wallet;
mod transaction;

extern crate byteorder;

use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt, BigEndian, ByteOrder};

extern crate curve25519_dalek;
use self::curve25519_dalek::{ 	constants, scalar::Scalar, traits::MultiscalarMul,
								ristretto::{ RistrettoPoint, CompressedRistretto }
							};

fn main() {
	//if database::read_chain_params_db(vec![0,0]).unwrap_or(vec![0])[0] == 0 {
		init::init_chain();
		println!("{:?}", "Chain initialized");
	//};

	let (pub_key1, pub_key2) = ([222, 239, 177, 184, 14, 231, 248, 119, 169, 130, 170, 244, 181, 193, 22, 62, 86, 213, 98, 124, 51, 78, 70, 157, 75, 79, 132, 5, 71, 65, 14, 111], [254, 83, 66, 243, 220, 113, 105, 66, 180, 206, 111, 227, 225, 128, 249, 4, 105, 123, 192, 242, 154, 6, 13, 178, 3, 191, 36, 175, 76, 93, 11, 95]);
	let (pub_key1, pub_key2) = (CompressedRistretto(pub_key1), CompressedRistretto(pub_key2));

	let (priv_key1, priv_key2) = ([147, 102, 50, 185, 99, 31, 203, 134, 93, 10, 174, 165, 250, 28, 177, 220, 204, 155, 147, 120, 212, 12, 50, 103, 225, 4, 7, 81, 152, 87, 93, 11], [72, 240, 8, 187, 148, 30, 194, 143, 36, 1, 207, 62, 23, 43, 89, 217, 42, 211, 232, 12, 222, 1, 250, 34, 44, 142, 97, 187, 231, 23, 77, 11]);
	let (priv_key1, priv_key2) = (Scalar::from_bytes_mod_order(priv_key1), Scalar::from_bytes_mod_order(priv_key2));

	let amount = wallet::get_balance(priv_key1, pub_key2);
	println!("{:?}", amount);
	wallet::create_raw_tx(&[priv_key1, priv_key2], &[ ([pub_key1, pub_key2], 1_000_000u64) ], &[0,1], 1_000_000u64);

}

//pub key
//[222, 239, 177, 184, 14, 231, 248, 119, 169, 130, 170, 244, 181, 193, 22, 62, 86, 213, 98, 124, 51, 78, 70, 157, 75, 79, 132, 5, 71, 65, 14, 111]
//[254, 83, 66, 243, 220, 113, 105, 66, 180, 206, 111, 227, 225, 128, 249, 4, 105, 123, 192, 242, 154, 6, 13, 178, 3, 191, 36, 175, 76, 93, 11, 95]

//priv key
//[147, 102, 50, 185, 99, 31, 203, 134, 93, 10, 174, 165, 250, 28, 177, 220, 204, 155, 147, 120, 212, 12, 50, 103, 225, 4, 7, 81, 152, 87, 93, 11]
//[72, 240, 8, 187, 148, 30, 194, 143, 36, 1, 207, 62, 23, 43, 89, 217, 42, 211, 232, 12, 222, 1, 250, 34, 44, 142, 97, 187, 231, 23, 77, 11]