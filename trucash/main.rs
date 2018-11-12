mod init;
mod database;
mod crypto;
mod error;

extern crate byteorder;

use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt, BigEndian, ByteOrder};

extern crate curve25519_dalek;
use self::curve25519_dalek::{ 	constants, scalar::Scalar, traits::MultiscalarMul,
								ristretto::{ RistrettoPoint, CompressedRistretto }
							};


fn main() {
	//init::init_utxo(&mut vec![2,1]);
	let s = CompressedRistretto::from_slice(&[1;32]);
	let f = Scalar::from_bits([9;32]);

	let B = constants::RISTRETTO_BASEPOINT_POINT;

	println!("{:?}", f);
}

//pub key = [184, 247, 169, 32, 15, 18, 89, 62, 65, 113, 126, 100, 21, 109, 138, 129, 183, 137, 114, 52, 90, 50, 88, 201, 40, 198, 174, 64, 41, 209, 48, 127]
//priv key = [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]