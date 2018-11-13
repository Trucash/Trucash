use database;
use error::SuperError;

extern crate curve25519_dalek;
use self::curve25519_dalek::{ scalar::Scalar };

extern crate byteorder;
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt, BigEndian, ByteOrder};

pub fn get_balance() {
	//database::get_balance();
}

pub fn generate_to_address() {

}

pub fn create_wallet() {

}