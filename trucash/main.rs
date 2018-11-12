mod init;
mod database;
mod crypto;
mod error;

extern crate byteorder;

use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt, BigEndian, ByteOrder};


fn main() {
	//init::init_utxo(&mut vec![2,1]);
	let mut wtr = vec![0,1,8,9];
	BigEndian::write_u32(&mut wtr, 300);
	println!("{:?}", wtr);

	let s = BigEndian::read_u32(&mut wtr);
	println!("{:?}", s);

}