use crypto::*;

#[derive(Debug)]
pub struct Transaction {
	pub version: Vec<u8>,			//2 byte
	pub input_count: Vec<u8>,		//2 byte
	pub inputs: Vec<Input>,		
	pub output_count: Vec<u8>,		//2 byte
	pub outputs: Vec<Output>
}

#[derive(Debug)]
pub struct Input {
	pub utxo_reference: Vec<u8>,	//8 byte
	pub commit: Vec<u8>,			//32 byte		commit(blinding_key * G + amount * H)
	pub commit_key: Vec<u8>,		//32 byte		(this is not used for the actual tx, just storing the key for signing later)
	pub commit_sig: Vec<u8>,		//64 byte 		sig(old_blinding_key - blinding_key)
	pub owner_key: Vec<u8>,			//32 byte		(this is not used for the actual tx, just storing the key for signing later)
	pub owner_sig: Vec<u8>			//64 byte		sig(owner_stealth_address)
}

#[derive(Debug, Clone)]
pub struct Output {
	pub to_owner: Vec<u8>, 			//32 byte 		stealth address
	pub tx_pub_key: Vec<u8>,		//32 byte
	pub masked_amount: Vec<u8>,		//32 byte
	pub masked_blinding: Vec<u8>,	//32 byte
	pub commit: Vec<u8>,			//32 byte
	pub range_proof_len: Vec<u8>,	//2 byte
	pub range_proof: Vec<u8>		//n bytes		this is a byte vector representation of the range proof
}

//todo: write algorithm for sorting extra commits into aggregate range proof

impl Transaction {
	pub fn serialize_tx(&mut self) -> Vec<u8> {
		let mut bytes: Vec<u8> = Vec::new();
		bytes.append(&mut self.version);
		bytes.append(&mut self.input_count);

		for i in &mut self.inputs {
			let mut in_bytes: Vec<u8> = Vec::new();
			in_bytes.append(&mut i.utxo_reference);
			in_bytes.append(&mut i.commit);
			in_bytes.append(&mut i.commit_sig);
			in_bytes.append(&mut i.owner_sig);
			bytes.append(&mut in_bytes);
		}

		bytes.append(&mut self.output_count);
		for i in &mut self.outputs {
			let mut out_bytes: Vec<u8> = Vec::new();
			out_bytes.append(&mut i.to_owner);
			out_bytes.append(&mut i.tx_pub_key);
			out_bytes.append(&mut i.masked_amount);
			out_bytes.append(&mut i.masked_blinding);
			out_bytes.append(&mut i.commit);
			out_bytes.append(&mut i.range_proof_len);
			out_bytes.append(&mut i.range_proof);
			bytes.append(&mut out_bytes);
		}
		println!("{:?}", bytes.len());
		return bytes;
	}
}

impl Output {
	pub fn serialize(outputs: Vec<Output>) -> Vec<u8> {
		let mut bytes: Vec<u8> = Vec::new();
		for mut i in outputs.clone() {
			bytes.append(&mut i.to_owner);
			bytes.append(&mut i.tx_pub_key);
			bytes.append(&mut i.masked_amount);
			bytes.append(&mut i.masked_blinding);
			bytes.append(&mut i.commit);
		}
		return bytes;
	}
}