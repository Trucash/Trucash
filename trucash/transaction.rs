pub struct Transaction {
	pub version: Vec<u8>,			//2 byte
	pub input_count: Vec<u8>,		//2 byte
	pub inputs: Vec<Input>,		
	pub output_count: Vec<u8>,		//2 byte
	pub outputs: Vec<Ouput>,
	pub range_proofs: Vec<RangeProof>
}

pub struct Input {
	pub utxo_reference: Vec<u8>,	//8 byte
	pub commit: Vec<u8>,			//32 byte
	pub commit_sig_size: Vec<u8>,	//1 byte
	pub commit_sig: Vec<u8>,		//69-72 byte
	pub owner_sig_size: Vec<u8>,	//1 byte
	pub owner_sig: Vec<u8>			//69-72 byte
}

pub struct Ouput {
	pub to_owner: Vec<u8>, 			//32 byte //stealth address
	pub tx_pub_key: Vec<u8>,		//32 byte
	pub masked_amount: Vec<u8>,		//32 byte
	pub masked_blinding: Vec<u8>,	//32 byte
	pub commit: Vec<u8>,			//32 byte
}

pub struct RangeProof {
	pub commit_count: Vec<u8>,		//1 byte
}

//todo: write algorithm for sorting extra commits into aggregate range proof

impl Transaction {
	pub fn serialize_tx(&self) -> Vec<u8> {
		return Vec::new();
	}
}