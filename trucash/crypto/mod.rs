use error::SuperError;

pub fn create_keypair() {

}

/// Generates a pedersen commitment for a given
/// amount with a known scalar as a blinding factor;
/// In this case, 0x01 padded with 32 bytes
pub fn generate_known_pedersen(amount: u64) -> Result<[u8;32], SuperError> {
	return Ok([0;32]);
}

/// Generates a pedersen commitment for a given
/// amount with an inputted 32 byte scalar/blinding factor
pub fn generate_pedersen(amount: u64, blinding: &[u8]) -> Result<[u8;32], SuperError> {
	return Ok([0;32]);
}