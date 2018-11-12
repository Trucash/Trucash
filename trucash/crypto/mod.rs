use error::SuperError;

extern crate rand;
use self::rand::thread_rng;

extern crate curve25519_dalek;
use self::curve25519_dalek::{ 	constants, scalar::Scalar, 
								traits::MultiscalarMul, 
								ristretto::{ RistrettoPoint, CompressedRistretto }
							};

extern crate merlin;
use self::merlin::Transcript;

extern crate bulletproofs;
use self::bulletproofs::{ BulletproofGens, PedersenGens, RangeProof };

pub fn create_keypair() {

}

pub fn generate_scalar_one_keypair() -> (Scalar, CompressedRistretto) {
	let scalar_one = Scalar::one();
	let base_point = constants::RISTRETTO_BASEPOINT_POINT;
	let public_key = RistrettoPoint::multiscalar_mul(&[scalar_one], &[base_point]).compress();
	return (scalar_one, public_key);
}

/// Generates a pedersen commitment for a given
/// amount with an inputted 32 byte scalar/blinding factor
pub fn generate_pedersen(amount: u64, blinding: &Scalar) -> Result<[u8;32], SuperError> {
	return Ok([0;32]);
}

/// Creates a diffie-hellman
/// shared secret and returns it
pub fn create_diffie_hellman(private_key: &[u8], public_key: &[u8]) {

}

pub fn hash() {
	
}