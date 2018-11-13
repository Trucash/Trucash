use error::SuperError;

extern crate rand;
use self::rand::OsRng;

extern crate curve25519_dalek;
use self::curve25519_dalek::{ 	constants, scalar::Scalar, 
								traits::MultiscalarMul, 
								ristretto::{ RistrettoPoint, CompressedRistretto }
							};

extern crate merlin;
use self::merlin::Transcript;

extern crate bulletproofs;
use self::bulletproofs::{ BulletproofGens, PedersenGens, RangeProof };

pub fn create_address() -> ([CompressedRistretto;2], [Scalar; 2]) {
	let base_point = constants::RISTRETTO_BASEPOINT_POINT;
	let mut csprng: OsRng = OsRng::new().unwrap();
	let (priv_key1, priv_key2) = (Scalar::random(&mut csprng), Scalar::random(&mut csprng));
	let (pub_key1, pub_key2) = ((priv_key1 * base_point).compress(), (priv_key2 * base_point).compress());

	let address = [pub_key1, pub_key2];
	let priv_keys = [priv_key1, priv_key2];
	return (address, priv_keys);
}

//get the txpubkey
//check if it matches our address
//get the diffiehellman key
//get the amount
//save the utxo

/// new address -> arG + bG -> aR + B -> rA + B
pub fn generate_stealth_address(pub_addresses: &[CompressedRistretto], priv_key: Scalar) -> CompressedRistretto {
	let address = (priv_key * pub_addresses[0].decompress().unwrap()) + pub_addresses[1].decompress().unwrap();
	return address.compress();
}

pub fn generate_scalar_one_keypair() -> (Scalar, CompressedRistretto) {
	let scalar_one = Scalar::one();
	let base_point = constants::RISTRETTO_BASEPOINT_POINT;
	let public_key = RistrettoPoint::multiscalar_mul(&[scalar_one], &[base_point]).compress();
	return (scalar_one, public_key);
}

/// Generates a pedersen commitment for a given
/// amount with an inputted 32 byte scalar/blinding factor
pub fn generate_pedersen(amount: u64, blinding: Scalar) -> RistrettoPoint {
	let pc_gens = PedersenGens::default();
	let commit = pc_gens.commit(amount.into(), blinding);
	return commit;
}

/// Creates a diffie-hellman
/// shared secret and returns it
pub fn create_diffie_hellman(private_key: Scalar, public_key: CompressedRistretto) -> CompressedRistretto {
	let secret_key = (private_key * public_key.decompress().unwrap()).compress();
	return secret_key;
}

pub fn hash() {

}