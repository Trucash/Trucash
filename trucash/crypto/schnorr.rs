///! Schnorr singatures
///! over the curve25519 standard

use curve25519_dalek::{ 	constants, scalar::Scalar, 
							traits::MultiscalarMul, 
							constants::RISTRETTO_BASEPOINT_POINT,
							ristretto::{ RistrettoPoint, CompressedRistretto }
						};

use crypto::sha2::Sha512;
use crypto::bulletproofs::{ BulletproofGens, PedersenGens, RangeProof };

///P = priv_key.G
///R = kG
///e = H_s(R || M)
///s = k - priv_key * e
pub fn sign(priv_key: Scalar, message: &[u8], basepoint: RistrettoPoint) -> (Scalar, Scalar) {
	let pub_key = priv_key * basepoint;

	/// k is constructed from h_s(priv_key || message) for provable pseudorandomness
	let mut k_digest = priv_key.to_bytes().to_vec();
	k_digest.extend_from_slice(message);
	let k = Scalar::hash_from_bytes::<Sha512>(&k_digest);

	let R = k * basepoint;

	let mut e_digest = R.compress().to_bytes().to_vec();
	e_digest.extend_from_slice(message);
	let e = Scalar::hash_from_bytes::<Sha512>(&e_digest);

	let s = k - priv_key * e;

	return (s, e);
}

///k - xe + e * x * G
///k - xe + e * P
///H_s((k - xe)G + (xe)G || M)
///H_s(k * G || M)
pub fn verify(pub_key: CompressedRistretto, message: &[u8], basepoint: RistrettoPoint, s: Scalar, e: Scalar) -> bool {
	let s_pub = s * basepoint;
	let e_x_pub = e * pub_key.decompress().unwrap();

	let R = s_pub + e_x_pub;

	let mut hash_digest = R.compress().to_bytes().to_vec();
	hash_digest.extend_from_slice(message);
	let hash_to_verify = Scalar::hash_from_bytes::<Sha512>(&hash_digest);

	return hash_to_verify == e;
}
