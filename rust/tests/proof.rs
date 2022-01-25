/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
mod common;

use std::convert::TryInto;

use common::{MockRng, ID};
use oberon::{Blinding, Proof, PublicKey, SecretKey};
use rand_core::RngCore;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use bls12_381_plus::{G1Affine, Scalar};

#[test]
fn proof_works() {
    let mut rng = MockRng::new();
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::from(&sk);
    let token = sk.sign(ID).unwrap();
    let blinding = Blinding::new(b"1234");
    let blinded_token = token - &blinding;

    // sent from verifier, could also be a timestamp in milliseconds as unsigned 8 byte integer
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);

    let opt_proof = Proof::new(&blinded_token, &[blinding], ID, &nonce, &mut rng);
    assert!(opt_proof.is_some());
    let proof = opt_proof.unwrap();

    // Send proof, id, nonce to verifier
    assert_eq!(proof.open(pk, ID, nonce).unwrap_u8(), 1u8);
    assert_eq!(proof.open(pk, b"wrong id", nonce).unwrap_u8(), 0u8);
    assert_eq!(proof.open(pk, ID, b"wrong nonce").unwrap_u8(), 0u8);

    // // No blinding factor
    // let opt_proof = Proof::new(&blinded_token, &[], ID, &nonce, &mut rng);
    // assert!(opt_proof.is_some());
    // let proof = opt_proof.unwrap();

    // // Send proof, id, nonce to verifier
    // assert_eq!(proof.open(pk, ID, nonce).unwrap_u8(), 0u8);

    // // proof to bytes
    // assert_eq!(
    //     proof.to_bytes(),
    //     [
    //         172, 44, 196, 169, 160, 26, 52, 127, 53, 59, 189, 108, 9, 32, 254, 37, 75, 107, 18, 84,
    //         126, 229, 137, 64, 94, 84, 198, 224, 51, 47, 129, 95, 172, 142, 27, 206, 212, 176, 121,
    //         124, 0, 121, 27, 210, 138, 46, 62, 32, 171, 50, 166, 43, 168, 199, 83, 254, 187, 82,
    //         10, 20, 80, 106, 217, 99, 152, 85, 146, 201, 116, 160, 65, 177, 74, 89, 56, 163, 249,
    //         54, 78, 230, 45, 98, 181, 248, 14, 40, 206, 168, 136, 107, 154, 224, 116, 86, 210, 236
    //     ]
    // );

    // AW: testing replaced nonce
    let pb = proof.to_bytes();
    let prf = G1Affine::from_compressed(&pb[..48].try_into().unwrap()).unwrap();
    let u_tick = G1Affine::from_compressed(&pb[48..96].try_into().unwrap()).unwrap();

    let t1 = hash_to_scalar(&[ID, nonce.as_ref()]);

    let mut nonce2 = [0u8; 16];
    rng.fill_bytes(&mut nonce2);
    let t2 = hash_to_scalar(&[ID, nonce2.as_ref()]);
    let r_sigma = G1Affine::from(prf - u_tick * t1);
    let prf2 = G1Affine::from(r_sigma + u_tick * t2);

    let mut pb2 = pb;
    pb2[..48].copy_from_slice(&prf2.to_compressed()[..]);
    let proof2 = Proof::from_bytes(&pb2).unwrap();

    assert_eq!(proof2.open(pk, ID, nonce).unwrap_u8(), 0u8);
    assert_eq!(proof2.open(pk, ID, nonce2).unwrap_u8(), 1u8);
}

#[test]
fn vectors() {
    let mut rng = MockRng::new();
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::from(&sk);
    let id = hex::decode("aa").unwrap();
    let token = sk.sign(&id).unwrap();
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    let proof = Proof::new(&token, &[], &id, nonce, &mut rng).unwrap();
    println!("sk    = {}", hex::encode(sk.to_bytes()));
    println!("token = {}", hex::encode(token.to_bytes()));
    println!("nonce = {}", hex::encode(nonce));
    println!("proof = {}", hex::encode(proof.to_bytes()));
    println!("open = {}", proof.open(pk, &id, nonce).unwrap_u8())
}

const TO_SCALAR_DST: &[u8] = b"OBERON_BLS12381FQ_XOF:SHAKE-256_";

pub fn hash_to_scalar(data: &[&[u8]]) -> Scalar {
    let mut hasher = Shake256::default();
    hasher.update(TO_SCALAR_DST);
    for slice in data {
        hasher.update(slice);
    }
    let mut reader = hasher.finalize_xof();
    let mut data = [0u8; 48];
    reader.read(&mut data);
    Scalar::from_okm(&data)
}
