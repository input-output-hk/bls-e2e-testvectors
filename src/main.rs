use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

use sha2::{Digest, Sha256};

use ff::Field;
use group::{Curve, GroupEncoding};

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::{ChaCha8Rng};


const DST: &[u8; 43] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// BLS signature with the public key over G1. This function returns a message `msg`, a public
/// key `pk`, and a signature `sig`. Verification of these test vectors should proceed as follows:
/// * pk_deser = G1Decompress(pk)
/// * sig_deser = G2Decompress(sig)
/// * hashed_msg = G2HashToCurve(msg, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
/// * Check that pairing(pk_deser, hashed_msg) = pairing(G1Generator, sig_deser)
fn bls_pk_g1(mut rng: impl RngCore + CryptoRng) {
    println!("+---------------------------------------------------------------------------+");
    println!("|                 BLS signature with PK in G1                               |");
    println!("+---------------------------------------------------------------------------+");
    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);

    let sk = Scalar::random(&mut rng);
    let pk = sk * G1Affine::generator();
    let hashed_msg = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, DST);

    let signature = sk * hashed_msg;

    assert_eq!(
        pairing(&pk.to_affine(), &hashed_msg.to_affine()),
        pairing(&G1Affine::generator(), &signature.to_affine())
    );

    println!("| Message   : 0x{}", hex::encode(msg));
    println!("| Public key: 0x{}", hex::encode(pk.to_bytes()));
    println!("| Signature : 0x{}", hex::encode(signature.to_bytes()));
}

/// BLS signature with the public key over G2. This function returns a message `msg`, a public
/// key `pk`, and a signature `sig`. Verification of these test vectors should proceed as follows:
/// * pk_deser = G2Decompress(pk)
/// * sig_deser = G1Decompress(sig)
/// * hashed_msg = G1HashToCurve(msg, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
/// * Check that pairing(pk_deser, hashed_msg) = pairing(G1Generator, sig_deser)
fn bls_pk_g2(mut rng: impl RngCore + CryptoRng) {
    let mut msg = [0u8; 32];
    println!("+---------------------------------------------------------------------------+");
    println!("|                    BLS signature with PK in G2                            |");
    println!("+---------------------------------------------------------------------------+");
    rng.fill_bytes(&mut msg);

    let sk = Scalar::random(&mut rng);
    let pk = sk * G2Affine::generator();
    let hashed_msg = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, DST);

    let signature = sk * hashed_msg;

    assert_eq!(
        pairing(&hashed_msg.to_affine(), &pk.to_affine()),
        pairing(&signature.to_affine(), &G2Affine::generator())
    );



    println!("| Message   : 0x{}", hex::encode(msg));
    println!("| Public key: 0x{}", hex::encode(pk.to_bytes()));
    println!("| Signature : 0x{}", hex::encode(signature.to_bytes()));
}

/// Aggregate BLS signature with the same key and different messages, with public key over G1. This
/// function returns a list of 10 messages {`msg_1`, ..., `msg_10`}, a public key `pk`, and an
/// aggregate signature `aggr_sig`. To verify the correctness of the test vectors, check the
/// following:
/// * hashed_msg_i = G2HashToCurve(msg_i, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_") for i in [1, 10]
/// * pk_deser = G1Decompress(pk)
/// * aggr_sig_deser = G2Decompress(aggr_sig)
/// * aggr_msg = sum_{i\in[1,10]} hashed_msg_i
/// * Check that pairing(pk_deser, aggr_msg) = pairing(G1Generator, aggr_sig_deser)
fn aggr_bls_diff_msg_pk_g1(mut rng: impl RngCore + CryptoRng) {
    println!("+---------------------------------------------------------------------------+");
    println!("| Aggregate BLS signature with same key, different message, with PK over G1 |");
    println!("+---------------------------------------------------------------------------+");
    // Let's sign 10 messages
    let mut msgs = [[0u8; 32]; 10];
    msgs.iter_mut().for_each(|msg| rng.fill_bytes(msg));

    let sk = Scalar::random(&mut rng);
    let pk = sk * G1Affine::generator();

    let hashed_msgs = msgs
        .iter()
        .map(|msg| <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, DST))
        .collect::<Vec<_>>();

    let sigs = hashed_msgs
        .iter()
        .map(|hashed_msg| sk * hashed_msg)
        .collect::<Vec<_>>();

    let aggr_sig: G2Projective = sigs.iter().sum();
    let aggr_msgs: G2Projective = hashed_msgs.iter().sum();

    assert_eq!(pairing(&pk.to_affine(), &aggr_msgs.to_affine()), pairing(&G1Affine::generator(), &aggr_sig.to_affine()));

    println!("| Messages   :");
    for (index, msg) in msgs.iter().enumerate() {
        println!("|    {}. 0x{}", index + 1, hex::encode(msg));
    }

    println!("| Public key: 0x{}", hex::encode(pk.to_bytes()));
    println!("| Aggregate Signature : 0x{}", hex::encode(aggr_sig.to_bytes()));
}

/// Aggregate BLS signature with different keys and same message, with public key over G2. This
/// function returns a message `msg`, ten public keys `{pk_1,...,pk_10}`, and an
/// aggregate signature `aggr_sig`. To verify the correctness of the test vectors, check the
/// following:
/// * hashed_msg = G1HashToCurve(msg, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
/// * pk_deser_i = G1Decompress(pk_i) for i in [1, 10]
/// * ds_scalar = SHA256(pk_1 || .. || pk_10) mod `period`, where `period` is the order of the group G2
/// * aggr_sig_deser = G2Decompress(aggr_sig)
/// * aggr_pk = sum_{i\in[1,10]} ds_scalar^i * pk_deser_i
/// * Check that pairing(aggr_pk, hashed_msg) = pairing(G1Generator, aggr_sig_deser)
fn aggr_bls_same_msg_pk_g2(mut rng: impl RngCore + CryptoRng) {
    let mut msg = [0u8; 32];

    println!("+---------------------------------------------------------------------------+");
    println!("| Aggregate BLS signature with different key, same message, with PK over G2 |");
    println!("+---------------------------------------------------------------------------+");
    rng.fill_bytes(&mut msg);
    let hashed_msg = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, DST);

    let sks = (0..10).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
    let pks = sks.iter().map(|sk| sk * G2Affine::generator()).collect::<Vec<_>>();

    let mut hash = Sha256::new();
    let mut scalar_bytes = [0u8; 32];

    pks.iter().for_each(|pk| hash.update(&pk.to_bytes()) );
    let out = hash.finalize();
    println!("Output of hash: 0x{}", hex::encode(out));
    let decoded_bytes = hex::decode("fc67e8340e7cea5202939c73fcf5716b").unwrap();
    println!("hex decode: {:?}", decoded_bytes);
    scalar_bytes[..16].copy_from_slice(&out[..16]);
    let ds_scalar = Scalar::from_bytes(&scalar_bytes).unwrap();
    println!("Scalar from hash: {:?}", ds_scalar.to_bytes());
    println!("{:?}", num_bigint::BigUint::from_bytes_le(&ds_scalar.to_bytes()));
    println!("{:?}", num_bigint::BigUint::from_bytes_be(&decoded_bytes));

    let mut ds_scalar_power = Scalar::one();

    let sigs = sks
        .iter()
        .map(|sk| sk * hashed_msg)
        .collect::<Vec<_>>();

    let aggr_sig: G1Projective = sigs.iter().fold(G1Projective::identity(), |acc, sig| {
        ds_scalar_power *= ds_scalar;
        acc + ds_scalar_power * sig
    });

    // initialise the power (not the most efficient, but we don't really care here)
    ds_scalar_power = Scalar::one();
    let aggr_pk: G2Projective = pks.iter().fold(G2Projective::identity(), |acc, pk| {
        ds_scalar_power *= ds_scalar;
        acc + ds_scalar_power * pk
    });

    println!("Aggregate pk: {:?}", hex::encode(aggr_pk.to_bytes()));

    assert_eq!(pairing(&hashed_msg.to_affine(), &aggr_pk.to_affine()), pairing(&aggr_sig.to_affine(), &G2Affine::generator()));


    println!("| Message    : 0x{}", hex::encode(msg));
    println!("| Public keys:");
    for (index, pk) in pks.iter().enumerate() {
        println!("|    {}. 0x{}", index + 1, hex::encode(pk.to_bytes()));
    }

    println!("| Aggregate Signature : 0x{}", hex::encode(aggr_sig.to_bytes()));
}

/// FastAggregate BLS signature with different keys and same message, with PK over G2.
/// Assumes PoP(pk_i) has already been verified for all i (per IETF FastAggregateVerify).
///
/// Returns:
/// - msg
/// - pk_1..pk_10 (G2 compressed)
/// - aggr_sig (G1 compressed)
///
/// Verification:
///   hashed_msg = G1HashToCurve(msg, DST)
///   aggr_pk = sum_i G2Decompress(pk_i)
///   aggr_sig = G1Decompress(aggr_sig)
///   Check pairing(hashed_msg, aggr_pk) == pairing(aggr_sig, G2Generator)
fn fast_aggr_bls_same_msg_pk_g2(mut rng: impl RngCore + CryptoRng) {
    let mut msg = [0u8; 32];

    println!("+---------------------------------------------------------------------------+");
    println!("| FastAggregate BLS sig (same msg, different keys), PK over G2 (PoP assumed) |");
    println!("+---------------------------------------------------------------------------+");

    rng.fill_bytes(&mut msg);

    // Hash message onto G1 (because signatures live in G1 when PKs are in G2)
    let hashed_msg =
        <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, DST);

    // Generate 10 keypairs
    let sks = (0..10).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
    let pks = sks
        .iter()
        .map(|sk| sk * G2Affine::generator())
        .collect::<Vec<_>>();

    // Each signer signs the same message: sig_i = sk_i * H(msg) in G1
    let sigs = sks
        .iter()
        .map(|sk| sk * hashed_msg)
        .collect::<Vec<_>>();

    // Fast aggregation is simple addition (NO coefficient / DS trick)
    let aggr_sig: G1Projective = sigs.iter().sum();
    let aggr_pk: G2Projective = pks.iter().sum();

    // FastAggregateVerify pairing check
    assert_eq!(
        pairing(&hashed_msg.to_affine(), &aggr_pk.to_affine()),
        pairing(&aggr_sig.to_affine(), &G2Affine::generator())
    );

    // Print vectors (similar format to existing ones)
    println!("| Message    : 0x{}", hex::encode(msg));
    println!("| Public keys:");
    for (index, pk) in pks.iter().enumerate() {
        println!("|    {}. 0x{}", index + 1, hex::encode(pk.to_bytes()));
    }
    println!(
        "| Aggregate Signature : 0x{}",
        hex::encode(aggr_sig.to_bytes())
    );
}


/// Schnorr signature in G1. This function returns a message `msg`, a public key `pk` and a
/// signature `(A, r)`.
///
/// To verify the signature, proceed as follows:
/// * hash = Sha256(A || pk || msg)
/// * c = hash mod `period`, where `period` is the order of the group defined over G1
/// * pk_deser = G1Decompress(pk)
/// * A_deser = G1Decompress(A)
/// * r_deser = IntegerFromBytes(r)
/// * Check that r_deser * G1Generator = A_deser + c * pk_deser
fn schnorr_g1(mut rng: impl RngCore + CryptoRng) {
    let mut msg = [0u8; 32];
    println!("+---------------------------------------------------------------------------+");
    println!("|                      Schnorr signature over G1                            |");
    println!("+---------------------------------------------------------------------------+");
    rng.fill(&mut msg);

    let sk = Scalar::random(&mut rng);
    let pk = sk * G1Affine::generator();
    let nonce = Scalar::random(&mut rng);
    let announcement = nonce * G1Affine::generator();
    let hasher = Sha256::new()
        .chain(&announcement.to_bytes())
        .chain(&pk.to_bytes())
        .chain(&msg)
        .finalize();

    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[..16].copy_from_slice(&hasher[..16]);
    let challenge = Scalar::from_bytes(&scalar_bytes).unwrap();
    let response = nonce + challenge * sk;

    let sig = (announcement, response);

    // verifier
    let hasher = Sha256::new()
        .chain(&announcement.to_bytes())
        .chain(&pk.to_bytes())
        .chain(&msg)
        .finalize();

    scalar_bytes[..16].copy_from_slice(&hasher[..16]);
    let challenge = Scalar::from_bytes(&scalar_bytes).unwrap();

    assert_eq!(
        response * G1Affine::generator(),
        announcement + challenge * pk
    );


    println!("| Message   : 0x{}", hex::encode(msg));
    println!("| Public key: 0x{}", hex::encode(pk.to_bytes()));
    println!("| Signature : (0x{}, 0x{})", hex::encode(sig.0.to_bytes()), hex::encode(sig.1.to_bytes()));
}

/// Schnorr signature in G2. This function returns a message `msg`, a public key `pk` and a
/// signature `(A, r)`.
///
/// To verify the signature, proceed as follows:
/// * hash = Sha256(A || pk || msg)
/// * c = hash mod `period`, where `period` is the order of the group defined over G2
/// * pk_deser = G2Decompress(pk)
/// * A_deser = G2Decompress(A)
/// * r_deser = IntegerFromBytes(r)
/// * Check that r_deser * G2Generator = A_deser + c * pk_deser
fn schnorr_g2(mut rng: impl RngCore + CryptoRng) {
    let mut msg = [0u8; 32];
    println!("+---------------------------------------------------------------------------+");
    println!("|                      Schnorr signature over G2                            |");
    println!("+---------------------------------------------------------------------------+");
    rng.fill(&mut msg);

    let sk = Scalar::random(&mut rng);
    let pk = sk * G2Affine::generator();
    let nonce = Scalar::random(&mut rng);
    let announcement = nonce * G2Affine::generator();
    let hasher = Sha256::new()
        .chain(&announcement.to_bytes())
        .chain(&pk.to_bytes())
        .chain(&msg)
        .finalize();

    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[..16].copy_from_slice(&hasher[..16]);
    let challenge = Scalar::from_bytes(&scalar_bytes).unwrap();
    let response = nonce + challenge * sk;

    let sig = (announcement, response);

    // verifier
    let hasher = Sha256::new()
        .chain(&announcement.to_bytes())
        .chain(&pk.to_bytes())
        .chain(&msg)
        .finalize();

    scalar_bytes[..16].copy_from_slice(&hasher[..16]);
    let challenge = Scalar::from_bytes(&scalar_bytes).unwrap();

    assert_eq!(
        response * G2Affine::generator(),
        announcement + challenge * pk
    );


    println!("| Message   : 0x{}", hex::encode(msg));
    println!("| Public key: 0x{}", hex::encode(pk.to_bytes()));
    println!("| Signature : (0x{}, 0x{})", hex::encode(sig.0.to_bytes()), hex::encode(sig.1.to_bytes()));
}

fn main() {
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
    println!("+---------------------------------------------------------------------------+");
    println!("|            Test vectors for E2E with BLS12-381 bindings                   |");
    println!("+---------------------------------------------------------------------------+");
    println!("|                                                                           |");
    bls_pk_g1(&mut rng);
    println!("|");
    bls_pk_g2(&mut rng);
    println!("|");
    aggr_bls_diff_msg_pk_g1(&mut rng);
    println!("|");
    aggr_bls_same_msg_pk_g2(&mut rng);
    println!("|");
    fast_aggr_bls_same_msg_pk_g2(&mut rng);
    println!("|");
    schnorr_g1(&mut rng);
    println!("|");
    schnorr_g2(&mut rng);
}
