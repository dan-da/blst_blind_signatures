use blst::min_pk::SecretKey;
use blst::{blst_fr, blst_p1_affine, blst_p2, blst_p2_affine, blst_scalar, Pairing};

fn main() {
    // ￼########################################################################
    // ￼# rudimentary blind signature PoC
    //

    let msg = b"assertion"; // this what we're signing
    let dst = b"MY-DST"; // domain separation tag

    let ikm = b"********************************"; // non-random for now.
    let ki = b"";

    // Mint: Generate Secret Key for signing
    let sk_rust = SecretKey::key_gen(ikm, ki).unwrap();

    // let ikm = b"********************************";   // non-random for now.
    // let sk_scalar_ikm = blst_scalar { b: *ikm };

    let sk_scalar = blst_scalar {
        b: sk_rust.to_bytes(),
    };

    let mut sk_be: [u8; 32] = Default::default();
    unsafe { blst::blst_bendian_from_scalar(&mut sk_be[0], &sk_scalar) };
    let sk_scalar_be = blst_scalar { b: sk_be };
    // println!("sk_scalar_be: {:?}", sk_scalar_be);

    let mut sk_fr: blst_fr = Default::default();
    unsafe { blst::blst_fr_from_scalar(&mut sk_fr, &sk_scalar) };

    // println!("sk_scalar: {:?}", sk_scalar);
    // println!("sk_rust: {:?}", sk_rust);
    // println!("sk_rust bytes: {:?}", sk_rust.serialize());

    // let mut sk_affine: blst_p1_affine = Default::default();
    // let result = unsafe { blst::blst_p1_from_fr(&mut sk_affine, &sk_fr ) };
    // println!("result: {:?}", result);

    // let mut sk: blst_p1 = Default::default();
    // unsafe { blst::blst_p1_from_affine(&mut sk, &sk_affine) };

    // println!("sk: {:?}", sk);

    // Mint: Create Signer PK
    // ￼# Signer's public key
    // let PK = blst.P1(SK).to_affine()

    let pk_rust = sk_rust.sk_to_pk();
    // println!("pk_rust: {:?}", pk_rust.serialize());

    let pk_bytes = pk_rust.serialize();

    let mut pk: blst_p1_affine = Default::default();
    unsafe { blst::blst_p1_deserialize(&mut pk, pk_bytes.as_ptr()) };

    let mut pk_bytes2: Vec<u8> = vec![0; 96];
    unsafe { blst::blst_p1_affine_serialize(&mut pk_bytes2[0], &pk) };

    println!("SK: {:?}", sk_scalar);
    println!("PK: {:?}", pk_bytes2);

    // User: Generate random r  (blinding factor)
    // ￼# User wants to have |msg| signed, chooses random |r|,
    // ￼r = blst.Scalar().from_bendian(os.urandom(32))

    let r_bytes = b"11111111111111111111111111111111"; // non-random for now.
    let r = blst_scalar { b: *r_bytes };
    println!("{:?}", r.b);

    // User: Hash message and blind it with r.
    // ￼# blinds the H(|msg|) with |r| and sends it to the Signer.
    // ￼sig_for_wire = blst.P2().hash_to(msg, DST).sign_with(r).serialize()

    let mut hash: blst_p2 = Default::default();
    let aug = b"";
    unsafe {
        blst::blst_hash_to_g2(
            &mut hash,
            msg.as_ptr(),
            msg.len(),
            dst.as_ptr(),
            dst.len(),
            aug.as_ptr(),
            aug.len(),
        )
    };

    // let mut hash_bytes: Vec<u8> = vec![0; 192];
    // unsafe { blst::blst_p2_serialize(&mut hash_bytes[0], &hash) };
    // println!("hash: {:?}", hash_bytes);

    let mut sig: blst_p2 = Default::default();
    unsafe { blst::blst_sign_pk_in_g1(&mut sig, &hash, &r) };
    let mut sig_for_wire: Vec<u8> = vec![0; 192];
    unsafe { blst::blst_p2_serialize(&mut sig_for_wire[0], &sig) };

    println!("sig_for_wire: {:?}", sig_for_wire);

    // Mint: Sign message
    // ￼# Signer signs and sends the result back to the User.
    // ￼sig_for_wire = blst.P2(sig_for_wire).sign_with(SK).serialize()

    let mut user_sig_affine: blst_p2_affine = Default::default();
    let mut rc = unsafe { blst::blst_p2_deserialize(&mut user_sig_affine, &sig_for_wire[0]) };
    println!("{:?}", rc);

    let mut user_sig: blst_p2 = Default::default();
    unsafe { blst::blst_p2_from_affine(&mut user_sig, &user_sig_affine) };

    let mut mint_sig: blst_p2 = Default::default();
    unsafe { blst::blst_sign_pk_in_g1(&mut mint_sig, &user_sig, &sk_scalar_be) };

    let mut mint_sig_for_wire = vec![0; 192];
    unsafe { blst::blst_p2_serialize(&mut mint_sig_for_wire[0], &mint_sig) };

    println!("mint_sig_for_wire: {:?}", mint_sig_for_wire);

    // User: Unblind and obtain mint's signature.
    // ￼# User unblinds the result with 1/|r| to produce the actual |signature|,
    // ￼signature = blst.P2(sig_for_wire).sign_with(r.inverse()).to_affine()

    let mut mint_sig_affine: blst_p2_affine = Default::default();
    rc = unsafe { blst::blst_p2_deserialize(&mut mint_sig_affine, &mint_sig_for_wire[0]) };
    println!("{:?}", rc);

    let mut mint_sig_user_copy: blst_p2 = Default::default();
    unsafe { blst::blst_p2_from_affine(&mut mint_sig_user_copy, &mint_sig_affine) };

    let mut r_fr: blst_fr = Default::default();
    unsafe { blst::blst_fr_from_scalar(&mut r_fr, &r) };

    let mut r_inverse_fr: blst_fr = Default::default();
    unsafe { blst::blst_fr_inverse(&mut r_inverse_fr, &r_fr) };

    let mut r_inverse: blst_scalar = Default::default();
    unsafe { blst::blst_scalar_from_fr(&mut r_inverse, &r_inverse_fr) };

    let mut signature: blst_p2 = Default::default();
    unsafe { blst::blst_sign_pk_in_g1(&mut signature, &mint_sig_user_copy, &r_inverse) };

    let mut sig_inverse = vec![0; 192];
    unsafe { blst::blst_p2_serialize(&mut sig_inverse[0], &signature) };

    println!("signature_inverse: {:?}", sig_inverse);

    // User: verify mint's signature.
    // ￼# and now it can be verified as following...
    // ￼ctx = blst.Pairing(True, DST)
    // ￼ctx.aggregate(PK, signature, msg)
    // ￼ctx.commit()
    // ￼if not ctx.finalverify():
    // ￼    raise AssertionError("disaster")
    // ￼
    // ￼print("OK")

    let mut sig_affine: blst_p2_affine = Default::default();
    unsafe { blst::blst_p2_to_affine(&mut sig_affine, &signature) };
    println!("sig_affine: {:?}", sig_affine);

    let mut ctx = Pairing::new(true, dst);
    println!("msg: {:?}", msg);
    let rc = ctx.aggregate(&pk, true, &sig_affine, true, msg, aug);
    println!("rc: {:?}", rc);
    ctx.commit();

    if !ctx.finalverify(None) {
        panic!("disaster");
    }

    // let mut ctx: blst_pairing = Default::default();
    // unsafe { blst::blst_pairing_init(&mut ctx, true, dst.as_ptr(), dst.len()) };

    // let rc = unsafe { blst::blst_pairing_aggregate_pk_in_g1(&mut ctx, &pk, &sig_affine, msg.as_ptr(), msg.len(), aug.as_ptr(), aug.len()) };
    // println!("rc: {:?}", rc);
    // unsafe { blst::blst_pairing_commit(&mut ctx)};

    // let ok = unsafe { blst::blst_pairing_finalverify(&mut ctx, std::ptr::null()) };
    // if !ok {
    //      panic!("disaster");
    // }

    println!("OK");
}
