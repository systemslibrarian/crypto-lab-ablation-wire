#![cfg(feature = "pq")]

use libcrux_traits::{
    kem::arrayref::Kem,
    libcrux_secrets::{Classify, Declassify, DeclassifyRef, U8},
};

#[test]
fn typed_sha3_matches_released_portable_api_across_rate_boundaries() {
    for input_len in [0, 1, 71, 72, 73, 135, 136, 137, 167, 168, 169, 336] {
        let input: Vec<u8> = (0..input_len)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
            .collect();
        let typed_input: Vec<U8> = input.iter().copied().map(U8).collect();

        let mut expected_256 = [0u8; 32];
        libcrux_sha3::portable::sha256(&mut expected_256, &input);
        let mut actual_256 = [U8(0); 32];
        libcrux_sha3::secret::sha256(&mut actual_256, &typed_input);
        assert_eq!(actual_256.declassify(), expected_256);

        let mut expected_512 = [0u8; 64];
        libcrux_sha3::portable::sha512(&mut expected_512, &input);
        let mut actual_512 = [U8(0); 64];
        libcrux_sha3::secret::sha512(&mut actual_512, &typed_input);
        assert_eq!(actual_512.declassify(), expected_512);

        for output_len in [0, 1, 31, 32, 71, 72, 135, 136, 137, 167, 168, 169, 400] {
            let mut expected_128 = vec![0u8; output_len];
            libcrux_sha3::portable::shake128(&mut expected_128, &input);
            let mut actual_128 = vec![U8(0); output_len];
            libcrux_sha3::secret::shake128(&mut actual_128, &typed_input);
            assert_eq!(actual_128.as_slice().declassify_ref(), expected_128);

            let mut expected_256 = vec![0u8; output_len];
            libcrux_sha3::portable::shake256(&mut expected_256, &input);
            let mut actual_256 = vec![U8(0); output_len];
            libcrux_sha3::secret::shake256(&mut actual_256, &typed_input);
            assert_eq!(actual_256.as_slice().declassify_ref(), expected_256);
        }
    }
}

macro_rules! assert_mlkem_typed_path_matches_release_api {
    (
        $name:ident,
        $variant:ty,
        $generate:path,
        $encapsulate:path,
        $decapsulate:path,
        $ek_len:expr,
        $dk_len:expr,
        $ct_len:expr
    ) => {
        #[test]
        fn $name() {
            const EK_LEN: usize = $ek_len;
            const DK_LEN: usize = $dk_len;
            const CT_LEN: usize = $ct_len;

            for case_number in 0..8u8 {
                let key_seed = core::array::from_fn::<_, 64, _>(|i| {
                    (i as u8).wrapping_mul(17).wrapping_add(case_number)
                });
                let encaps_seed = core::array::from_fn::<_, 32, _>(|i| {
                    (i as u8)
                        .wrapping_mul(29)
                        .wrapping_add(case_number.wrapping_mul(3))
                });
                let typed_key_seed = key_seed.classify();
                let typed_encaps_seed = encaps_seed.classify();

                let mut ek = [0u8; EK_LEN];
                let mut dk = [U8(0); DK_LEN];
                <$variant as Kem<EK_LEN, DK_LEN, CT_LEN, 32, 64, 32>>::keygen(
                    &mut ek,
                    &mut dk,
                    &typed_key_seed,
                )
                .unwrap();

                let release_keypair = $generate(key_seed);
                assert_eq!(ek.as_slice(), release_keypair.pk().as_slice());
                assert_eq!(dk.declassify().as_slice(), release_keypair.sk().as_slice());

                let mut ct = [0u8; CT_LEN];
                let mut ss = [U8(0); 32];
                <$variant as Kem<EK_LEN, DK_LEN, CT_LEN, 32, 64, 32>>::encaps(
                    &mut ct,
                    &mut ss,
                    &ek,
                    &typed_encaps_seed,
                )
                .unwrap();

                let (release_ct, release_ss) = $encapsulate(release_keypair.public_key(), encaps_seed);
                assert_eq!(ct.as_slice(), release_ct.as_slice());
                assert_eq!(ss.declassify().as_slice(), release_ss.as_slice());

                let mut decapsulated = [U8(0); 32];
                <$variant as Kem<EK_LEN, DK_LEN, CT_LEN, 32, 64, 32>>::decaps(&mut decapsulated, &ct, &dk)
                    .unwrap();
                assert_eq!(decapsulated.declassify(), ss.declassify());

                // Invalid ciphertexts at each region of the encoding must take
                // implicit rejection and match the released implementation.
                for invalid_index in [0, CT_LEN / 2, CT_LEN - 1] {
                    let mut invalid_ct = ct;
                    invalid_ct[invalid_index] ^= 0x80;
                    let mut rejected = [U8(0); 32];
                    <$variant as Kem<EK_LEN, DK_LEN, CT_LEN, 32, 64, 32>>::decaps(
                        &mut rejected,
                        &invalid_ct,
                        &dk,
                    )
                    .unwrap();
                    let invalid_release_ct = invalid_ct.into();
                    let release_rejected = $decapsulate(release_keypair.private_key(), &invalid_release_ct);
                    assert_eq!(
                        rejected.declassify().as_slice(),
                        release_rejected.as_slice()
                    );
                    assert_ne!(rejected.declassify(), ss.declassify());
                }
            }
        }
    };
}

assert_mlkem_typed_path_matches_release_api!(
    mlkem512_typed_path_matches_release_api,
    libcrux_ml_kem::mlkem512::MlKem512,
    libcrux_ml_kem::mlkem512::generate_key_pair,
    libcrux_ml_kem::mlkem512::encapsulate,
    libcrux_ml_kem::mlkem512::decapsulate,
    800,
    1632,
    768
);

assert_mlkem_typed_path_matches_release_api!(
    mlkem768_typed_path_matches_release_api,
    libcrux_ml_kem::mlkem768::MlKem768,
    libcrux_ml_kem::mlkem768::generate_key_pair,
    libcrux_ml_kem::mlkem768::encapsulate,
    libcrux_ml_kem::mlkem768::decapsulate,
    1184,
    2400,
    1088
);

assert_mlkem_typed_path_matches_release_api!(
    mlkem1024_typed_path_matches_release_api,
    libcrux_ml_kem::mlkem1024::MlKem1024,
    libcrux_ml_kem::mlkem1024::generate_key_pair,
    libcrux_ml_kem::mlkem1024::encapsulate,
    libcrux_ml_kem::mlkem1024::decapsulate,
    1568,
    3168,
    1568
);

#[test]
fn xwing_typed_path_matches_release_api() {
    use libcrux_kem::{Algorithm, Ct, XWing};

    const EK_LEN: usize = 1216;
    const DK_LEN: usize = 2432;
    const CT_LEN: usize = 1120;

    for case_number in 0..8u8 {
        let key_seed =
            core::array::from_fn::<_, 32, _>(|i| (i as u8).wrapping_mul(13).wrapping_add(case_number));
        let encaps_seed = core::array::from_fn::<_, 64, _>(|i| {
            (i as u8)
                .wrapping_mul(7)
                .wrapping_add(case_number.wrapping_mul(5))
        });
        let mut ek = [0u8; EK_LEN];
        let mut dk = [U8(0); DK_LEN];
        <XWing as Kem<EK_LEN, DK_LEN, CT_LEN, 32, 32, 64>>::keygen(&mut ek, &mut dk, &key_seed.classify())
            .unwrap();

        let (release_private, release_public) =
            libcrux_kem::key_gen_derand(Algorithm::XWingKemDraft06, &key_seed).unwrap();
        assert_eq!(ek.as_slice(), release_public.encode().as_slice());

        let mut ct = [0u8; CT_LEN];
        let mut ss = [U8(0); 32];
        <XWing as Kem<EK_LEN, DK_LEN, CT_LEN, 32, 32, 64>>::encaps(
            &mut ct,
            &mut ss,
            &ek,
            &encaps_seed.classify(),
        )
        .unwrap();
        let (release_ss, release_ct) = release_public.encapsulate_derand(&encaps_seed).unwrap();
        assert_eq!(ct.as_slice(), release_ct.encode().as_slice());
        assert_eq!(ss.declassify().as_slice(), release_ss.encode().as_slice());

        let mut decapsulated = [U8(0); 32];
        <XWing as Kem<EK_LEN, DK_LEN, CT_LEN, 32, 32, 64>>::decaps(&mut decapsulated, &ct, &dk).unwrap();
        assert_eq!(decapsulated.declassify(), ss.declassify());

        for invalid_index in [0, CT_LEN / 2, CT_LEN - 1] {
            let mut invalid_ct = ct;
            invalid_ct[invalid_index] ^= 0x80;
            let decoded_invalid = Ct::decode(Algorithm::XWingKemDraft06, &invalid_ct).unwrap();
            let release_rejected = decoded_invalid.decapsulate(&release_private).unwrap();
            let mut rejected = [U8(0); 32];
            <XWing as Kem<EK_LEN, DK_LEN, CT_LEN, 32, 32, 64>>::decaps(&mut rejected, &invalid_ct, &dk)
                .unwrap();
            assert_eq!(
                rejected.declassify().as_slice(),
                release_rejected.encode().as_slice()
            );
        }
    }
}
