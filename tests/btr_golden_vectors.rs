//! BTR golden vector conformance tests (PROTOCOL-HARDENING-1).
//!
//! Consumes the canonical golden vectors from bolt-core/test-vectors/btr/
//! and verifies that bolt_btr produces identical outputs. This proves the
//! daemon's BTR implementation matches the canonical vector generator.
//!
//! If a TypeScript implementation also passes these same vectors, it proves
//! cross-implementation compatibility.

use bolt_btr::key_schedule::{chain_advance, derive_session_root, derive_transfer_root};

fn hex_to_32(hex: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

// ── Session root derivation vectors ─────────────────────────

#[test]
fn golden_session_root_vector_0() {
    let shared = hex_to_32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let expected = hex_to_32("beff9b312b06cff7d24e1acb6fddc01cf12ab35eca1c93cf498433b51f8ae488");
    let result = derive_session_root(&shared);
    assert_eq!(result, expected, "session-root-0 mismatch");
}

#[test]
fn golden_session_root_vector_1() {
    let shared = hex_to_32("32333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051");
    let expected = hex_to_32("2119b11d9a46af3f381d3567ff21a127517ede4fcf4337848fedda6289f6a2ca");
    let result = derive_session_root(&shared);
    assert_eq!(result, expected, "session-root-1 mismatch");
}

#[test]
fn golden_session_root_vector_2() {
    let shared = hex_to_32("6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283");
    let expected = hex_to_32("7db9ef6fa789fcc7401a5351f1932744fcbc8bc5ade144ab2172f3bd99a74bae");
    let result = derive_session_root(&shared);
    assert_eq!(result, expected, "session-root-2 mismatch");
}

// ── Chain advance vectors ───────────────────────────────────

#[test]
fn golden_chain_advance_vector_0() {
    let chain_key = hex_to_32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    let expected_msg = hex_to_32("a4e53f48d6a8f6f992802dc0dab2ac6aaac4fa3baf75c8c02f4f60a273fcdfb1");
    let expected_next = hex_to_32("aa659d2f3fc3391c814e634b230e1a3160e0be9df47d78912284064f2746f033");
    let result = chain_advance(&chain_key);
    assert_eq!(result.message_key, expected_msg, "chain-step-0 message_key");
    assert_eq!(result.next_chain_key, expected_next, "chain-step-0 next_chain_key");
}

#[test]
fn golden_chain_advance_vector_1() {
    // Step 1 uses step 0's next_chain_key as input
    let chain_key = hex_to_32("aa659d2f3fc3391c814e634b230e1a3160e0be9df47d78912284064f2746f033");
    let expected_msg = hex_to_32("e0a8b8b0ea44123935b1f88a424c433acdb381e7856ddc436251332aa56d9fec");
    let expected_next = hex_to_32("80c50c2d3d490ec0e26163ef84216a7da12c0888ae7062ee052653e567cfe516");
    let result = chain_advance(&chain_key);
    assert_eq!(result.message_key, expected_msg, "chain-step-1 message_key");
    assert_eq!(result.next_chain_key, expected_next, "chain-step-1 next_chain_key");
}

#[test]
fn golden_chain_advance_5_step_sequence() {
    // Verify the full 5-step chain from the vector file
    let vectors = [
        ("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
         "a4e53f48d6a8f6f992802dc0dab2ac6aaac4fa3baf75c8c02f4f60a273fcdfb1",
         "aa659d2f3fc3391c814e634b230e1a3160e0be9df47d78912284064f2746f033"),
        ("aa659d2f3fc3391c814e634b230e1a3160e0be9df47d78912284064f2746f033",
         "e0a8b8b0ea44123935b1f88a424c433acdb381e7856ddc436251332aa56d9fec",
         "80c50c2d3d490ec0e26163ef84216a7da12c0888ae7062ee052653e567cfe516"),
        ("80c50c2d3d490ec0e26163ef84216a7da12c0888ae7062ee052653e567cfe516",
         "81423f1ed1362e31990e322b853e44c9a6432c019289dd14ea53e5c27a114f38",
         "b8052f35de3c61fe1ac18194ba324198638295058394199a064248a07d6d9eeb"),
        ("b8052f35de3c61fe1ac18194ba324198638295058394199a064248a07d6d9eeb",
         "0fa892a7a8cccdf2b31a1c18f562d5fdbb9be65f8db74b281cd9292603f9532a",
         "98862be8d26835422b5eea3bcf8a4ca533d7e70bbeb5d474e99e3fceb6521ce8"),
        ("98862be8d26835422b5eea3bcf8a4ca533d7e70bbeb5d474e99e3fceb6521ce8",
         "76a604f2f269647ff15bc9edcb53950cbed8ea3a7d18a91d57605a531b604e0e",
         "05c5a95e88b64ebcd2b4730cea6bae97b4c4e69d4edf1b9abfc09b6d12af4399"),
    ];

    for (i, (chain_hex, msg_hex, next_hex)) in vectors.iter().enumerate() {
        let chain_key = hex_to_32(chain_hex);
        let expected_msg = hex_to_32(msg_hex);
        let expected_next = hex_to_32(next_hex);
        let result = chain_advance(&chain_key);
        assert_eq!(result.message_key, expected_msg, "step {i} message_key");
        assert_eq!(result.next_chain_key, expected_next, "step {i} next_chain_key");
    }
}
