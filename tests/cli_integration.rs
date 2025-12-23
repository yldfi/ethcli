//! CLI integration tests
//!
//! Tests the ethcli binary end-to-end for offline commands

use assert_cmd::Command;
use predicates::prelude::*;

fn ethcli() -> Command {
    Command::cargo_bin("ethcli").unwrap()
}

// ==================== Basic CLI tests ====================

#[test]
fn test_version() {
    ethcli()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("ethcli"));
}

#[test]
fn test_help() {
    ethcli()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Comprehensive Ethereum CLI"));
}

#[test]
fn test_cast_help() {
    ethcli()
        .args(["cast", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("to-wei"));
}

// ==================== Cast conversion tests ====================

#[test]
fn test_cast_to_hex() {
    ethcli()
        .args(["cast", "to-hex", "255"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0xff"));
}

#[test]
fn test_cast_to_hex_large() {
    ethcli()
        .args(["cast", "to-hex", "1000000"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0xf4240"));
}

#[test]
fn test_cast_to_dec() {
    ethcli()
        .args(["cast", "to-dec", "0xff"])
        .assert()
        .success()
        .stdout(predicate::str::contains("255"));
}

#[test]
fn test_cast_to_dec_without_prefix() {
    ethcli()
        .args(["cast", "to-dec", "ff"])
        .assert()
        .success()
        .stdout(predicate::str::contains("255"));
}

#[test]
fn test_cast_to_wei_eth() {
    ethcli()
        .args(["cast", "to-wei", "1", "eth"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1000000000000000000"));
}

#[test]
fn test_cast_to_wei_decimal() {
    ethcli()
        .args(["cast", "to-wei", "1.5", "eth"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1500000000000000000"));
}

#[test]
fn test_cast_to_wei_gwei() {
    ethcli()
        .args(["cast", "to-wei", "1", "gwei"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1000000000"));
}

#[test]
fn test_cast_from_wei_eth() {
    ethcli()
        .args(["cast", "from-wei", "1000000000000000000", "eth"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1.0"));
}

#[test]
fn test_cast_from_wei_gwei() {
    ethcli()
        .args(["cast", "from-wei", "1000000000", "gwei"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1.0"));
}

// ==================== Cast hashing tests ====================

#[test]
fn test_cast_keccak_string() {
    ethcli()
        .args(["cast", "keccak", "hello"])
        .assert()
        .success()
        // keccak256("hello") = 0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
        .stdout(predicate::str::contains(
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8",
        ));
}

#[test]
fn test_cast_sig_transfer() {
    ethcli()
        .args(["cast", "sig", "transfer(address,uint256)"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0xa9059cbb"));
}

#[test]
fn test_cast_sig_approve() {
    ethcli()
        .args(["cast", "sig", "approve(address,uint256)"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0x095ea7b3"));
}

#[test]
fn test_cast_sig_balance_of() {
    ethcli()
        .args(["cast", "sig", "balanceOf(address)"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0x70a08231"));
}

#[test]
fn test_cast_topic_transfer() {
    ethcli()
        .args(["cast", "topic", "Transfer(address,address,uint256)"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        ));
}

// ==================== Cast address tests ====================

#[test]
fn test_cast_checksum() {
    ethcli()
        .args([
            "cast",
            "checksum",
            "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
        ])
        .assert()
        .success()
        // EIP-55 checksummed address
        .stdout(predicate::str::contains(
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        ));
}

#[test]
fn test_cast_checksum_already_valid() {
    ethcli()
        .args([
            "cast",
            "checksum",
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        ));
}

// ==================== Cast bytes32 tests ====================

#[test]
fn test_cast_to_bytes32() {
    ethcli()
        .args(["cast", "to-bytes32", "0x01"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        ));
}

#[test]
fn test_cast_to_bytes32_larger() {
    ethcli()
        .args(["cast", "to-bytes32", "0xabcd"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "0x000000000000000000000000000000000000000000000000000000000000abcd",
        ));
}

// ==================== Cast concat tests ====================

#[test]
fn test_cast_concat() {
    ethcli()
        .args(["cast", "concat", "0xaa", "0xbb", "0xcc"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0xaabbcc"));
}

// ==================== ENS tests (offline) ====================

#[test]
fn test_ens_namehash() {
    ethcli()
        .args(["ens", "namehash", "vitalik.eth"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "0xee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a53475835",
        ));
}

#[test]
fn test_ens_namehash_eth() {
    ethcli()
        .args(["ens", "namehash", "eth"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae",
        ));
}

// ==================== Error handling tests ====================

#[test]
fn test_cast_to_wei_invalid_unit() {
    ethcli()
        .args(["cast", "to-wei", "1", "invalid"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown unit"));
}

#[test]
fn test_cast_to_wei_invalid_value() {
    ethcli()
        .args(["cast", "to-wei", "not_a_number", "eth"])
        .assert()
        .failure();
}

#[test]
fn test_cast_to_dec_invalid_hex() {
    ethcli()
        .args(["cast", "to-dec", "0xZZZ"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid hex"));
}

#[test]
fn test_cast_checksum_invalid_address() {
    ethcli()
        .args(["cast", "checksum", "not_an_address"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid address"));
}

// ==================== ABI encode/decode tests ====================

#[test]
fn test_cast_abi_encode_no_args() {
    ethcli()
        .args(["cast", "abi-encode", "totalSupply()"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0x18160ddd"));
}

#[test]
fn test_cast_abi_encode_with_args() {
    ethcli()
        .args([
            "cast",
            "abi-encode",
            "transfer(address,uint256)",
            "0x0000000000000000000000000000000000000001",
            "1000",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("0xa9059cbb"));
}
