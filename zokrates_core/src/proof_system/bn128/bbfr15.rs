extern crate libc;

use self::libc::{c_char, c_int};
use ir;
use std::ffi::CString;

//Unused import preserved for future contract/json support
//use proof_system::bn128::utils::solidity::{SOLIDITY_G2_ADDITION_LIB, SOLIDITY_PAIRING_LIB};
//use regex::Regex;
//use std::io::{BufRead, BufReader};
//use std::fs::File;

use zokrates_field::field::FieldPrime;

pub struct BBFR15 {}

impl BBFR15 {
    pub fn new() -> BBFR15 {
        BBFR15 {}
    }
}

impl BBFR15 {
    pub fn setup(&self, program: ir::Prog<FieldPrime>, pk_path: &str, vk_path: &str, pap_path: &str) {
    }

    pub fn generate_proof(
        &self,
        program: ir::Prog<FieldPrime>,
        witness: ir::Witness<FieldPrime>,
        pk_path: &str,
        proof_path: &str,
        authdata_path: &str,
        json_proof_path: &str
    ) -> bool {
        true
    }

    pub fn auth_setup(&self, pk_path: &str, sk_path: &str, pap_path: &str) {
    }

    pub fn auth_sign(&self, arguments: &Vec<FieldPrime>, sk_path: &str, label_path: &str, authdata_path: &str) {
    }

    pub fn verify_signature(&self, auth_pk_path: &str, label_path: &str, authdata_path: &str) -> bool {
        true
    }

    pub fn verify_proof(&self, vk_path: &str, auth_pk_path: &str, label_path: &str, authdata_path: &str, proof_path: &str) -> bool {
        true
    }

//No contract support now
/*
    pub fn export_solidity_verifier(&self, reader: BufReader<File>) -> String {
    }
*/

}
