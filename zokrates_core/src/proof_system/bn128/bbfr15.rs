extern crate libc;

use self::libc::{c_char, c_int};
use ir;
use proof_system::bn128::utils::libsnark::{prepare_generate_proof, prepare_setup, prepare_auth_sign};
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

extern "C" {
    fn _bbfr15_setup(
        A: *const u8,
        B: *const u8,
        C: *const u8,
        A_len: c_int,
        B_len: c_int,
        C_len: c_int,
        constraints: c_int,
        variables: c_int,
        inputs: c_int,
        pk_path: *const c_char,
        vk_path: *const c_char,
        pap_path: *const c_char,
    ) -> bool;

    fn _bbfr15_generate_proof(
        pk_path: *const c_char,
        proof_path: *const c_char,
        publquery_inputs: *const u8,
        publquery_inputs_length: c_int,
        private_inputs: *const u8,
        private_inputs_length: c_int,
        authdata_path: *const c_char,
        json_proof_path: *const c_char,
    ) -> bool;

    fn _bbfr15_auth_setup(
        pk_path: *const c_char,
        sk_path: *const c_char,
        pap_path: *const c_char,
    ) -> bool;

    fn _bbfr15_auth_sign(
        arguments: *const u8,
        arg_len: c_int,
        sk_path: *const c_char,
        label_path: *const c_char,
        authdata_path: *const c_char,
    ) -> bool;

    fn _bbfr15_verify_signature(
        auth_pk_path: *const c_char,
        label_path: *const c_char,
        authdata_path: *const c_char,
    ) -> bool;

    fn _bbfr15_verify_proof(
        vk_path: *const c_char,
        auth_pk_path: *const c_char,
        label_path: *const c_char,
        authdata_path: *const c_char,
        proof_path: *const c_char,
    ) -> bool;

}

impl BBFR15 {
    pub fn setup(&self, program: ir::Prog<FieldPrime>, pk_path: &str, vk_path: &str, pap_path: &str) {
        let (
            a_arr,
            b_arr,
            c_arr,
            a_vec,
            b_vec,
            c_vec,
            num_constraints,
            num_variables,
            num_inputs,
            pk_path_cstring,
            vk_path_cstring,
        ) = prepare_setup(program, pk_path, vk_path);

        let pap_path_cstring = CString::new(pap_path).unwrap();

        unsafe {
            _bbfr15_setup(
                a_arr.as_ptr(),
                b_arr.as_ptr(),
                c_arr.as_ptr(),
                a_vec.len() as i32,
                b_vec.len() as i32,
                c_vec.len() as i32,
                num_constraints as i32,
                num_variables as i32,
                num_inputs as i32,
                pk_path_cstring.as_ptr(),
                vk_path_cstring.as_ptr(),
                pap_path_cstring.as_ptr(),
            );
        }
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
        let (
            pk_path_cstring,
            proof_path_cstring,
            public_inputs_arr,
            public_inputs_length,
            private_inputs_arr,
            private_inputs_length,
        ) = prepare_generate_proof(program, witness, pk_path, proof_path);

        //Json output is preserved for future usage on contracts, currently not supported
        let json_proof_path_cstring = CString::new(json_proof_path).unwrap();
        let authdata_path_cstring = CString::new(authdata_path).unwrap();

        unsafe {
            _bbfr15_generate_proof(
                pk_path_cstring.as_ptr(),
                proof_path_cstring.as_ptr(),
                public_inputs_arr[0].as_ptr(),
                public_inputs_length as i32,
                private_inputs_arr[0].as_ptr(),
                private_inputs_length as i32,
                authdata_path_cstring.as_ptr(),
                json_proof_path_cstring.as_ptr(),
            )
        }
    }

    pub fn auth_setup(&self, pk_path: &str, sk_path: &str, pap_path: &str) {
        let pk_path_cstring = CString::new(pk_path).unwrap();
        let sk_path_cstring = CString::new(sk_path).unwrap();
        let pap_path_cstring = CString::new(pap_path).unwrap();

        unsafe{
            _bbfr15_auth_setup(
                pk_path_cstring.as_ptr(),
                sk_path_cstring.as_ptr(),
                pap_path_cstring.as_ptr(),
            );
        }
    }

    pub fn auth_sign(&self, arguments: &Vec<FieldPrime>, sk_path: &str, label_path: &str, authdata_path: &str) {
        let (
            arguments_arr,
            arguments_length,
            sk_path_cstring,
            label_path_cstring,
            authdata_path_cstring,
        ) = prepare_auth_sign(arguments, sk_path, label_path, authdata_path);

        unsafe{
            _bbfr15_auth_sign(
                arguments_arr[0].as_ptr(),
                arguments_length as i32,
                sk_path_cstring.as_ptr(),
                label_path_cstring.as_ptr(),
                authdata_path_cstring.as_ptr(),
            );
        }
    }

    pub fn verify_signature(&self, auth_pk_path: &str, label_path: &str, authdata_path: &str) -> bool {
        let auth_pk_path_cstring = CString::new(auth_pk_path).unwrap();
        let label_path_cstring = CString::new(label_path).unwrap();
        let authdata_path_cstring = CString::new(authdata_path).unwrap();

        unsafe{
            _bbfr15_verify_signature(
                auth_pk_path_cstring.as_ptr(),
                label_path_cstring.as_ptr(),
                authdata_path_cstring.as_ptr(),
            )
        }
    }

    pub fn verify_proof(&self, vk_path: &str, auth_pk_path: &str, label_path: &str, authdata_path: &str, proof_path: &str) -> bool {
        let vk_path_cstring = CString::new(vk_path).unwrap();
        let auth_pk_path_cstring = CString::new(auth_pk_path).unwrap();
        let label_path_cstring = CString::new(label_path).unwrap();
        let authdata_path_cstring = CString::new(authdata_path).unwrap();
        let proof_path_cstring = CString::new(proof_path).unwrap();

        unsafe{
            _bbfr15_verify_proof(
                vk_path_cstring.as_ptr(),
                auth_pk_path_cstring.as_ptr(),
                label_path_cstring.as_ptr(),
                authdata_path_cstring.as_ptr(),
                proof_path_cstring.as_ptr(),
            )
        }
    }

//No contract support now
/*
    pub fn export_solidity_verifier(&self, reader: BufReader<File>) -> String {
    }
*/

}
