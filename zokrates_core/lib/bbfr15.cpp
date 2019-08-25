#include "util.hpp"
#include "bbfr15.hpp"
#include <fstream>
#include <iostream>
#include <string>
#include <cassert>
#include <iomanip>

#include <type_traits>

using namespace std;

bool _bbfr15_setup(const uint8_t* A, const uint8_t* B, const uint8_t* C, int A_len, int B_len, int C_len, int constraints, int variables, int inputs, const char* pk_path, const char* vk_path, const char* pap_path)
{
  return true;
}

bool _bbfr15_generate_proof(const char* pk_path, const char* proof_path, const uint8_t* public_inputs, int public_inputs_length, const uint8_t* private_inputs, int private_inputs_length, const char* authdata_path, const char* json_proof_path)
{
  return true;
}

bool _bbfr15_auth_setup(const char* pk_path, const char* sk_path, const char* pap_path)
{
  return true;
}

bool _bbfr15_auth_sign(const uint8_t* arguments, int arg_len, const char*  sk_path, const char* label_path, const char* authdata_path)
{
  return true;
}

bool _bbfr15_verify_signature(const char* auth_pk_path, const char* label_path, const char* authdata_path)
{
  return true;
}

bool _bbfr15_verify_proof(const char* vk_path, const char* auth_pk_path, const char* label_path, const char* authdata_path, const char* proof_path)
{
  return true;
}
