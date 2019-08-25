#include "util.hpp"
#include "bbfr15.hpp"
#include <fstream>
#include <iostream>
#include <string>
#include <cassert>
#include <iomanip>

#include <type_traits>

#include <libff/common/profiling.hpp>

// contains definition of alt_bn128 ec public parameters
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"
// contains ADSNARK pp type
#include "r1cs_ppzkadsnark_pp.hpp"
// contains our prf and signature scheme for authentication
#include "prf/aes_ctr_prf.tcc"
#include "signature/ed25519_signature.tcc"
// contains required interfaces and types (keypair, proof, generator, prover, verifier)
#include <libsnark/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark.hpp>

using namespace std;
using namespace libsnark;

namespace bbfr15 {

//takes input and puts it into constraint system
r1cs_ppzkadsnark_constraint_system<r1cs_ppzkadsnark_pp> createConstraintSystem(const uint8_t* A, const uint8_t* B, const uint8_t* C, int A_len, int B_len, int C_len, int constraints, int variables, int inputs)
{
  r1cs_ppzkadsnark_constraint_system<r1cs_ppzkadsnark_pp> cs;
  cs.primary_input_size = inputs;
  cs.auxiliary_input_size = variables - inputs - 1; // ~one not included

  cout << "num variables: " << variables <<endl;
  cout << "num constraints: " << constraints <<endl;
  cout << "num inputs: " << inputs <<endl;

  struct VariableValueMapping {
    int constraint_id;
    int variable_id;
    uint8_t variable_value[32];
  };
  const VariableValueMapping* A_vvmap = (VariableValueMapping*) A;
  const VariableValueMapping* B_vvmap = (VariableValueMapping*) B;
  const VariableValueMapping* C_vvmap = (VariableValueMapping*) C;

  int A_id = 0;
  int B_id = 0;
  int C_id = 0;

  libff::alt_bn128_pp::init_public_params();

  for (int row = 0; row < constraints; row++) {
    linear_combination<libff::Fr<libff::alt_bn128_pp> > lin_comb_A, lin_comb_B, lin_comb_C;

    while (A_id < A_len && A_vvmap[A_id].constraint_id == row) {
      libff::bigint<libff::alt_bn128_r_limbs> value = libsnarkBigintFromBytes(A_vvmap[A_id].variable_value);
      if (!value.is_zero())
        lin_comb_A.add_term(A_vvmap[A_id].variable_id, value);
      A_id++;
    }
    while (B_id < B_len && B_vvmap[B_id].constraint_id == row) {
      libff::bigint<libff::alt_bn128_r_limbs> value = libsnarkBigintFromBytes(B_vvmap[B_id].variable_value);
      if (!value.is_zero())
        lin_comb_B.add_term(B_vvmap[B_id].variable_id, value);
      B_id++;
    }
    while (C_id < C_len && C_vvmap[C_id].constraint_id == row) {
      libff::bigint<libff::alt_bn128_r_limbs> value = libsnarkBigintFromBytes(C_vvmap[C_id].variable_value);
      if (!value.is_zero())
        lin_comb_C.add_term(C_vvmap[C_id].variable_id, value);
      C_id++;
    }

    cs.add_constraint(r1cs_constraint<libff::Fr<libff::alt_bn128_pp> >(lin_comb_A, lin_comb_B, lin_comb_C));
  }

  return cs;
}

// load label from label file
vector<labelT> loadLabelFromFile(const char* label_path){
  ifstream label_file(label_path);
  assert(label_file.is_open());

  int label_count;
  label_file>>label_count;
  vector<labelT> ret;
  if(label_count <= 0){
    return ret;
  }
  ret.reserve(label_count);
  string remaining_line;
  getline(label_file, remaining_line);
  for(int i=0; i<label_count; i++){
    string line;
    getline(label_file, line);
    labelT label;

    // labelT is now restricted to 16 bytes long, so longer label will be truncated
    // One may modify the r1cs_ppzkadsnark_params.hpp from libsnark backend to extend its length
    // Beware that prf and signature should be modified at the same time
    for(int i=0; i<16; i++){
      if(line.length()>i) label.label_bytes[i] = static_cast<unsigned char>(line[i]);
      else label.label_bytes[i] = 0;
    }
    ret.emplace_back(label);
  }
  return ret;
}

// Stores Authdata to Files
// Each authdata is stored in seperated file to resolve parsing issue
// Files will be stored to authdata_path concatenated with the id.
void writeAuthdataToFile(const char* authdata_path, vector<r1cs_ppzkadsnark_auth_data<r1cs_ppzkadsnark_pp>> authdata){
  int authdata_len = authdata.size();
  for(int i=0; i<authdata_len; i++){
    string authdata_path_i = authdata_path + to_string(i);
    writeToFile(authdata_path_i, authdata[i]);
  }
}

// Load Authdata from file
vector<r1cs_ppzkadsnark_auth_data<r1cs_ppzkadsnark_pp>> loadAuthdataFromFile(const char* authdata_path, int authdata_len){
  vector<r1cs_ppzkadsnark_auth_data<r1cs_ppzkadsnark_pp>> ret;
  if(authdata_len <= 0){
    return ret;
  }
  ret.reserve(authdata_len);
  for(int i=0; i<authdata_len; i++){
    string authdata_path_i = authdata_path + to_string(i);
    auto authdata = loadFromFile< r1cs_ppzkadsnark_auth_data<r1cs_ppzkadsnark_pp>>(authdata_path_i);
    ret.emplace_back(authdata);
  }
  return ret;
}


}


bool _bbfr15_setup(const uint8_t* A, const uint8_t* B, const uint8_t* C, int A_len, int B_len, int C_len, int constraints, int variables, int inputs, const char* pk_path, const char* vk_path, const char* pap_path)
{
  //ban libff profiling output
  libff::inhibit_profiling_info = true;
  libff::inhibit_profiling_counters = true;

  //initialize curve parameters
  libff::alt_bn128_pp::init_public_params();

  auto cs = bbfr15::createConstraintSystem(A, B, C, A_len, B_len, C_len, constraints, variables, inputs);

  assert(cs.num_variables() >= (unsigned)inputs);
  assert(cs.num_inputs() == (unsigned)inputs);
  assert(cs.num_constraints() == (unsigned)constraints);

  auto pap = loadFromFile<r1cs_ppzkadsnark_pub_auth_prms<r1cs_ppzkadsnark_pp>>(pap_path);


  // create keypair
  auto keypair = r1cs_ppzkadsnark_generator<r1cs_ppzkadsnark_pp>(cs, pap);

  // Export vk and pk to files
  writeToFile(pk_path, keypair.pk);
  writeToFile(vk_path, keypair.vk);
  return true;
}

bool _bbfr15_generate_proof(const char* pk_path, const char* proof_path, const uint8_t* public_inputs, int public_inputs_length, const uint8_t* private_inputs, int private_inputs_length, const char* authdata_path, const char* json_proof_path)
{
  //ban libff profiling output
  libff::inhibit_profiling_info = true;
  libff::inhibit_profiling_counters = true;

  //initialize curve parameters
  libff::alt_bn128_pp::init_public_params();

  auto pk = loadFromFile<r1cs_ppzkadsnark_proving_key<r1cs_ppzkadsnark_pp>>(pk_path);
  auto authdata = bbfr15::loadAuthdataFromFile(authdata_path, pk.constraint_system.num_inputs());

  // assign variables based on witness values, excludes ~one
  r1cs_variable_assignment<libff::Fr<libff::alt_bn128_pp> > full_variable_assignment;
  for (int i = 1; i < public_inputs_length; i++) {
    full_variable_assignment.push_back(libff::Fr<libff::alt_bn128_pp>(libsnarkBigintFromBytes(public_inputs + i*32)));
  }
  for (int i = 0; i < private_inputs_length; i++) {
    full_variable_assignment.push_back(libff::Fr<libff::alt_bn128_pp>(libsnarkBigintFromBytes(private_inputs + i*32)));
  }

  // split up variables into primary and auxiliary inputs. Does *NOT* include the constant 1
  // Public variables belong to primary input, private variables are auxiliary input.
  r1cs_primary_input<libff::Fr<libff::alt_bn128_pp>> primary_input(full_variable_assignment.begin(), full_variable_assignment.begin() + public_inputs_length-1);
  r1cs_primary_input<libff::Fr<libff::alt_bn128_pp>> auxiliary_input(full_variable_assignment.begin() + public_inputs_length-1, full_variable_assignment.end());

  // for debugging
  // cout << "full variable assignment:"<< endl << full_variable_assignment;
  // cout << "primary input:"<< endl << primary_input;
  // cout << "auxiliary input:"<< endl << auxiliary_input;

  // Proof Generation
  auto proof = r1cs_ppzkadsnark_prover<r1cs_ppzkadsnark_pp>(pk, primary_input, auxiliary_input, authdata);

  writeToFile(proof_path, proof);

  //Json proof currently not supported
  //bbfr15::exportProof(proof, json_proof_path, public_inputs, public_inputs_length);

  return true;
}

bool _bbfr15_auth_setup(const char* pk_path, const char* sk_path, const char* pap_path)
{
  //ban libff profiling output
  libff::inhibit_profiling_info = true;
  libff::inhibit_profiling_counters = true;

  //initialize curve parameters
  libff::alt_bn128_pp::init_public_params();

  r1cs_ppzkadsnark_auth_keys<r1cs_ppzkadsnark_pp> auth_keys = r1cs_ppzkadsnark_auth_generator<r1cs_ppzkadsnark_pp>();
  writeToFile(pk_path, auth_keys.pak);
  writeToFile(sk_path, auth_keys.sak);
  writeToFile(pap_path, auth_keys.pap);
  return true;
}

bool _bbfr15_auth_sign(const uint8_t* arguments, int arg_len, const char*  sk_path, const char* label_path, const char* authdata_path)
{
  //ban libff profiling output
  libff::inhibit_profiling_info = true;
  libff::inhibit_profiling_counters = true;

  //initialize curve parameters
  libff::alt_bn128_pp::init_public_params();

  //assign arguments to vector data
  std::vector<libff::Fr<snark_pp<r1cs_ppzkadsnark_pp>>> data;
  for (int i = 0; i < arg_len; i++) {
    data.push_back(libff::Fr<libff::alt_bn128_pp>(libsnarkBigintFromBytes(arguments + i*32)));
  }

  std::vector<labelT> labels = bbfr15::loadLabelFromFile(label_path);
  auto sk = loadFromFile<r1cs_ppzkadsnark_sec_auth_key<r1cs_ppzkadsnark_pp>>(sk_path);
  std::vector<r1cs_ppzkadsnark_auth_data<r1cs_ppzkadsnark_pp>> auth_data = r1cs_ppzkadsnark_auth_sign<r1cs_ppzkadsnark_pp>(data, sk ,labels);
  bbfr15::writeAuthdataToFile(authdata_path, auth_data);

  return true;
}

//Directly calls verify funtion in ed25519_signature
//Designed mostly for testing propose
//The entired function is already contained in the _bbfr15_verify_proof function
bool _bbfr15_verify_signature(const char* auth_pk_path, const char* label_path, const char* authdata_path)
{
  //initialize curve parameters
  libff::alt_bn128_pp::init_public_params();

  auto pk = loadFromFile<r1cs_ppzkadsnark_pub_auth_key<r1cs_ppzkadsnark_pp>>(auth_pk_path);

  std::vector<labelT> labels = bbfr15::loadLabelFromFile(label_path);
  std::vector<r1cs_ppzkadsnark_auth_data<r1cs_ppzkadsnark_pp>> authdata = bbfr15::loadAuthdataFromFile(authdata_path, labels.size());

  std::vector<libff::G2<snark_pp<r1cs_ppzkadsnark_pp>>> Lambdas;
  std::vector<r1cs_ppzkadsnark_sigT<r1cs_ppzkadsnark_pp>> sigs;
  Lambdas.reserve(labels.size());
  sigs.reserve(labels.size());
  for (size_t i = 0; i < labels.size();i++) {
      Lambdas.emplace_back(authdata[i].Lambda);
      sigs.emplace_back(authdata[i].sigma);
  }

  bool result_auth = sigBatchVerif<r1cs_ppzkadsnark_pp>(pk.vkp,labels,Lambdas,sigs);
  return result_auth;
}

bool _bbfr15_verify_proof(const char* vk_path, const char* auth_pk_path, const char* label_path, const char* authdata_path, const char* proof_path)
{
  //ban libff profiling output
  libff::inhibit_profiling_info = true;
  libff::inhibit_profiling_counters = true;

  //initialize curve parameters
  libff::alt_bn128_pp::init_public_params();

  auto auth_pk = loadFromFile<r1cs_ppzkadsnark_pub_auth_key<r1cs_ppzkadsnark_pp>>(auth_pk_path);
  auto vk = loadFromFile<r1cs_ppzkadsnark_verification_key<r1cs_ppzkadsnark_pp>>(vk_path);
  auto proof = loadFromFile<r1cs_ppzkadsnark_proof<r1cs_ppzkadsnark_pp>>(proof_path);
  std::vector<labelT> labels = bbfr15::loadLabelFromFile(label_path);
  std::vector<r1cs_ppzkadsnark_auth_data<r1cs_ppzkadsnark_pp>> authdata = bbfr15::loadAuthdataFromFile(authdata_path, labels.size());
  bool result = r1cs_ppzkadsnark_verifier(vk, authdata, proof, auth_pk, labels);
  return result;
}
