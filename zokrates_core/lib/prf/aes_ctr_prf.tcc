/** @file
 *****************************************************************************

 AES-Based PRF for ADSNARK.

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include<iostream>
#include "gmp.h"
#include "crypto_core_aes128encrypt.h"
#include "randombytes.h"

#include "../r1cs_ppzkadsnark_pp.hpp"
#define DELIMITER " "

namespace libsnark {


bool aesPrfKeyT::operator==(const aesPrfKeyT &other) const{
    return memcmp(this->key_bytes, other.key_bytes, 32) == 0;
}

std::ostream& operator<<(std::ostream &out, const aesPrfKeyT &key) {
  for(int i=0; i<32; i++){
    int tmp = key.key_bytes[i];
    out<<tmp<<DELIMITER;
  }
  return out;
}

std::istream& operator>>(std::istream &in, aesPrfKeyT &key) {
  for(int i=0; i<32; i++){
    int tmp;
    in>>tmp;
    key.key_bytes[i]=(unsigned char)tmp;
  }
  char delimiter_to_consume;
  in>>delimiter_to_consume;
  return in;
}

template <>
aesPrfKeyT prfGen<r1cs_ppzkadsnark_pp>() {
    aesPrfKeyT key;
    randombytes(key.key_bytes,32);
    return key;
}

template<>
libff::Fr<snark_pp<r1cs_ppzkadsnark_pp>> prfCompute<r1cs_ppzkadsnark_pp>(
    const aesPrfKeyT &key,  const labelT &label) {
    unsigned char seed_bytes[16];
    mpz_t aux,Fr_mod;
    unsigned char random_bytes[16*3];
    size_t exp_len;

    mpz_init (aux);
    mpz_init (Fr_mod);

    // compute random seed using AES as PRF
    crypto_core_aes128encrypt_openssl(seed_bytes,label.label_bytes,key.key_bytes,NULL);

    // use first 128 bits of output to seed AES-CTR
    // PRG to expand to 3*128 bits
    crypto_core_aes128encrypt_openssl(random_bytes,seed_bytes,key.key_bytes+16,NULL);

    mpz_import(aux, 16, 0, 1, 0, 0, seed_bytes);
    mpz_add_ui(aux,aux,1);
    mpz_export(seed_bytes, &exp_len, 0, 1, 0, 0, aux);
    while (exp_len < 16)
        seed_bytes[exp_len++] = 0;

    crypto_core_aes128encrypt_openssl(random_bytes+16,seed_bytes,key.key_bytes+16,NULL);

    mpz_add_ui(aux,aux,1);
    mpz_export(seed_bytes, &exp_len, 0, 1, 0, 0, aux);
    while (exp_len < 16)
        seed_bytes[exp_len++] = 0;

    crypto_core_aes128encrypt_openssl(random_bytes+32,seed_bytes,key.key_bytes+16,NULL);

    // see output as integer and reduce modulo r
    mpz_import(aux, 16*3, 0, 1, 0, 0, random_bytes);
    libff::Fr<snark_pp<r1cs_ppzkadsnark_pp>>::mod.to_mpz(Fr_mod);
    mpz_mod(aux,aux,Fr_mod);


    return libff::Fr<snark_pp<r1cs_ppzkadsnark_pp>>(
        libff::bigint<libff::Fr<snark_pp<r1cs_ppzkadsnark_pp>>::num_limbs>(aux));
}

} // libsnar1k
