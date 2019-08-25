/** @file
 *****************************************************************************

 Fast batch verification signature for ADSNARK.

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

/** @file
 *****************************************************************************
 * @author     This file was deed to libsnark by Manuel Barbosa.
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include<iostream>
#include "crypto_sign.h"

#include "../r1cs_ppzkadsnark_pp.hpp"
#define DELIMITER " "

namespace libsnark {

bool ed25519_sigT::operator==(const ed25519_sigT &other) const{
    return memcmp(this->sig_bytes, other.sig_bytes, 64) == 0;
}


std::ostream& operator<<(std::ostream &out, const ed25519_sigT &sig) {
  out<<DELIMITER;
  for(int i=0; i<64; i++){
    int tmp = sig.sig_bytes[i];
    out<<tmp<<DELIMITER;
  }
  return out;
}

std::istream& operator>>(std::istream &in, ed25519_sigT &sig) {
  for(int i=0; i<64; i++){
    int tmp;
    in>>tmp;
    sig.sig_bytes[i]=(unsigned char)tmp;
  }
  char delimiter_to_consume;
  in>>delimiter_to_consume;
  return in;
}

bool ed25519_vkT::operator==(const ed25519_vkT &other) const{
    return memcmp(this->vk_bytes, other.vk_bytes, 32) == 0;
}

std::ostream& operator<<(std::ostream &out, const ed25519_vkT &vk) {
  out<<DELIMITER;
  for(int i=0; i<32; i++){
    int tmp = vk.vk_bytes[i];
    out<<tmp<<DELIMITER;
  }
  return out;
}

std::istream& operator>>(std::istream &in, ed25519_vkT &vk) {
  for(int i=0; i<32; i++){
    int tmp;
    in>>tmp;
    vk.vk_bytes[i]=(unsigned char)tmp;
  }
  char delimiter_to_consume;
  in>>delimiter_to_consume;
  return in;
}

bool ed25519_skT::operator==(const ed25519_skT &other) const{
    return memcmp(this->sk_bytes, other.sk_bytes, 64) == 0;
}

std::ostream& operator<<(std::ostream &out, const ed25519_skT &sk) {
  out<<DELIMITER;
  for(int i=0; i<64; i++){
    int tmp = sk.sk_bytes[i];
    out<<tmp<<DELIMITER;
  }
  return out;
}

std::istream& operator>>(std::istream &in, ed25519_skT &sk) {
  for(int i=0; i<64; i++){
    int tmp;
    in>>tmp;
    sk.sk_bytes[i]=(unsigned char)tmp;
  }
  char delimiter_to_consume;
  in>>delimiter_to_consume;
  return in;
}


template<>
kpT<r1cs_ppzkadsnark_pp> sigGen<r1cs_ppzkadsnark_pp>(void) {
    kpT<r1cs_ppzkadsnark_pp> keys;
    crypto_sign_ed25519_amd64_51_30k_keypair(keys.vk.vk_bytes,keys.sk.sk_bytes);
    return keys;
}

template<>
ed25519_sigT sigSign<r1cs_ppzkadsnark_pp>(const ed25519_skT &sk, const labelT &label,
                                                  const libff::G2<snark_pp<r1cs_ppzkadsnark_pp>> &Lambda) {
    ed25519_sigT sigma;
    unsigned long long sigmalen;
    unsigned char signature[64+16+320];
    unsigned char message[16+320];

    libff::G2<snark_pp<r1cs_ppzkadsnark_pp>> Lambda_copy(Lambda);
    Lambda_copy.to_affine_coordinates();

    for(size_t i = 0; i<16;i++)
        message[i] = label.label_bytes[i];

    // More efficient way to get canonical point rep?
    std::stringstream stream;
    stream.rdbuf()->pubsetbuf(((char*)message)+16, 320);
    stream << Lambda_copy;
    size_t written = stream.tellp();
    while (written<320)
    	message[16+written++] = 0;

    crypto_sign_ed25519_amd64_51_30k(signature,&sigmalen,message,16+320,sk.sk_bytes);

    assert(sigmalen == 64+16+320);

    for(size_t i = 0; i<64;i++)
        sigma.sig_bytes[i] = signature[i];

    return sigma;
}

template<>
bool sigVerif<r1cs_ppzkadsnark_pp>(const ed25519_vkT &vk, const labelT &label,
                                           const libff::G2<snark_pp<r1cs_ppzkadsnark_pp>> &Lambda,
                                           const ed25519_sigT &sig) {
    unsigned long long msglen;
    unsigned char message[64+16+320];
    unsigned char signature[64+16+320];

    libff::G2<snark_pp<r1cs_ppzkadsnark_pp>> Lambda_copy(Lambda);
    Lambda_copy.to_affine_coordinates();

    for(size_t i = 0; i<64;i++)
        signature[i] = sig.sig_bytes[i];

    for(size_t i = 0; i<16;i++)
        signature[64+i] = label.label_bytes[i];

    // More efficient way to get canonical point rep?
    std::stringstream stream;
    stream.rdbuf()->pubsetbuf(((char*)signature)+64+16, 320);
    stream << Lambda_copy;
    size_t written = stream.tellp();
    while (written<320)
    	signature[64+16+written++] = 0;

    int res = crypto_sign_ed25519_amd64_51_30k_open(message,&msglen,signature,64+16+320,vk.vk_bytes);
    return (res==0);
}

template<>
bool sigBatchVerif<r1cs_ppzkadsnark_pp>(const ed25519_vkT &vk, const std::vector<labelT> &labels,
                                                const std::vector<libff::G2<snark_pp<r1cs_ppzkadsnark_pp>>> &Lambdas,
                                                const std::vector<ed25519_sigT> &sigs) {
    std::stringstream stream;

    assert(labels.size() == Lambdas.size());
    assert(labels.size() == sigs.size());

    unsigned long long msglen[labels.size()];
    unsigned long long siglen[labels.size()];
    unsigned char *messages[labels.size()];
    unsigned char *signatures[labels.size()];
    unsigned char *pks[labels.size()];

    unsigned char pk_copy[32];
    for(size_t i = 0; i < 32; i++) {
        pk_copy[i] = vk.vk_bytes[i];
    }

    unsigned char *messagemem = (unsigned char*)malloc(labels.size()*(64+16+320));
    assert(messagemem != NULL);
    unsigned char *signaturemem = (unsigned char*)malloc(labels.size()*(64+16+320));
    assert(signaturemem != NULL);

    for(size_t i = 0; i < labels.size(); i++) {
        siglen[i] = 64+16+320;
        messages[i] = messagemem+(64+16+320)*i;
        signatures[i] = signaturemem+(64+16+320)*i;
        pks[i] = pk_copy;

        for(size_t j = 0; j<64;j++)
            signaturemem[i*(64+16+320)+j] = sigs[i].sig_bytes[j];

        for(size_t j = 0; j<16;j++)
            signaturemem[i*(64+16+320)+64+j] = labels[i].label_bytes[j];

        // More efficient way to get canonical point rep?
        libff::G2<snark_pp<r1cs_ppzkadsnark_pp>> Lambda_copy(Lambdas[i]);
        Lambda_copy.to_affine_coordinates();
        stream.clear();
        stream.rdbuf()->pubsetbuf((char*)(signaturemem+i*(64+16+320)+64+16), 320);
        stream << Lambda_copy;
        size_t written = stream.tellp();
        while (written<320)
            signaturemem[i*(64+16+320)+64+16+written++] = 0;

    }
    int res = crypto_sign_ed25519_amd64_51_30k_open_batch(
        messages,msglen,
        signatures,siglen,
        pks,
        labels.size());

    return (res==0);
}

} // libsnark
