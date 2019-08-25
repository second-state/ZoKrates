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

#ifndef ED25519SIG_HPP_
#define ED25519SIG_HPP_

#include <libsnark/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_signature.hpp>

namespace libsnark {

class ed25519_sigT {
public:
    unsigned char sig_bytes[64];

    bool operator==(const ed25519_sigT &other) const;
    friend std::ostream& operator<< (std::ostream &out, const ed25519_sigT &key);
    friend std::istream& operator>> (std::istream &in, ed25519_sigT &key);
};

class ed25519_vkT {
public:
    unsigned char vk_bytes[32];

    bool operator==(const ed25519_vkT &other) const;
    friend std::ostream& operator<< (std::ostream &out, const ed25519_vkT &key);
    friend std::istream& operator>> (std::istream &in, ed25519_vkT &key);
};

class ed25519_skT {
public:
    unsigned char sk_bytes[64];

    bool operator==(const ed25519_skT &other) const;
    friend std::ostream& operator<< (std::ostream &out, const ed25519_skT &key);
    friend std::istream& operator>> (std::istream &in, ed25519_skT &key);
};

} // libsnark

#endif // ED25519SIG_HPP_
