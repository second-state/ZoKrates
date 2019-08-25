/** @file
 *****************************************************************************

 AES-Based PRF for ADSNARK.

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef AESCTRPRF_HPP_
#define AESCTRPRF_HPP_

#include <libsnark/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_prf.hpp>

namespace libsnark {

class aesPrfKeyT {
public:
    unsigned char key_bytes[32];

    bool operator==(const aesPrfKeyT &other) const;
    friend std::ostream& operator<< (std::ostream &out, const aesPrfKeyT &key);
    friend std::istream& operator>> (std::istream &in, aesPrfKeyT &key);
};

} // libsnark

#endif // AESCTRPRF_HPP_
