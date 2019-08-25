/** @file
 *****************************************************************************

 This file defines default_r1cs_ppzkadsnark_pp based on the elliptic curve
 choice selected in ec_pp.hpp.

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef R1CS_PPZKADSNARK_PP_HPP_
#define R1CS_PPZKADSNARK_PP_HPP_

#include "prf/aes_ctr_prf.hpp"
#include "signature/ed25519_signature.hpp"
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"

namespace libsnark {

	class r1cs_ppzkadsnark_pp {
	public:
		typedef libff::alt_bn128_pp snark_pp;
		typedef ed25519_skT skT;
		typedef ed25519_vkT vkT;
    typedef ed25519_sigT sigT;
    typedef aesPrfKeyT prfKeyT;

    static void init_public_params();
	};

};  // libsnark

#endif // R1CS_PPZKADSNARK_PP_HPP_
