/**
*** Copyright (c) 2020-present, Jaguar0625, gimre, BloodyRookie.
*** All rights reserved.
***
*** This file is part of Catapult.
***
*** Catapult is free software: you can redistribute it and/or modify
*** it under the terms of the GNU Lesser General Public License as published by
*** the Free Software Foundation, either version 3 of the License, or
*** (at your option) any later version.
***
*** Catapult is distributed in the hope that it will be useful,
*** but WITHOUT ANY WARRANTY; without even the implied warranty of
*** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*** GNU Lesser General Public License for more details.
***
*** You should have received a copy of the GNU Lesser General Public License
*** along with Catapult. If not, see <http://www.gnu.org/licenses/>.
**/

#pragma once
#include "VotingKeyPair.h"
#include <vector>

namespace catapult { namespace crypto {

	/// Voting verification error codes.
	enum class VotingVerifyResult {
		/// Success.
		Success,

		/// Invalid public key flags.
		Failure_Invalid_Public_Key_Flags,

		/// Public key coordinate is not reduced.
		Failure_Public_Key_Not_Reduced,

		/// Public key is invalid point.
		Failure_Public_Key_Is_Invalid_Point,

		/// Public key is not member of subgroup.
		Failure_Public_Key_Subgroup_Check,

		/// Invalid signature flags.
		Failure_Invalid_Signature_Flags,

		/// Signature coordinate(s) are not reduced.
		Failure_Signature_Not_Reduced,

		/// Signature is invalid point
		Failure_Signature_Is_Invalid_Point,

		/// Signature is not member of subgroup.
		Failure_Signature_Subgroup_Check,

		/// Signature is invalid.
		Failure_Verification_Failed
	};

	/// Signs data pointed by \a dataBuffer using \a keyPair, placing resulting signature in \a computedSignature.
	/// \note The function will throw if the generated S part of the signature is not less than the group order.
	void Sign(const VotingKeyPair& keyPair, const RawBuffer& dataBuffer, VotingSignature& computedSignature);

	/// Signs data in \a buffersList using \a keyPair, placing resulting signature in \a computedSignature.
	/// \note The function will throw if the generated S part of the signature is not less than the group order.
	void Sign(const VotingKeyPair& keyPair, std::initializer_list<const RawBuffer> buffersList, VotingSignature& computedSignature);

	/// Verifies that \a signature of data pointed by \a dataBuffer is valid, using public key \a publicKey.
	/// Returns \c true if signature is valid.
	VotingVerifyResult Verify(const VotingKey& publicKey, const RawBuffer& dataBuffer, const VotingSignature& signature);

	/// Verifies that \a signature of data in \a buffersList is valid, using public key \a publicKey.
	/// Returns \c true if signature is valid.
	VotingVerifyResult Verify(
			const VotingKey& publicKey,
			std::initializer_list<const RawBuffer> buffersList,
			const VotingSignature& signature);
}}
