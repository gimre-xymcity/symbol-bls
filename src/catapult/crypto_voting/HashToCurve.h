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
#include "catapult/types.h"

namespace catapult { namespace crypto {

	/// Wrapper for g2 point.
	class alignas(32) G2Point {
	public:
		/// Gets a pointer to point.
		template<typename T>
		T* get() {
			static_assert(sizeof(T) <= sizeof(G2Point), "G2Point is too small");
			return reinterpret_cast<T*>(m_buffer);
		}

		/// Gets a reference to point.
		template<typename T>
		T& ref() {
			return *get<T>();
		}

	private:
		uint8_t m_buffer[8 * 64 * 2 * 3];
	};

	/// Hash \a bufferList to \a point on curve.
	void HashToCurveG2(G2Point& point, std::initializer_list<const RawBuffer> buffersList);
}}
