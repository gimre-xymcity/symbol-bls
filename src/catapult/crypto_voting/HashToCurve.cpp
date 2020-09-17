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

#include "HashToCurve.h"
#include "ExpandHash.h"

// AMCL 'arch.h' requires __STDC_VERSION__, which won't be present because this is compiled as cpp code.
// Enforce C99, stdint.h will be included and AMCL types will be properly defined.
#if defined(__clang__) || defined(__GNUC__)
#define C99
#endif

extern "C" {
#include <amcl/config_curve_BLS381.h>
#include <amcl/bls_BLS381.h>
#include <amcl/big_512_56.h>
}

namespace catapult { namespace crypto {

	// note on naming:
	//  * p usually refers to point on G1
	//  * q usually refers to point on G2
	//  * some functions mimic naming from AMCL (ECP_BLS381_* / ECP2_BLS381_)

	// note on references: all functions in AMCL require non-const pointers
	// some of them actually require non-const objects, as they modify 'input' objects as well

	namespace {
		// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-08#section-5.1
		// ceil((ceil(log2(p)) + k) / 8) = ceil((381 + 128) / 8) = 64
		constexpr size_t Integer_Length = 64;

		// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-08#section-5.2
		// step 7. OS2IP(tv) mod p
		void MapToEj(BIG_384_58& tv, const RawBuffer& buffer, size_t offset) {
			DBIG_384_58 dbig;
			BIG_384_58_dfromBytesLen(dbig, const_cast<char*>(reinterpret_cast<const char*>(buffer.pData + offset)), Integer_Length);

			BIG_384_58 modulusBls381{
				0x1FEFFFFFFFFAAABL,
				0x2FFFFAC54FFFFEEL,
				0x12A0F6B0F6241EAL,
				0x213CE144AFD9CC3L,
				0x2434BACD764774BL,
				0x25FF9A692C6E9EDL,
				0x1A0111EA3L
			};
			BIG_384_58_dmod(tv, dbig, modulusBls381);
		}

		// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-08#section-5.2
		// specialized hash_to_field, that produces two FP2 coordinates, as required by hash_to_curve
		void HashToFieldFp2(FP2_BLS381 (&u)[2], const RawString& dstTag, std::initializer_list<const RawBuffer> buffersList) {
			std::array<uint8_t, 4 * Integer_Length> buffer;
			HashExpanderXmd<Sha256_Builder>::Expand(buffersList, { reinterpret_cast<const uint8_t*>(dstTag.pData), dstTag.Size }, buffer);

			// 4 coordinates each 64bytes
			BIG_384_58 xa;
			MapToEj(xa, buffer, 0 * Integer_Length);
			BIG_384_58 xb;
			MapToEj(xb, buffer, 1 * Integer_Length);

			BIG_384_58 ya;
			MapToEj(ya, buffer, 2 * Integer_Length);
			BIG_384_58 yb;
			MapToEj(yb, buffer, 3 * Integer_Length);

			FP2_BLS381_from_BIGs(&u[0], xa, xb);
			FP2_BLS381_from_BIGs(&u[1], ya, yb);
		}

		// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-08#section-4.1
		// sgn0_m_eq_2
		bool Fp2Signum(FP2_BLS381& u) {
			FP_BLS381& fieldElement = FP_BLS381_iszilch(&u.a) ? u.b : u.a;

			BIG_384_58 big;
			FP_BLS381_redc(big, &fieldElement);

			return 0 != BIG_384_58_parity(big);
		}

		// Simplified Shallue-van de Woestijne-Ulas Method - Fp2
		//
		// Returns projectives as (X, Y)
		// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-08#section-6.6.2
		// `Operations` from sections 6.6.2 have been marked below
		void SimplifiedSwuFp2(FP2_BLS381 (&xy)[2], FP2_BLS381& u) {
			// TODO: technically those should be const, not sure about naming
			BIG_384_58 Sswu_A2_A{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
			BIG_384_58 Sswu_A2_B{ 0xF0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
			BIG_384_58 Sswu_B2_A{ 0x3F4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
			BIG_384_58 Sswu_B2_B{ 0x3F4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
			BIG_384_58 Sswu_Z2_A{
				0x1FEFFFFFFFFAAA9,
				0x2FFFFAC54FFFFEE,
				0x12A0F6B0F6241EA,
				0x213CE144AFD9CC3,
				0x2434BACD764774B,
				0x25FF9A692C6E9ED,
				0x1A0111EA3
			};
			BIG_384_58 Sswu_Z2_B{
				0x1FEFFFFFFFFAAAA,
				0x2FFFFAC54FFFFEE,
				0x12A0F6B0F6241EA,
				0x213CE144AFD9CC3,
				0x2434BACD764774B,
				0x25FF9A692C6E9ED,
				0x1A0111EA3
			};

			FP2_BLS381 sswuA;
			FP2_BLS381 sswuB;
			FP2_BLS381 sswuZ;
			FP2_BLS381_from_BIGs(&sswuA, Sswu_A2_A, Sswu_A2_B);
			FP2_BLS381_from_BIGs(&sswuB, Sswu_B2_A, Sswu_B2_B);
			FP2_BLS381_from_BIGs(&sswuZ, Sswu_Z2_A, Sswu_Z2_B);

			// tmp1 = Z * u^2
			FP2_BLS381 tmp1;
			FP2_BLS381_sqr(&tmp1, &u);
			FP2_BLS381_mul(&tmp1, &tmp1, &sswuZ);

			// 1. tv1 = 1 / (Z^2 * u^4 + Z * u^2)
			FP2_BLS381 tv1;
			FP2_BLS381_sqr(&tv1, &tmp1);
			FP2_BLS381_add(&tv1, &tv1, &tmp1);
			FP2_BLS381_inv(&tv1, &tv1);

			// 2. x = (-B / A) * (1 + tv1)
			FP2_BLS381 x;
			FP2_BLS381 oneFp2;
			FP2_BLS381_one(&oneFp2);
			FP2_BLS381_add(&x, &tv1, &oneFp2);
			FP2_BLS381_mul(&x, &x, &sswuB);
			FP2_BLS381_neg(&x, &x);

			FP2_BLS381 aInv;
			FP2_BLS381_inv(&aInv, &sswuA);
			FP2_BLS381_mul(&x, &x, &aInv);

			// 3. Deal with case where Z^2 * u^4 + Z * u^2 == 0
			if (FP2_BLS381_iszilch(&tv1)) {
				// x = B / (Z * A)
				FP2_BLS381_inv(&x, &sswuZ);
				FP2_BLS381_mul(&x, &x, &sswuB);
				FP2_BLS381_mul(&x, &x, &aInv);
			}

			// 4. gx = x^3 + A * x + B = (x^2 + A) * x + B
			FP2_BLS381 gx;
			FP2_BLS381_sqr(&gx, &x);
			FP2_BLS381_add(&gx, &gx, &sswuA);
			FP2_BLS381_mul(&gx, &gx, &x);
			FP2_BLS381_add(&gx, &gx, &sswuB);

			// 7. y = sqrt(gx)
			FP2_BLS381 y;
			if (!FP2_BLS381_sqrt(&y, &gx)) {
				// 5. x = x * Z * u^2
				FP2_BLS381_mul(&x, &x, &tmp1);

				// recalculate gx
				// 6. gx = x^3 + A * x + B
				FP2_BLS381_sqr(&gx, &x);
				FP2_BLS381_add(&gx, &gx, &sswuA);
				FP2_BLS381_mul(&gx, &gx, &x);
				FP2_BLS381_add(&gx, &gx, &sswuB);

				// following sqrt won't fail, see linked section 6.6.2 for details
				FP2_BLS381_sqrt(&y, &gx);
			}

			// compare signs

			bool su = Fp2Signum(u);
			bool sy = Fp2Signum(y);
			if (su != sy)
				FP2_BLS381_neg(&y, &y);

			FP2_BLS381_copy(&xy[0], &x);
			FP2_BLS381_copy(&xy[1], &y);
		}

		// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-08#appendix-C.3
		void Iso3ToEcp2(ECP2_BLS381& result, FP2_BLS381& isoX, FP2_BLS381& isoY) {
			constexpr size_t Poly_Degree = 4;

			// constants taken from `incubator-milagro-crypto-rust/src/bls381/iso_constants_x64.rs`
			BIG_384_58 xNumBigs[]{
				// k_(1,0)
				{
					0x238AAAAAAAA97D6, 0x18E38D0F671C718, 0x423C50AE15D5C2, 0xE7F4E810AA22D6,
					0x247D7ED8532C52D, 0x3A38CCFAED6DEA6, 0x5C759507
				},
				{
					0x238AAAAAAAA97D6, 0x18E38D0F671C718, 0x423C50AE15D5C2, 0xE7F4E810AA22D6,
					0x247D7ED8532C52D, 0x3A38CCFAED6DEA6, 0x5C759507
				},
				// k_(1,1)
				{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
				{
					0x2A9FFFFFFFFC71A, 0xAAAA72E3555549, 0xC6B4F20A418147, 0x2B7DEB831FE6882,
					0x2D787C88F984F87, 0x2EAA66F0C849BF3, 0x11560BF17
				},
				// k_(1,2)
				{
					0x2A9FFFFFFFFC71E, 0xAAAA72E3555549, 0xC6B4F20A418147, 0x2B7DEB831FE6882,
					0x2D787C88F984F87, 0x2EAA66F0C849BF3, 0x11560BF17
				},
				{
					0x354FFFFFFFFE38D, 0x255553971AAAAA4, 0x635A790520C0A3, 0x35BEF5C18FF3441,
					0x36BC3E447CC27C3, 0x375533786424DF9, 0x8AB05F8B
				},
				// k_(1,3)
				{
					0xE2AAAAAAAA5ED1, 0x238E343D9C71C62, 0x108F142B8575709, 0x39FD3A042A88B58,
					0x11F5FB614CB14B4, 0x28E333EBB5B7A9A, 0x171D6541F
				},
				{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
			};

			BIG_384_58 xDenBigs[]{
				// k_(2,0)
				{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
				{
					0x1FEFFFFFFFFAA63, 0x2FFFFAC54FFFFEE, 0x12A0F6B0F6241EA, 0x213CE144AFD9CC3,
					0x2434BACD764774B, 0x25FF9A692C6E9ED, 0x1A0111EA3
				},
				// k_(2,1)
				{ 0xC, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
				{
					0x1FEFFFFFFFFAA9F, 0x2FFFFAC54FFFFEE, 0x12A0F6B0F6241EA, 0x213CE144AFD9CC3,
					0x2434BACD764774B, 0x25FF9A692C6E9ED, 0x1A0111EA3
				},
				// k_(2,2) (note: x'^2 is present in evaluation of x_den)
				{ 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
				{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
				// k_(2,3)
				{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
				{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
			};

			BIG_384_58 yNumBigs[]{
				// k_(3,0)
				{
					0x2CFC71C71C6D706, 0x3097AFE324BDA04, 0x39D87D27E500FC8, 0x35281FD926FD510,
					0x3076D11930F7DA5, 0x2AD044ED6693062, 0x1530477C7
				},
				{
					0x2CFC71C71C6D706, 0x3097AFE324BDA04, 0x39D87D27E500FC8, 0x35281FD926FD510,
					0x3076D11930F7DA5, 0x2AD044ED6693062, 0x1530477C7
				},
				// k_(3,1)
				{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
				{
					0x238AAAAAAAA97BE, 0x18E38D0F671C718, 0x423C50AE15D5C2, 0xE7F4E810AA22D6,
					0x247D7ED8532C52D, 0x3A38CCFAED6DEA6, 0x5C759507
				},
				// k_(3,2)
				{
					0x2A9FFFFFFFFC71C, 0xAAAA72E3555549, 0xC6B4F20A418147, 0x2B7DEB831FE6882,
					0x2D787C88F984F87, 0x2EAA66F0C849BF3, 0x11560BF17
				},
				{
					0x354FFFFFFFFE38F, 0x255553971AAAAA4, 0x635A790520C0A3, 0x35BEF5C18FF3441,
					0x36BC3E447CC27C3, 0x375533786424DF9, 0x8AB05F8B
				},
				// k_(3,3)
				{
					0x1B371C71C718B10, 0x2425E95B712F678, 0x37C69AA274524E7, 0xDE87898A1AC3A5,
					0x1E3811AD0761B0F, 0x2DB3DE6FEFDC10F, 0x124C9AD43
				},
				{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
			};

			BIG_384_58 yDenBigs[]{
				// k_(4,0)
				{
					0x1FEFFFFFFFFA8FB, 0x2FFFFAC54FFFFEE, 0x12A0F6B0F6241EA, 0x213CE144AFD9CC3,
					0x2434BACD764774B, 0x25FF9A692C6E9ED, 0x1A0111EA3
				},
				{
					0x1FEFFFFFFFFA8FB, 0x2FFFFAC54FFFFEE, 0x12A0F6B0F6241EA, 0x213CE144AFD9CC3,
					0x2434BACD764774B, 0x25FF9A692C6E9ED, 0x1A0111EA3
				},
				// k_(4,1)
				{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
				{
					0x1FEFFFFFFFFA9D3, 0x2FFFFAC54FFFFEE, 0x12A0F6B0F6241EA, 0x213CE144AFD9CC3,
					0x2434BACD764774B, 0x25FF9A692C6E9ED, 0x1A0111EA3
				},
				// k_(4,2)
				{ 0x12, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
				{
					0x1FEFFFFFFFFAA99, 0x2FFFFAC54FFFFEE, 0x12A0F6B0F6241EA, 0x213CE144AFD9CC3,
					0x2434BACD764774B, 0x25FF9A692C6E9ED, 0x1A0111EA3
				},
				// k_(4,3) // (note: y'^3 is present in evaluation of y_den)
				{ 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
				{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
			};

			using FourCoords = FP2_BLS381[4];
			using FourCoordsPtr = FourCoords*;

			FourCoords xNum;
			for (auto i = 0u; i < Poly_Degree; ++i)
				FP2_BLS381_from_BIGs(&xNum[i], xNumBigs[2 * i], xNumBigs[2 * i + 1]);

			FourCoords xDen;
			for (auto i = 0u; i < Poly_Degree; ++i)
				FP2_BLS381_from_BIGs(&xDen[i], xDenBigs[2 * i], xDenBigs[2 * i + 1]);

			FourCoords yNum;
			for (auto i = 0u; i < Poly_Degree; ++i)
				FP2_BLS381_from_BIGs(&yNum[i], yNumBigs[2 * i], yNumBigs[2 * i + 1]);

			FourCoords yDen;
			for (auto i = 0u; i < Poly_Degree; ++i)
				FP2_BLS381_from_BIGs(&yDen[i], yDenBigs[2 * i], yDenBigs[2 * i + 1]);

			FourCoordsPtr polyCoefficients[]{
				&xNum, &xDen, &yNum, &yDen
			};

			// horner polynomial evaluation x' == isoX, calculate x_num, x_den, y_num, y_den
			FP2_BLS381 mappedVals[4];
			for (auto i = 0; i < 4; ++i) {
				auto& pCoefficients = *polyCoefficients[i];
				auto& mappedVal = mappedVals[i];

				// initialize to highest coeficient k(*, 3)
				mappedVal = pCoefficients[3];
				for (auto j = 0; j < 3; ++j) {
					FP2_BLS381_mul(&mappedVal, &mappedVal, &isoX);
					FP2_BLS381_add(&mappedVal, &mappedVal, &pCoefficients[2 - j]);
				}
			}

			// y' * y_num
			FP2_BLS381_mul(&mappedVals[2], &mappedVals[2], &isoY);

			// finally represent as (x,y,z)
			// X = X/Z = (x_num * y_den) / (x_den * y_den) = x_num / x_den
			// Y = Y/Z = (y_num * x_den) / (x_den * y_den) = y_num / y_den
			FP2_BLS381_mul(&result.z, &mappedVals[1], &mappedVals[3]); // x_den * y_den
			FP2_BLS381_mul(&result.x, &mappedVals[0], &mappedVals[3]); // x_num * y_den
			FP2_BLS381_mul(&result.y, &mappedVals[2], &mappedVals[1]); // y_num * x_den
		}

		void MapToCurve(ECP2_BLS381& point, FP2_BLS381& u) {
			FP2_BLS381 xy[2];
			SimplifiedSwuFp2(xy, u);
			Iso3ToEcp2(point, xy[0], xy[1]);
		}

		// Budroni, Pintore  "Efficient hash maps to G2 on BLS curves"
		// https://eprint.iacr.org/2017/419
		void ECP2_clearCofactor(ECP2_BLS381& point) {
			// frobenius constants
			BIG_384_58 fx;
			BIG_384_58 fy;

			// precalc frob const
			FP2_BLS381 frobC;
			BIG_384_58_rcopy(fx, Fra_BLS381);
			BIG_384_58_rcopy(fy, Frb_BLS381);
			FP2_BLS381_from_BIGs(&frobC, fx, fy);
			FP2_BLS381_inv(&frobC, &frobC);
			FP2_BLS381_norm(&frobC);

			BIG_384_58 x;
			BIG_384_58_rcopy(x, CURVE_Bnx_BLS381);

			// Efficient hash maps to G2 on BLS curves - Budroni, Pintore
			// [x^2 - x - 1] * Q + [x - 1]*psi(Q) + psi^2(2*Q) ==>
			// x^2*Q - x*Q - Q + psi(x*Q - Q) + psi(psi(2*Q))

			ECP2_BLS381 xQ;
			ECP2_BLS381 x2Q;

			ECP2_BLS381_copy(&xQ, &point);
			ECP2_BLS381_mul(&xQ, x);

			ECP2_BLS381_copy(&x2Q, &xQ);
			ECP2_BLS381_mul(&x2Q, x);

			ECP2_BLS381_neg(&xQ);

			ECP2_BLS381_sub(&x2Q, &xQ); // x^2*Q - x*Q
			ECP2_BLS381_sub(&x2Q, &point); // x^2*Q - x*Q - Q

			ECP2_BLS381_sub(&xQ, &point);
			ECP2_BLS381_frob(&xQ, &frobC); // psi(x*Q - Q)

			ECP2_BLS381_dbl(&point);
			ECP2_BLS381_frob(&point, &frobC);
			ECP2_BLS381_frob(&point, &frobC); // psi(psi(2*Q))

			ECP2_BLS381_add(&point, &x2Q); // psi(psi(2*Q)) + x^2*Q - x*Q - Q
			ECP2_BLS381_add(&point, &xQ); // psi(psi(2*Q)) + x^2*Q - x*Q - Q + psi(x*Q - Q)

			ECP2_BLS381_affine(&point);
		}
	}

	// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-08#section-3
	void HashToCurveG2(G2Point& point, const RawString& dstTag, std::initializer_list<const RawBuffer> buffersList) {
		FP2_BLS381 u[2];
		HashToFieldFp2(u, dstTag, buffersList);

		auto& p1 = point.ref<ECP2_BLS381>();
		MapToCurve(p1, u[0]);

		ECP2_BLS381 p2;
		MapToCurve(p2, u[1]);

		ECP2_BLS381_add(&p1, &p2);

		ECP2_clearCofactor(p1);
	}
}}
