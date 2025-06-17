#ifndef HEADER_PRIME_EC_DEF_H
#define HEADER_PRIME_EC_DEF_H


/*!
* \brief
* P-224 곡선에 대한 타원곡선 연산 관련 고정값 (Affine coordinates)
*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* P-224 곡선 파라미터
*/
static uintptr isc_P224_a_data[7] = {0XFFFFFFFE,0XFFFFFFFF,0XFFFFFFFF,0XFFFFFFFE,0XFFFFFFFF,0XFFFFFFFF,0XFFFFFFFF};
static uintptr isc_P224_b_data[7] = {0X2355FFB4,0X270B3943,0XD7BFD8BA,0X5044B0B7,0XF5413256,0X0C04B3AB,0XB4050A85};
static uintptr isc_P224_p_data[7] = {0X00000001,0X00000000,0X00000000,0XFFFFFFFF,0XFFFFFFFF,0XFFFFFFFF,0XFFFFFFFF};
static uintptr isc_P224_x_data[7] = {0X115C1D21,0X343280D6,0X56C21122,0X4A03C1D3,0X321390B9,0X6BB4BF7F,0XB70E0CBD};
static uintptr isc_P224_y_data[7] = {0X85007E34,0X44D58199,0X5A074764,0XCD4375A0,0X4C22DFE6,0XB5F723FB,0XBD376388};
static uintptr isc_P224_n_data[7] = {0X5C5C2A3D,0X13DD2945,0XE0B8F03E,0XFFFF16A2,0XFFFFFFFF,0XFFFFFFFF,0XFFFFFFFF};

static ISC_BIGINT isc_P224_a={isc_P224_a_data, 7, 7 ,ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_P224_b={isc_P224_b_data, 7, 7 ,ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_P224_p={isc_P224_p_data, 7, 7 ,ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_P224_x={isc_P224_x_data, 7, 7 ,ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_P224_y={isc_P224_y_data, 7, 7 ,ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_P224_n={isc_P224_n_data, 7, 7 ,ISC_BIGINT_HAS_DATA};

static ISC_ECPOINT isc_P224_gen={(&isc_P224_x), (&isc_P224_y), ISC_EC_INF_FALSE};

static ISC_ECURVE isc_P224_Para = {
	/*field id*/
	ISC_ECC_P_224,
	/*Coefficients a, b*/
	(&isc_P224_a),
	(&isc_P224_b),
	/*Prime p*/
	(&isc_P224_p),
	/*Base point G*/
	(&isc_P224_gen),
	/*Main subgroup order*/
	(&isc_P224_n),
	/*curve name*/
	"secp224r1"
};

/*!
* \brief
* P-256 곡선 파라미터
*/
static uintptr isc_P256_a_data[8] = {0XFFFFFFFC,0XFFFFFFFF,0XFFFFFFFF,0X00000000,0X00000000,0X00000000,0X00000001,0XFFFFFFFF};
static uintptr isc_P256_b_data[8] = {0X27D2604B,0X3BCE3C3E,0XCC53B0F6,0X651D06B0,0X769886BC,0XB3EBBD55,0XAA3A93E7,0X5AC635D8};
static uintptr isc_P256_p_data[8] = {0XFFFFFFFF,0XFFFFFFFF,0XFFFFFFFF,0X00000000,0X00000000,0X00000000,0X00000001,0XFFFFFFFF};
static uintptr isc_P256_x_data[8] = {0XD898C296,0XF4A13945,0X2DEB33A0,0X77037D81,0X63A440F2,0XF8BCE6E5,0XE12C4247,0X6B17D1F2};
static uintptr isc_P256_y_data[8] = {0X37BF51F5,0XCBB64068,0X6B315ECE,0X2BCE3357,0X7C0F9E16,0X8EE7EB4A,0XFE1A7F9B,0X4FE342E2};
static uintptr isc_P256_n_data[8] = {0XFC632551,0XF3B9CAC2,0XA7179E84,0XBCE6FAAD,0XFFFFFFFF,0XFFFFFFFF,0X00000000,0XFFFFFFFF};

static ISC_BIGINT isc_P256_a = {isc_P256_a_data, 8, 8, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_P256_b = {isc_P256_b_data, 8, 8, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_P256_p = {isc_P256_p_data, 8, 8, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_P256_x = {isc_P256_x_data, 8, 8, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_P256_y = {isc_P256_y_data, 8, 8, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_P256_n = {isc_P256_n_data, 8, 8 ,ISC_BIGINT_HAS_DATA};

static ISC_ECPOINT isc_P256_gen={(&isc_P256_x), (&isc_P256_y), ISC_EC_INF_FALSE};

static ISC_ECURVE isc_P256_Para = {
	/*field id*/
	ISC_ECC_P_256,
	/*Coefficients a, b*/
	(&isc_P256_a),
	(&isc_P256_b),
	/*Prime p*/
	(&isc_P256_p),
	/*Base point G*/
	(&isc_P256_gen),
	/*Main subgroup order*/
	(&isc_P256_n),
	/*curve name*/
	"secp256r1"
};

#ifdef  __cplusplus
}
#endif

#endif /* #ifndef HEADER_PRIME_EC_DEF_H */

