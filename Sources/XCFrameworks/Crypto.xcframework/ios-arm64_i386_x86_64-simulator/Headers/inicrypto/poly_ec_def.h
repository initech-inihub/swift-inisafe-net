#ifndef HEADER_POLY_EC_DEF_H
#define HEADER_POLY_EC_DEF_H


/*!
* \brief
* K-233 곡선에 대한 타원곡선 연산 관련 고정값 (Affine coordinates)
*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* K-233 곡선 파라미터
*/
static uintptr isc_K233_a_data[8] = {0X00000000,0X00000000,0X00000000,0X00000000,0X00000000,0X00000000,0X00000000,0X00000000};
static uintptr isc_K233_b_data[8] = {0X00000001,0X00000000,0X00000000,0X00000000,0X00000000,0X00000000,0X00000000,0X00000000};
static uintptr isc_K233_p_data[8] = {0x00000001,0x00000000,0x00000400,0x00000000,0x00000000,0x00000000,0x00000000,0x00000200};
static uintptr isc_K233_x_data[8] = {0XEFAD6126,0X0A4C9D6E,0X19C26BF5,0X149563A4,0X29F22FF4,0X7E731AF1,0X32BA853A,0X00000172};
static uintptr isc_K233_y_data[8] = {0X56FAE6A3,0X56E0C110,0XF18AEB9B,0X27A8CD9B,0X555A67C4,0X19B7F70F,0X537DECE8,0X000001DB};
static uintptr isc_K233_n_data[8] = {0XF173ABDF,0X6EFB1AD5,0XB915BCD4,0X00069D5B,0X00000000,0X00000000,0X00000000,0X00000080};

static ISC_BIGINT isc_K233_a={isc_K233_a_data, 0, 8, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_K233_b={isc_K233_b_data, 1, 8, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_K233_p={isc_K233_p_data, 8, 8, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_K233_x={isc_K233_x_data, 8, 8, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_K233_y={isc_K233_y_data, 8, 8, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_K233_n={isc_K233_n_data, 8, 8, ISC_BIGINT_HAS_DATA};

static ISC_ECPOINT isc_K233_gen={(&isc_K233_x), (&isc_K233_y), ISC_EC_INF_FALSE};

static ISC_ECURVE isc_K233_Para = {
	/*field id*/
	ISC_ECC_K_233,
	/*Coefficients a, b*/
	(&isc_K233_a),
	(&isc_K233_b),
	/*reduction polynomial*/
	(&isc_K233_p),
	/*Base point G*/
	(&isc_K233_gen),
	/*Main subgroup order*/
	(&isc_K233_n),
	/*curve name*/
	"sect233k1"
};

/*!
* \brief
* K-283 곡선 파라미터
*/
static uintptr isc_K283_a_data[9] = {0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000};
static uintptr isc_K283_b_data[9] = {0x00000001,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000};
static uintptr isc_K283_p_data[9] = {0x000010A1,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x08000000};
static uintptr isc_K283_x_data[9] = {0x58492836,0xb0c2ac24,0x16876913,0x23c1567a,0x53cd265f,0x62f188e5,0x3f1a3b81,0x78ca4488,0x0503213f};
static uintptr isc_K283_y_data[9] = {0x77dd2259,0x4e341161,0xe4596236,0xe8184698,0xe87e45c0,0x07e5426f,0x8d90f95d,0x0f1c9e31,0x01ccda38};
static uintptr isc_K283_n_data[9] = {0X1E163C61,0X94451E06,0X265DFF7F,0X2ED07577,0XFFFFE9AE,0XFFFFFFFF,0XFFFFFFFF,0XFFFFFFFF,0X01FFFFFF};

static ISC_BIGINT isc_K283_a = {isc_K283_a_data, 0, 9, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_K283_b = {isc_K283_b_data, 1, 9, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_K283_p = {isc_K283_p_data, 9, 9, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_K283_x = {isc_K283_x_data, 9, 9, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_K283_y = {isc_K283_y_data, 9, 9, ISC_BIGINT_HAS_DATA};
static ISC_BIGINT isc_K283_n = {isc_K283_n_data, 9, 9, ISC_BIGINT_HAS_DATA};

static ISC_ECPOINT isc_K283_gen={(&isc_K283_x), (&isc_K283_y), ISC_EC_INF_FALSE};

static ISC_ECURVE isc_K283_Para = {
	/*field id*/
	ISC_ECC_K_283,
	/*Coefficients a, b*/
	(&isc_K283_a),
	(&isc_K283_b),
	/*reduction polynomial*/
	(&isc_K283_p),
	/*Base point G*/
	(&isc_K283_gen),
	/*Main subgroup order*/
	(&isc_K283_n),
	/*curve name*/
	"sect283k1"
};

#ifdef  __cplusplus
}
#endif

#endif /* #ifndef HEADER_POLY_EC_DEF_H */
