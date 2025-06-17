/*!
* \file drbg.h
* \brief DRBG; Deterministic Random Bit Generator Algorithm
* \remarks
* NIST SP800-90 ������ �������� �ۼ� �Ǿ���.
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_DRBG_H
#define HEADER_DRBG_H

#include "foundation.h"
#include "mem.h"
#include "entropy.h"
#include "drbg.h"

#ifndef ISC_NO_DRBG

#ifndef ISC_NO_BIGINT
#include "biginteger.h"
#endif

#ifdef  __cplusplus
extern "C" {
#endif

/* DRBG Type */
#define ISC_DRBG_HASH_MODE						0
#define ISC_DRBG_HMAC_MODE						1
#define ISC_DRBG_CTR_MODE						2

/* under 2^35 bit */
#define ISC_DRBG_MAX_LENGTH						0x7ffffff0
#define ISC_DRBG_MAX_REQUEST_LENGTH				0x8000
#define ISC_DRBG_MAX_RESEED_COUNTER				0x5F5E100		/* 1�� (ǥ�� MAX : 2^48) */

#define ISC_MAX_HASH_DRBG_OUTLEN_BYTES			ISC_SHA512_OUTLEN_BYTES
#define ISC_MAX_HASH_DRBG_SEED_LENGTH_BYTES		ISC_SHA512_SEED_LENGTH_BYTES

#define ISC_HAS160_SECURITY_STRENGTH_BITS		80
#define ISC_HAS160_SECURITY_STRENGTH_BYTES		10
#define ISC_HAS160_SEED_LENGTH_BYTES			55
#define ISC_HAS160_OUTLEN_BYTES					20

#define ISC_SHA1_SECURITY_STRENGTH_BITS			80
#define ISC_SHA1_SECURITY_STRENGTH_BYTES		10
#define ISC_SHA1_SEED_LENGTH_BYTES				55
#define ISC_SHA1_OUTLEN_BYTES					20

#define ISC_SHA224_SECURITY_STRENGTH_BITS		112
#define ISC_SHA224_SECURITY_STRENGTH_BYTES		14
#define ISC_SHA224_SEED_LENGTH_BYTES			55
#define ISC_SHA224_OUTLEN_BYTES					28

#define ISC_SHA256_SECURITY_STRENGTH_BITS		128
#define ISC_SHA256_SECURITY_STRENGTH_BYTES		16
#define ISC_SHA256_SEED_LENGTH_BYTES			55
#define ISC_SHA256_OUTLEN_BYTES					32

#define ISC_SHA384_SECURITY_STRENGTH_BITS		192
#define ISC_SHA384_SECURITY_STRENGTH_BYTES		24
#define ISC_SHA384_SEED_LENGTH_BYTES			111
#define ISC_SHA384_OUTLEN_BYTES					48

#define ISC_SHA512_SECURITY_STRENGTH_BITS		256
#define ISC_SHA512_SECURITY_STRENGTH_BYTES		32
#define ISC_SHA512_SEED_LENGTH_BYTES			111
#define ISC_SHA512_OUTLEN_BYTES					64

#define ISC_DRBG_NON_PREDICTION_RESISTANCE_MODE	0	/*!< ���� ���� */
#define ISC_DRBG_PREDICTION_RESISTANCE_MODE		1	/*!< ���� ���� */

#define ISC_DRBG_PROVEN_MODE  		1		/*!<  0: ����� ���, 1: ������� */

/* Entropy internal state */
typedef struct isc_drbg_entropy_input_st {
	uint8	status;
	int		collection_mode;
	int		entropy_input_len;
	int		nonce_len;
	int		personalization_string_len;
	uint8   *entropy_input;
	uint8   *nonce;
	uint8   *personalization_string;
} ISC_DRBG_ENTROPY_INPUT;

/*!
* \brief
* DRBG���� ���̴� ������ ��� �ִ� ����ü
* \remarks
*/
struct isc_drbg_st {
	int		type;
	int		status;
	int		algo_id;

	int		min_entropy;
	int		max_entropy;
	int		min_nonce;
	int		max_nonce;

	int		max_personal_string;
	int		max_additional_input;

	int		max_request;
	int		reseed_interval;

	int		block_len;
	int		security_len;

	uint8	*v;
	uint8	*c;

	int		seed_len;
	uint8	*seed;
	
	int		additional_input_len;
	uint8	*additional_input;

	int		returned_bytes_len;
	uint8	*returned_bytes;

	int		prediction_resistance_flag; 
	int		reseed_counter;
	
	uint8	rbg_block[ISC_MAX_HASH_DRBG_OUTLEN_BYTES];		/* ������ �����߻��� üũ�� ���� block ���� ���� */
	uint8	rbg_block_len;								/* ������ �����߻��� üũ�� ���� block ���� ���� */

	ISC_DRBG_ENTROPY_INPUT *entropy;
};

#define ISC_RAND_BYTES(x, y) ISC_Rand_Bytes((x), (y))

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* DRBG ���� ���� �� �����ϴ� �Լ�
* \param *drbg_input
* ������ ������
* \param drbg_input_length
* ������ ������ ����
* \param operation_mode
* DRBG � ��� (ISC_DRBG_HASH_MODE, ISC_DRBG_HMAC_MODE, ISC_DRBG_CTR_MODE)
* \param hash_id
* �������� �� ����� �ؽ� �˰���
* \param prediction_resistance_flag
* �������� ����(�������� : ISC_DRBG_PREDICTION_RESISTANCE_MODE, 
* �������� : ISC_DRBG_NON_PREDICTION_RESISTANCE_MODE)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_DRBG^ISC_F_RAND_BYTES_DRBG^ISC_ERR_MUTEX_LOCK_FAIL: Mutex Lock ����
* -# ISC_L_DRBG^ISC_F_RAND_BYTES_DRBG^ISC_ERR_MEM_ALLOC: DRBG ����ü �Ҵ� ����
* -# ISC_L_DRBG^ISC_F_RAND_BYTES_DRBG^ISC_ERR_MUTEX_UNLOCK_FAIL: Mutex Unlock ����
* -# ISC_L_DRBG^ISC_F_RAND_BYTES_DRBG^ISC_ERR_INIT_DRBG_FAIL : INIT DRBG ����
* -# ISC_L_DRBG^ISC_F_RAND_BYTES_DRBG^ISC_ERR_INSTANTIATE_DRBG_FAIL : INSTANTIATE DRBG ����
* -# ISC_L_DRBG^ISC_F_RAND_BYTES_DRBG^ISC_ERR_GENERATE_DRBG_FAIL : GENERATE DRBG ����
*/
ISC_API ISC_STATUS ISC_Rand_Bytes_DRBG(uint8 *drbg_input, int drbg_input_length, int operation_mode, int hash_id, int prediction_resistance_flag);

/*!
* \brief
* DRBG ���� ���� �� �����ϴ� �Լ�
* \param *rand
* ������ ������
* \param length
* ������ ������ ���� �Է�
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS ISC_Rand_Bytes(uint8 *rand, int length);

/*!
* \brief
* DRBG ���μ�����(V, C ��) ����
* \returns
* -# ����
*/
ISC_API void ISC_Uninstantiate_DRBG();

/*!
* \brief
* ������ ���� ISC_BIGINT �������� ��� ���� �Լ�,
* NIST FIPS PUB186-2 Appendix 3.1 & 3.2 ������ �������� �ۼ� �Ǿ���.
* ���� x(0<x<q)���� ���ϱ� ���� �˰�������
* �Ϲ����� ���� ���� ���� ������ mod q ������ ���ʿ��ϱ� ������ mod
* q������ ���� �ʾ���.
* \param output
* ���� ���� �����ϱ� ���� ISC_BIGINT�� ������
* \param bit_length
* ���ϴ� ���� ���� ����(bit)
* \returns
* -# ISC_Get_Rand()�� �����ڵ�\n
* -# ISC_SUCCESS : Success\n
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_DRBG^ISC_F_GET_RAND_BIGINT_EX^ISC_ERR_GET_RAND_FAIL : ���� ���� ����
* -# ISC_L_DRBG^ISC_F_GET_RAND_BIGINT_EX^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY_TO_BIGINT ����
*/
ISC_API ISC_STATUS ISC_Get_Rand_BIGINT_Ex(ISC_BIGINT *output, int bit_length);

/*!
* \brief
* ISC_DRBG_ENTROPY_INPUT ���� �Լ�
* \returns
* ������ ISC_DRBG_ENTROPY_INPUT�� ������
*/
 ISC_DRBG_ENTROPY_INPUT *isc_New_DRBG_ENTROPY_Input(void);

/*!
* \brief
* ISC_DRBG_ENTROPY_INPUT�� �� �ʱ�ȭ �Լ�
* \param entropy
* ISC_DRBG_ENTROPY_INPUT ����ü�� ������
*/
 void isc_Clean_DRBG_ENTROPY_Input(ISC_DRBG_ENTROPY_INPUT *entropy);

/*!
* \brief
* ISC_DRBG_ENTROPY_INPUT ���� �Լ�
* \param entropy
* ISC_DRBG_ENTROPY_INPUT ����ü�� ������
*/
 void isc_Free_DRBG_ENTROPY_Input(ISC_DRBG_ENTROPY_INPUT *entropy);

 ISC_STATUS isc_Get_Rand_Bytes_DRBG(uint8 *drbg_input, int drbg_input_length, int operation_mode, int hash_id, int prediction_resistance_flag, ISC_DRBG_ENTROPY_INPUT *entropy);

#ifndef ISC_CRYPTO_VS_TEST /* IUT �׽�Ʈ �Ҷ��� �ܺ��Լ��� ����. */

/*!
* \brief
* ISC_DRBG_UNIT ���� �Լ�
* \returns
* ������ ISC_DRBG_UNIT�� ������
*/
ISC_DRBG_UNIT *isc_New_DRBG_Unit(void);

/*!
* \brief
* ISC_DRBG_UNIT�� �� �ʱ�ȭ �Լ�
* \param drbg
* ISC_DRBG_UNIT ����ü�� ������
*/
 void isc_Clean_DRBG_Unit(ISC_DRBG_UNIT *drbg);

/*!
* \brief
* ISC_DRBG_UNIT ���� �Լ�
* \param drbg
* ISC_DRBG_UNIT ����ü�� ������
*/
 void isc_Free_DRBG_Unit(ISC_DRBG_UNIT *drbg);

/*!
* \brief
* DRBG �ʱ�ȭ �Լ�
* \param drbg
* ISC_DRBG_UNIT ����ü ������
* \param algo_id
* �ؽ� �˰��� ISC_SHA1/ISC_SHA224/ISC_SHA256/ISC_SHA384/ISC_SHA512/ISC_HAS160
* \param operation_mode
* drbg ����(ISC_DRBG_HASH_MODE)
* \param prediction_resistance_flag
* �������� ����(�������� : ISC_DRBG_PREDICTION_RESISTANCE_MODE, �������� : ISC_DRBG_NON_PREDICTION_RESISTANCE_MODE)
* \param entropy_collection_mode
* ��Ʈ���� ���� ���(ISC_ENTROPY_FAST_MODE, ISC_ENTROPY_NORMAL_MODE, ISC_ENTROPY_SLOW_MODE)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# LOCATION^ISC_F_INIT_DRBG^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_INIT_DRBG^ ISC_ERR_NOT_SUPPORTED: �������� �ʴ� �˰��� �Է�
* -# LOCATION^ISC_F_INIT_HASHDRBG^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_INIT_HASHDRBG^ISC_ERR_NOT_PROVEN_ALGORITHM : ����� �˰��� �Է�
* -# LOCATION^ISC_F_INIT_HASHDRBG^ISC_ERR_NOT_SUPPORTED : �������� �ʴ� �˰��� �Է�
*/
 ISC_STATUS isc_Init_DRBG(ISC_DRBG_UNIT *drbg, int algo_id, int operation_mode, int prediction_resistance_flag, int entropy_collection_mode);

/*!
* \brief
* DRBG instantiate �Լ�
* \param drbg
* ISC_DRBG_UNIT ����ü ������
* \param requested_instantiation_security_strength 
* ������Է� ���Ȱ�������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INSTANTIATE_DRBG^ISC_ERR_NULL_INPUT: �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_INSTANTIATE_DRBG^ISC_ERR_COMPARE_FAIL: ������ �� ����
* -# LOCATION^ISC_F_INSTANTIATE_DRBG^ISC_ERR_NOT_SUPPORTED: �������� �ʴ� �˰��� �Է�
* -# LOCATION^ISC_F_INSTANTIATE_HASHDRBG^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_INSTANTIATE_HASHDRBG^ISC_ERR_INPUT_BUF_TOO_BIG : ���ۺ��� ū �Է�
* -# LOCATION^ISC_F_INSTANTIATE_HASHDRBG^ISC_ERR_HASH_DF_FAIL : HASH DF ����
*/
ISC_STATUS isc_Instantiate_DRBG(ISC_DRBG_UNIT *drbg, int requested_instantiation_security_strength);

/*!
* \brief
* DRBG Reseed �Լ�
* \param drbg
* ISC_DRBG_UNIT ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_RESEED_DRBG^ISC_ERR_NULL_INPUT: �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_RESEED_DRBG^ISC_ERR_COMPARE_FAIL: ������ �� ����
* -# LOCATION^ISC_F_RESEED_DRBG^ISC_ERR_NOT_SUPPORTED: �������� �ʴ� �˰��� �Է�
* -# LOCATION^ISC_F_RESEED_DRBG^ISC_ERR_SUB_OPERATION_FAILURE: ��Ʈ���� ���� ����
* -# LOCATION^ISC_F_RESEED_HASHDRBG^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_RESEED_HASHDRBG^ISC_ERR_INPUT_BUF_TOO_BIG: ���ۺ��� ū �Է�
* -# LOCATION^ISC_F_RESEED_HASHDRBG^ISC_ERR_HASH_DF_FAIL : HASH DF ����
*/
 ISC_STATUS isc_Reseed_DRBG(ISC_DRBG_UNIT *drbg);

/*!
* \brief
* DRBG ���� �Լ�
* \param drbg
* ISC_DRBG_UNIT ����ü ������
* \param *output
* ������ drbg ���� ��
* \param output_len
* ������ �������� ����
* \param output_len
* ������� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_GENERATE_DRBG^ISC_ERR_NULL_INPUT: �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_GENERATE_DRBG^ISC_ERR_INVALID_INPUT: �߸��� �ʱ�ȭ�� �Է�
* -# LOCATION^ISC_F_GENERATE_DRBG^ISC_ERR_SUB_OPERATION_FAILURE: RESEED ���� ����
* -# LOCATION^ISC_F_GENERATE_DRBG^ISC_ERR_NOT_SUPPORTED: �������� �ʴ� �˰��� �Է�
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_NULL_INPUT: �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_INPUT_BUF_TOO_BIG: ���ۺ��� ū �Է�
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_MALLOC: �޸� �Ҵ� ����
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_INIT_DIGEST_FAIL: �ؽ� �ʱ�ȭ ����
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_UPDATE_DIGEST_FAIL: �ؽ� ������Ʈ ����
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_FINAL_DIGEST_FAIL: �ؽ� ���̳� ����
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_HASH_GEN_FAIL: HASH GEN �������
*/
ISC_STATUS isc_Generate_DRBG(ISC_DRBG_UNIT *drbg, uint8 *output, int output_len);

/*!
* \brief
* isc_Instantiate_DRBG �Լ��� �Է°� ���� �Լ� (�ʿ�� ���)
* \param *drbg
* ISC_DRBG_UNIT ����ü ������
* \param *entropy_input
* ������ entropy �Է°�
* \param entropy_input_len
* ������ entropy �Է°� ����
* \param *nonce_input
* ������ nonce �Է°�
* \param nonce_len
* ������ nonce �Է°� ����
* \param *personalization_string
* ������ personalization_string �Է°�
* \param personalization_string_len
* ������ personalization_string �Է°� ����
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_STATUS isc_Set_Instantiate_DRBG_Param(ISC_DRBG_UNIT *drbg, const uint8 *entropy_input, uint8 entropy_input_len, const uint8 *nonce, uint8 nonce_len, const uint8 *personalization_string, uint8 personalization_string_len);

/*!
* \brief
* isc_Reseed_DRBG �Լ��� �Է°� ���� �Լ� (�ʿ�� ���)
* \param *drbg
* ISC_DRBG_UNIT ����ü ������
* \param *additional_input
* ������ additional_input �Է°�
* \param additional_input_len
* ������ additional_input �Է°� ����
* \param *entropy_pr_input
* ������ entropy_pr �Է°�
* \param entropy_pr_input_len
* ������ entropy_pr �Է°� ����
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_STATUS isc_Set_Reseed_DRBG_Param(ISC_DRBG_UNIT *drbg, const uint8 *additional_input, uint8 additional_input_len, const uint8 *entropy_input_pr, uint8 entropy_input_pr_len);

/*!
* \brief
* isc_Generate_DRBG �Լ��� �Է°� ���� �Լ� (�ʿ�� ���)
* \param *drbg
* ISC_DRBG_UNIT ����ü ������
* \param *additional_input
* ������ additional_input �Է°�
* \param additional_input_len
* ������ additional_input �Է°� ����
* \param *entropy_pr_input
* ������ reseed �Լ��� ���� �� entropy_pr �Է°�
* \param entropy_pr_input_len
* ������ reseed �Լ��� ���� �� entropy_pr �Է°� ����
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
 ISC_STATUS isc_Set_Generate_DRBG_Param(ISC_DRBG_UNIT *drbg, const uint8 *additional_input, uint8 additional_input_len, const uint8 *entropy_input_pr, uint8 entropy_input_pr_len);

#else /* #ifndef ISC_CRYPTO_VS_TEST */

ISC_API ISC_DRBG_UNIT *isc_New_DRBG_Unit(void);
ISC_API void isc_Clean_DRBG_Unit(ISC_DRBG_UNIT *drbg);
ISC_API void isc_Free_DRBG_Unit(ISC_DRBG_UNIT *drbg);
ISC_API ISC_STATUS isc_Init_DRBG(ISC_DRBG_UNIT *drbg, int algo_id, int operation_mode, int prediction_resistance_flag, int entropy_collection_mode);
ISC_API ISC_STATUS isc_Instantiate_DRBG(ISC_DRBG_UNIT *drbg, int requested_instantiation_security_strength);
ISC_API ISC_STATUS isc_Reseed_DRBG(ISC_DRBG_UNIT *drbg);
ISC_API ISC_STATUS isc_Generate_DRBG(ISC_DRBG_UNIT *drbg, uint8 *output, int output_len);
ISC_API ISC_STATUS isc_Set_Instantiate_DRBG_Param(ISC_DRBG_UNIT *drbg, const uint8 *entropy_input, uint8 entropy_input_len, const uint8 *nonce, uint8 nonce_len, const uint8 *personalization_string, uint8 personalization_string_len);
ISC_API ISC_STATUS isc_Set_Reseed_DRBG_Param(ISC_DRBG_UNIT *drbg, const uint8 *additional_input, uint8 additional_input_len, const uint8 *entropy_input_pr, uint8 entropy_input_pr_len);
ISC_API ISC_STATUS isc_Set_Generate_DRBG_Param(ISC_DRBG_UNIT *drbg, const uint8 *additional_input, uint8 additional_input_len, const uint8 *entropy_input_pr, uint8 entropy_input_pr_len);

#endif /* #ifdef ISC_CRYPTO_VS_TEST */	

#else
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Rand_Bytes_DRBG, (uint8 *drbg_input, int drbg_input_length, int operation_mode, int hash_id int prediction_resistance_flag), (drbg_input, drbg_input_length, operation_mode, hash_id, prediction_resistance_flag), NULL );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_RAND_BYTES, (uint8 *rand, int length), (rand, length), NULL);
ISC_RET_LOADLIB_CRYPTO(void, ISC_Uninstantiate_DRBG, (void), (), NULL );
#endif

#ifdef  __cplusplus
}
#endif

#endif
#endif /* HEADER_DRBG_H */
