/*!
* \file error.h
* \brief 에러 처리에 관련된 내용을 담고 있는 헤더\n
* INICrypto의 에러 코드는 4바이트로 이루어져 있으며,\n
* 1 번째 바이트는 에러가 발생한 위치 / 2번째 바이트는 함수 /\n
* 3~4번째 바이트는 에러의 이유를 나타냄\n
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_ERROR_H
#define HEADER_ERROR_H

#include <stdlib.h>

#include "foundation.h"

#define ISC_SUCCESS							0		/*!< 성공*/
#define ISC_FAIL							1		/*!< 실패*/
#define ISC_INVALID_SIZE					0		/*!< size 실패*/
#define ISC_NULL_STRING						NULL	/*!< null string*/ 

typedef struct ERR_string_data_st
{	ISC_STATUS err;
const char *err_string;
} ERR_STRING_DATA;


/*--------------------------------------------------------------*/
/* mask list 													*/
/*--------------------------------------------------------------*/
#define ISC_L_MASK								0xFF000000	/*!< */
#define ISC_F_MASK								0x00FF0000	/*!< */
#define ISC_ERR_MASK							0x0000FFFF  /*!< */

/*--------------------------------------------------------------*/
/* algorithm list 												*/
/*--------------------------------------------------------------*/
#define ISC_L_AES_INTERFACE						0x01000000  /*!< */
#define ISC_F_INIT_AES_KEY						0x00010000  /*!< */
#define ISC_F_INIT_AES							0x00020000  /*!< */
#define ISC_F_DO_AES_ECB						0x00030000  /*!< */
#define ISC_F_DO_AES_CBC						0x00040000  /*!< */
#define ISC_F_DO_AES_CFB						0x00050000  /*!< */
#define ISC_F_DO_AES_OFB						0x00060000  /*!< */
#define ISC_F_DO_AES_CTR						0x00070000  /*!< */
#define ISC_F_DO_AES_FPE_ASCII					0x00080000  /*!< */
#define ISC_F_DO_AES_FPE_ENG					0x00090000  /*!< */
#define ISC_F_DO_AES_FPE_ASCII_NUM				0x000A0000  /*!< */
#define ISC_F_DO_AES_CCM						0x000B0000  /*!< */
#define ISC_F_DO_AES_GCM						0x000C0000  /*!< */

#define ISC_L_ARIA_INTERFACE					0x02000000  /*!< */
#define ISC_F_INIT_ARIA_KEY						0x00010000  /*!< */
#define ISC_F_INIT_ARIA							0x00020000  /*!< */
#define ISC_F_DO_ARIA_ECB						0x00030000  /*!< */
#define ISC_F_DO_ARIA_CBC						0x00040000  /*!< */
#define ISC_F_DO_ARIA_CFB						0x00050000  /*!< */
#define ISC_F_DO_ARIA_OFB						0x00060000  /*!< */
#define ISC_F_DO_ARIA_CTR						0x00070000  /*!< */
#define ISC_F_DO_ARIA_CCM						0x000B0000  /*!< */
#define ISC_F_DO_ARIA_GCM						0x000C0000  /*!< */

#define ISC_L_BF_INTERFACE						0x03000000  /*!< */
#define ISC_F_INIT_BF_KEY						0x00010000  /*!< */
#define ISC_F_INIT_BF							0x00020000  /*!< */
#define ISC_F_DO_BF_ECB							0x00030000  /*!< */
#define ISC_F_DO_BF_CBC							0x00040000  /*!< */
#define ISC_F_DO_BF_CFB							0x00050000  /*!< */
#define ISC_F_DO_BF_OFB							0x00060000  /*!< */
#define ISC_F_DO_BF_CTR							0x00070000  /*!< */

#define ISC_L_BIGINT							0x04000000  /*!< */
#define ISC_F_INIT_BIGINT						0x00010000  /*!< */
#define ISC_F_FREE_BIGINT						0x00020000  /*!< */
#define ISC_F_ADD_BIGINT_WORD					0x00030000  /*!< */
#define ISC_F_SUB_BIGINT_WORD					0x00040000  /*!< */
#define ISC_F_MTP_BIGINT_WORD					0x00050000  /*!< */
#define ISC_F_GCD_BIGINT						0x00060000  /*!< */
#define ISC_F_MOD_INVERSE_BIGINT				0x00070000  /*!< */
#define ISC_F_FREE_BIGINT_MONT					0x00080000  /*!< */
#define ISC_F_SET_BIGINT_MONT					0x00090000  /*!< */
#define ISC_F_MOD_EXP_MONT_BIGINT				0x000A0000  /*!< */
#define ISC_F_MOD_MUL_BIGINT_MONTGOMERY			0x000B0000  /*!< */
#define ISC_F_BIGINT_FROM_MONTGOMERY			0x000C0000  /*!< */
#define ISC_F_ADD_BIGINT						0x000D0000  /*!< */
#define ISC_F_SUB_BIGINT						0x000E0000  /*!< */
#define ISC_F_MOD_SUB_BIGINT					0x000F0000  /*!< */
#define ISC_F_DIV_BIGINT						0x00100000  /*!< */
#define ISC_F_SQR_BIGINT						0x00110000  /*!< */
#define ISC_F_MTP_BIGINT						0x00120000  /*!< */
#define ISC_F_MOD_MTP_BIGINT					0x00130000  /*!< */
#define ISC_F_MOD_EXP_BIGINT					0x00140000  /*!< */
#define ISC_F_LEFT_SHIFT_BIGINT					0x00150000  /*!< */
#define ISC_F_RIGHT_SHIFT_BIGINT				0x00160000  /*!< */
#define ISC_F_RAND_BIGINT_EX					0x00170000  /*!< */
#define ISC_F_RAND_BIGINT						0x00180000  /*!< */
#define ISC_F_FREE_BIGINT_POOL					0x00190000  /*!< */
#define ISC_F_CLEAR_BIGINT_POOL					0x001A0000  /*!< */
#define ISC_F_START_BIGINT_POOL					0x001B0000  /*!< */
#define ISC_F_FINISH_BIGINT_POOL				0x001C0000  /*!< */
#define ISC_F_RELEASE_BIGINT_POOL				0x001D0000  /*!< */
#define ISC_F_GENERATE_BIGINT_PRIME				0x001E0000  /*!< */
#define ISC_F_COPY_BIGINT						0x001F0000  /*!< */
#define ISC_F_SET_BIGINT_WORD					0x00200000  /*!< */
#define ISC_F_SET_BIGINT_BIT					0x00210000  /*!< */

#define ISC_L_BLOCK_CIPHER						0x05000000  /*!< */
#define ISC_F_INIT_BLOCKCIPHER					0x00010000  /*!< */
#define ISC_F_UPDATE_BLOCKCIPHER				0x00020000  /*!< */
#define ISC_F_UPDATE_ENCRYPTION					0x00030000  /*!< */
#define ISC_F_UPDATE_DECRYPTION					0x00040000  /*!< */
#define ISC_F_FINAL_BLOCKCIPHER					0x00050000  /*!< */
#define ISC_F_FINAL_ENCRYPTION					0x00060000  /*!< */
#define ISC_F_FINAL_DECRYPTION					0x00070000  /*!< */
#define ISC_F_BLOCKCIPHER						0x00080000  /*!< */
#define ISC_F_INIT_ALGORITHM					0x00090000  /*!< */
#define ISC_F_INIT_ADVANCED_BLOCKCIPHER			0x000A0000  /*!< */
#define ISC_F_DO_FINAL_ADVANCED_BLOCKCIPHER		0x000B0000  /*!< */

#define ISC_L_CBC_MAC							0x06000000  /*!< */
#define ISC_F_INIT_CBC_MAC						0x00010000  /*!< */
#define ISC_F_UPDATE_CBC_MAC					0x00020000  /*!< */
#define ISC_F_FINAL_CBC_MAC						0x00030000  /*!< */
#define ISC_F_CBC_MAC							0x00040000  /*!< */

#define ISC_L_DES_EDE_INTERFACE					0x07000000  /*!< */
#define ISC_F_INIT_DES_EDE_KEY					0x00010000  /*!< */
#define ISC_F_DO_DES_EDE_ECB					0x00020000  /*!< */
#define ISC_F_DO_DES_EDE_CBC					0x00030000  /*!< */
#define ISC_F_DO_DES_EDE_CFB					0x00040000  /*!< */
#define ISC_F_DO_DES_EDE_OFB					0x00050000  /*!< */
#define ISC_F_DO_DES_EDE_CTR					0x00060000  /*!< */
#define ISC_F_INIT_ENCRYPT_DES_EDE_KEY			0x00070000  /*!< */

#define ISC_L_DES_INTERFACE						0x08000000  /*!< */
#define ISC_F_INIT_DES_KEY						0x00010000  /*!< */
#define ISC_F_DO_DES_ECB						0x00020000  /*!< */
#define ISC_F_DO_DES_CBC						0x00030000  /*!< */
#define ISC_F_DO_DES_CFB						0x00040000  /*!< */
#define ISC_F_DO_DES_OFB						0x00050000  /*!< */
#define ISC_F_DO_DES_CTR						0x00060000  /*!< */

#define ISC_L_DES_MAC							0x09000000  /*!< */
#define ISC_F_DES_MAC							0x00010000  /*!< */

#define ISC_L_DIGEST							0x0A000000  /*!< */
#define ISC_F_INIT_DIGEST						0x00010000  /*!< */
#define ISC_F_UPDATE_DIGEST						0x00020000  /*!< */
#define ISC_F_FINAL_DIGEST						0x00030000  /*!< */
#define ISC_F_INIT_DIGEST_ALG					0x00040000  /*!< */
#define ISC_F_DIGEST							0x00050000  /*!< */

#define ISC_L_DRBG								0x0B000000	/*!< */
#define ISC_F_INIT_DRBG							0x00010000  /*!< */
#define ISC_F_INSTANTIATE_DRBG					0x00020000  /*!< */
#define ISC_F_RESEED_DRBG						0x00030000  /*!< */
#define ISC_F_GENERATE_DRBG						0x00040000  /*!< */
#define ISC_F_RAND_BYTES_DRBG					0x00050000  /*!< */
#define ISC_F_GET_RAND_BIGINT_EX				0x00060000  /*!< */
#define ISC_F_INIT_HASHDRBG						0x00070000  /*!< */
#define ISC_F_INSTANTIATE_HASHDRBG				0x00080000  /*!< */
#define ISC_F_RESEED_HASHDRBG					0x00090000  /*!< */
#define ISC_F_GENERATE_HASHDRBG					0x000A0000  /*!< */


#define ISC_L_DSA								0x0C000000  /*!< */
#define ISC_F_SET_DSA_PARAMS					0x00010000  /*!< */
#define ISC_F_INIT_DSA							0x00020000  /*!< */
#define ISC_F_UPDATE_DSA						0x00030000  /*!< */
#define ISC_F_FINAL_DSA							0x00040000  /*!< */
#define ISC_F_SIGN_DSA							0x00050000  /*!< */
#define ISC_F_VERIFY_DSA						0x00060000  /*!< */
#define ISC_F_GENERATE_DSA_PARAMS				0x00070000  /*!< */
#define ISC_F_GENERATE_DSA_KEY_PAIR				0x00080000  /*!< */
#define ISC_F_GENERATE_DSA_KEY					0x00090000  /*!< */


#define ISC_L_FOUNDATION						0x0D000000 	/*!< */
#define ISC_F_CHANGE_NON_PROVENMODE				0x00010000  /*!< */

#define ISC_L_HAS160							0x0E000000	/*!< */
#define ISC_F_INIT_HAS160						0x00010000  /*!< */
#define ISC_F_UPDATE_HAS160						0x00020000  /*!< */
#define ISC_F_FINAL_HAS160						0x00030000  /*!< */

#define ISC_L_HMAC								0x0F000000  /*!< */
#define ISC_F_INIT_HMAC							0x00010000  /*!< */
#define ISC_F_UPDATE_HMAC						0x00020000  /*!< */
#define ISC_F_FINAL_HMAC						0x00030000  /*!< */
#define ISC_F_HMAC								0x00040000  /*!< */

#define ISC_L_KCDSA								0x10000000  /*!< */
#define ISC_F_GENERATE_KCDSA_PARAMS_EX			0x00010000  /*!< */
#define ISC_F_GENERATE_KCDSA_PARAMS				0x00020000  /*!< */
#define ISC_F_GET_RAND_KCDSA_BIGINT				0x00030000  /*!< */
#define ISC_F_GENERATE_KCDSA_KEY_PAIR_EX		0x00040000  /*!< */
#define ISC_F_GENERATE_KCDSA_KEY_PAIR			0x00050000  /*!< */
#define ISC_F_SET_KCDSA_PARAMS					0x00060000  /*!< */
#define ISC_F_INIT_KCDSA_EX						0x00070000  /*!< */
#define ISC_F_INIT_KCDSA						0x00080000  /*!< */
#define ISC_F_UPDATE_KCDSA						0x00090000  /*!< */
#define ISC_F_FINAL_KCDSA						0x000A0000  /*!< */
#define ISC_F_SIGN_KCDSA						0x000B0000  /*!< */
#define ISC_F_VERIFY_KCDSA						0x000C0000  /*!< */

#define ISC_L_KEY								0x11000000  /*!< */

#define ISC_L_MD5								0x12000000	/*!< */
#define ISC_F_INIT_MD5							0x00010000  /*!< */
#define ISC_F_UPDATE_MD5						0x00020000  /*!< */
#define ISC_F_FINAL_MD5							0x00030000  /*!< */

#define ISC_L_MDC2								0x13000000  /*!< */
#define ISC_F_INIT_MDC2							0x00010000  /*!< */
#define ISC_F_UPDATE_MDC2						0x00020000  /*!< */
#define ISC_F_FINAL_MDC2						0x00030000  /*!< */

#define ISC_L_PRNG								0x14000000  /*!< */
#define ISC_F_INIT_PRNG							0x00010000  /*!< */
#define ISC_F_INIT_GFUNC_ALG					0x00020000  /*!< */
#define ISC_F_GET_INNER_RAND					0x00030000  /*!< */
#define ISC_F_GET_RAND							0x00040000  /*!< */
#define ISC_F_GET_RAND_BIGINT					0x00050000  /*!< */
#define ISC_F_RAND_BYTES						0x00060000  /*!< */
#define ISC_F_INIT_PRNG_ALG						0x00070000  /*!< */

#define ISC_L_RC2_INTERFACE						0x15000000  /*!< */
#define ISC_F_INIT_RC2_KEY						0x00010000  /*!< */
#define ISC_F_DO_RC2_ECB						0x00020000  /*!< */
#define ISC_F_DO_RC2_CBC						0x00030000  /*!< */
#define ISC_F_DO_RC2_CFB						0x00040000  /*!< */
#define ISC_F_DO_RC2_OFB						0x00050000  /*!< */

#define ISC_L_RC4_INTERFACE						0x16000000  /*!< */

#define ISC_L_RC5_INTERFACE						0x17000000  /*!< */
#define ISC_F_INIT_RC5_KEY						0x00010000  /*!< */
#define ISC_F_DO_RC5_ECB						0x00020000  /*!< */
#define ISC_F_DO_RC5_CBC						0x00030000  /*!< */
#define ISC_F_DO_RC5_CFB						0x00040000  /*!< */
#define ISC_F_DO_RC5_OFB						0x00050000  /*!< */
#define ISC_F_DO_RC5_CTR						0x00060000  /*!< */

#define ISC_L_RSA								0x18000000  /*!< */
#define ISC_F_SET_RSA_PRAMS						0x00010000  /*!< */
#define ISC_F_SET_RSA_PUBLIC_PRAMS				0x00020000  /*!< */
#define ISC_F_INIT_RSASSA						0x00030000  /*!< */
#define ISC_F_UPDATE_RSASSA						0x00040000  /*!< */
#define ISC_F_FINAL_RSASSA						0x00050000  /*!< */
#define ISC_F_SIGN_RSASSA						0x00060000  /*!< */
#define ISC_F_VERIFY_RSASSA						0x00070000  /*!< */
#define ISC_F_INIT_RSAES						0x00080000  /*!< */
#define ISC_F_ENCRYPT_RSAES						0x00090000  /*!< */
#define ISC_F_DECRYPT_RSAES						0x000A0000  /*!< */
#define ISC_F_GENERATE_RSA_PARAMS_EX			0x000B0000  /*!< */
#define ISC_F_GENERATE_RSA_PARAMS				0x000C0000  /*!< */
#define ISC_F_CHECK_PKCS1_v1_5_ENCODE			0x000D0000  /*!< */
#define ISC_F_PKCS1_MGF1						0x000E0000  /*!< */
#define ISC_F_ADD_RSASSA_ENCODING				0x000F0000  /*!< */
#define ISC_F_CHECK_RSASSA_PKCS1_PSS_ENCODE		0x00100000  /*!< */

#define ISC_L_SEED_INTERFACE					0x19000000  /*!< */
#define ISC_F_INIT_SEED_KEY						0x00010000  /*!< */
#define ISC_F_INIT_SEED							0x00020000  /*!< */
#define ISC_F_DO_SEED_CBC						0x00030000  /*!< */
#define ISC_F_DO_SEED_CFB						0x00040000  /*!< */
#define ISC_F_DO_SEED_ECB						0x00050000  /*!< */
#define ISC_F_DO_SEED_OFB						0x00060000  /*!< */
#define ISC_F_DO_SEED_CTR						0x00070000  /*!< */
#define ISC_F_DO_SEED_CCM						0x000B0000  /*!< */
#define ISC_F_DO_SEED_GCM						0x000C0000  /*!< */

#define ISC_L_SELF_TEST							0x1A000000	/*!< */
#define ISC_F_LIB_INTEGRITY_CHECK				0x00010000  /*!< */
#define ISC_F_CONTEXT_CHECK						0x00020000  /*!< */
#define ISC_F_VERSION_CHECK						0x00030000  /*!< */
#define ISC_F_ENTROPY_CHECK						0x00040000  /*!< */
#define ISC_F_DRBG_CHECK						0x00050000  /*!< */
#define ISC_F_HMAC_CHECK						0x00060000  /*!< */
#define ISC_F_DIGEST_CHECK						0x00070000  /*!< */
#define ISC_F_SYMMETIC_KEY_CHECK				0x00080000  /*!< */
#define ISC_F_SYMMETIC_ALGORITHM_CHECK			0x00090000  /*!< */
#define ISC_F_ASYMMETIC_KEY_CHECK				0x000A0000  /*!< */
#define ISC_F_RSAES_OAEP_CHECK					0x000B0000  /*!< */
#define ISC_F_RSASSA_CHECK						0x000C0000  /*!< */
#define ISC_F_KCDSA_CHECK						0x000D0000  /*!< */
#define ISC_F_DH_CHECK							0x000E0000  /*!< */
#define ISC_F_ECDH_CHECK						0x000F0000  /*!< */
#define ISC_F_ECDSA_CHECK						0x00100000  /*!< */
#define ISC_F_ECKCDSA_CHECK						0x00110000  /*!< */
#define ISC_F_INITIALIZE						0x00120000  /*!< */
#define ISC_F_SYMMETIC_MAC_ALGORITHM_CHECK		0x00130000  /*!< */
#define ISC_F_PBKDF_CHECK						0x00140000  /*!< */

#define ISC_L_SHA								0x1B000000	/*!< */
#define ISC_F_INIT_SHA1							0x00010000  /*!< */
#define ISC_F_UPDATE_SHA1						0x00020000  /*!< */
#define ISC_F_FINAL_SHA1						0x00030000  /*!< */
#define ISC_F_COMP_SHA1							0x00040000  /*!< */
#define ISC_F_INIT_SHA224						0x00050000  /*!< */
#define ISC_F_UPDATE_SHA224						0x00060000  /*!< */
#define ISC_F_FINAL_SHA224						0x00070000  /*!< */
#define ISC_F_INIT_SHA256						0x00080000  /*!< */
#define ISC_F_UPDATE_SHA256						0x00090000  /*!< */
#define ISC_F_FINAL_SHA256						0x000A0000  /*!< */
#define ISC_F_COMP_SHA256						0x000B0000  /*!< */
#define ISC_F_INIT_SHA384						0x000C0000  /*!< */
#define ISC_F_UPDATE_SHA384						0x000D0000  /*!< */
#define ISC_F_FINAL_SHA384						0x000E0000  /*!< */
#define ISC_F_INIT_SHA512						0x000F0000  /*!< */
#define ISC_F_UPDATE_SHA512						0x00200000  /*!< */
#define ISC_F_FINAL_SHA512						0x00210000  /*!< */
#define ISC_F_INIT_SHA3_224						0x00220000  /*!< */
#define ISC_F_UPDATE_SHA3_224					0x00230000  /*!< */
#define ISC_F_FINAL_SHA3_224					0x00240000  /*!< */
#define ISC_F_INIT_SHA3_256						0x00250000  /*!< */
#define ISC_F_UPDATE_SHA3_256					0x00260000  /*!< */
#define ISC_F_FINAL_SHA3_256					0x00270000  /*!< */
#define ISC_F_INIT_SHA3_384						0x00280000  /*!< */
#define ISC_F_UPDATE_SHA3_384					0x00290000  /*!< */
#define ISC_F_FINAL_SHA3_384					0x002A0000  /*!< */
#define ISC_F_INIT_SHA3_512						0x002B0000  /*!< */
#define ISC_F_UPDATE_SHA3_512					0x002C0000  /*!< */
#define ISC_F_FINAL_SHA3_512					0x002D0000  /*!< */

#define ISC_L_ENTROPY							0x1C000000	/*!< */
#define ISC_F_ADD_ENTROPY						0x00010000  /*!< */
#define ISC_F_COLLECT_ENTROPY					0x00020000  /*!< */
#define ISC_F_DIGEST_ENTROPY					0x00030000  /*!< */
#define ISC_F_GET_ENTROPY						0x00040000  /*!< */
#define ISC_F_GET_ENTROPY_INPUT					0x00050000  /*!< */
#define ISC_F_GET_ENTROPY_AND_NONCE_INPUT		0x00060000  /*!< */
#define ISC_F_CHECK_AND_GET_ENTROPY				0x00070000  /*!< */

#define ISC_L_METEX_LOCK						0x1D000000	/*!< */
#define ISC_F_INIT_LOCK							0x00010000  /*!< */
#define ISC_F_WAIT_LOCK							0x00020000  /*!< */
#define ISC_F_RELEASE_LOCK						0x00030000  /*!< */
#define ISC_F_CLEAR_LOCK						0x00040000  /*!< */

#define ISC_L_LEA_INTERFACE						0x1F000000  /*!< */
#define ISC_F_INIT_LEA_KEY						0x00010000  /*!< */
#define ISC_F_INIT_LEA							0x00020000  /*!< */
#define ISC_F_DO_LEA_ECB						0x00030000  /*!< */
#define ISC_F_DO_LEA_CBC						0x00040000  /*!< */
#define ISC_F_DO_LEA_CFB						0x00050000  /*!< */
#define ISC_F_DO_LEA_OFB						0x00060000  /*!< */
#define ISC_F_DO_LEA_CTR						0x00070000  /*!< */
#define ISC_F_DO_LEA_CCM						0x000B0000  /*!< */
#define ISC_F_DO_LEA_GCM						0x000C0000  /*!< */

#define ISC_L_DH								0x20000000  /*!< */
#define ISC_F_INIT_DH							0x00010000  /*!< */
#define ISC_F_INIT_DH_PARAMS					0x00020000  /*!< */
#define ISC_F_GENERATE_DH_PARAMS				0x00030000  /*!< */
#define ISC_F_GENERATE_DH_KEY_PAIR				0x00040000  /*!< */
#define ISC_F_COMPUTE_KEY						0x00050000  /*!< */

#define ISC_L_ECDSA								0x21000000  /*!< */
#define ISC_F_INIT_ECDSA						0x00010000  /*!< */
#define ISC_F_UPDATE_ECDSA						0x00020000  /*!< */
#define ISC_F_FINAL_ECDSA						0x00030000  /*!< */
#define ISC_F_SIGN_ECDSA						0x00040000  /*!< */
#define ISC_F_VERIFY_ECDSA						0x00050000  /*!< */
#define ISC_F_GENERATE_ECDSA_KEY_PAIR			0x00060000  /*!< */ 
#define ISC_F_SET_ECDSA_PARAMS					0x00070000  /*!< */
#define ISC_F_SET_ECDSA_PARAMS_EX				0x00080000  /*!< */

#define ISC_L_ECKCDSA							0x22000000  /*!< */
#define ISC_F_INIT_ECKCDSA						0x00010000  /*!< */
#define ISC_F_UPDATE_ECKCDSA					0x00020000  /*!< */
#define ISC_F_FINAL_ECKCDSA						0x00030000  /*!< */
#define ISC_F_SIGN_ECKCDSA						0x00040000  /*!< */
#define ISC_F_VERIFY_ECKCDSA					0x00050000  /*!< */
#define ISC_F_SET_ECKCDSA_PARAMS				0x00060000  /*!< */
#define ISC_F_GET_RAND_ECKCDSA_BIGINT			0x00070000  /*!< */
#define ISC_F_GENERATE_ECKCDSA_KEY_PAIR			0x00080000  /*!< */
#define ISC_F_SET_ECKCDSA_PARAMS_EX				0x00090000  /*!< */

#define ISC_L_ECDH								0x23000000  /*!< */
#define ISC_F_INIT_ECDH							0x00010000  /*!< */
#define ISC_F_SET_ECDH_PARAMS					0x00020000  /*!< */
#define ISC_F_GENERATE_ECDH_KEY_PAIR			0x00030000  /*!< */
#define ISC_F_COMPUTE_ECDH_KEY					0x00040000  /*!< */
#define ISC_F_SET_ECDH_PARAMS_EX				0x00050000  /*!< */

#define ISC_L_ECC								0x22000000  /*!< */
#define ISC_F_GENERATE_ECC_KEY_PAIR				0x00010000  /*!< */
#define ISC_F_GENERATE_ECC_PUB_KEY				0x00020000  /*!< */
#define ISC_F_VALIDATE_ECC_PUB_KEY				0x00030000  /*!< */
#define ISC_F_GENERATE_ECC_KEY_PAIR_NIST		0x00040000  /*!< */
#define ISC_F_GENERATE_ECC_PUB_KEY_NIST			0x00050000  /*!< */
#define	ISC_F_SQR_POLY_K233						0x00060000  /*!< */
#define	ISC_F_SQR_POLY_K283						0x00070000  /*!< */
#define	ISC_F_SQR_BIGINT_P224					0x00080000  /*!< */
#define	ISC_F_SQR_BIGINT_P256					0x00090000  /*!< */
#define	ISC_F_ADD_POLY_K233						0x000A0000  /*!< */
#define	ISC_F_ADD_POLY_K283						0x000B0000  /*!< */
#define	ISC_F_MTP_POLY_K233						0x000C0000  /*!< */
#define	ISC_F_MTP_POLY_K283						0x000D0000  /*!< */
#define	ISC_F_MTP_BIGINT_P224					0x000E0000  /*!< */
#define	ISC_F_MTP_BIGINT_P256					0x000F0000  /*!< */
#define	ISC_F_ADD_BIGINT_P224					0x00110000  /*!< */
#define	ISC_F_ADD_BIGINT_P256					0x00120000  /*!< */
#define	ISC_F_SUB_BIGINT_P224					0x00130000  /*!< */
#define	ISC_F_SUB_BIGINT_P256					0x00140000  /*!< */
#define	ISC_F_MOD_POLY_K233						0x00150000  /*!< */
#define	ISC_F_MOD_POLY_K283						0x00160000  /*!< */
#define	ISC_F_MOD_BIGINT_P224					0x00170000  /*!< */
#define	ISC_F_MOD_BIGINT_P256					0x00180000  /*!< */
#define	ISC_F_MOD_MTP_POLY_K233					0x00190000  /*!< */
#define	ISC_F_MOD_MTP_POLY_K283					0x001A0000  /*!< */
#define	ISC_F_MOD_MTP_BIGINT_P224				0x001B0000  /*!< */
#define	ISC_F_MOD_MTP_BIGINT_P256				0x001C0000  /*!< */
#define	ISC_F_MOD_SQR_POLY_K233					0x001D0000  /*!< */
#define	ISC_F_MOD_SQR_POLY_K283					0x001E0000  /*!< */
#define	ISC_F_MOD_SQR_BIGINT_P224				0x001F0000  /*!< */
#define	ISC_F_MOD_SQR_BIGINT_P256				0x00200000  /*!< */
#define	ISC_F_MOD_INV_POLY_K233					0x00210000  /*!< */
#define	ISC_F_MOD_INV_POLY_K283					0x00220000  /*!< */
#define	ISC_F_MOD_INV_BIGINT_P224				0x00230000  /*!< */
#define	ISC_F_MOD_INV_BIGINT_P256				0x00240000  /*!< */
#define	ISC_F_ADD_F2M_ECC_K233AC				0x00250000  /*!< */
#define	ISC_F_ADD_F2M_ECC_K283AC				0x00260000  /*!< */
#define	ISC_F_ADD_F2M_ECC_K233PC				0x00270000  /*!< */
#define	ISC_F_ADD_F2M_ECC_K233PC2				0x00280000  /*!< */
#define	ISC_F_ADD_F2M_ECC_K283PC				0x00290000  /*!< */
#define	ISC_F_ADD_F2M_ECC_K283PC2				0x002A0000  /*!< */
#define	ISC_F_DBL_F2M_ECC_K233AC				0x002B0000  /*!< */
#define	ISC_F_DBL_F2M_ECC_K283AC				0x002C0000  /*!< */
#define	ISC_F_DBL_F2M_ECC_K233PC				0x002D0000  /*!< */
#define	ISC_F_DBL_F2M_ECC_K283PC				0x002E0000  /*!< */
#define	ISC_F_DBL_FP_ECC_P224AC					0x002F0000  /*!< */
#define	ISC_F_DBL_FP_ECC_P256AC					0x00300000  /*!< */
#define	ISC_F_DBL_FP_ECC_P224PC					0x00310000  /*!< */
#define	ISC_F_DBL_FP_ECC_P256PC					0x00320000  /*!< */
#define	ISC_F_ADD_FP_ECC_P224AC					0x00330000  /*!< */
#define	ISC_F_ADD_FP_ECC_P256AC					0x00340000  /*!< */
#define	ISC_F_ADD_FP_ECC_P224PC					0x00350000  /*!< */
#define	ISC_F_ADD_FP_ECC_P224PC2				0x00360000  /*!< */
#define	ISC_F_ADD_FP_ECC_P256PC					0x00370000  /*!< */
#define	ISC_F_ADD_FP_ECC_P256PC2				0x00380000  /*!< */
#define	ISC_F_MTP_FP_ECC_P224PC_FBC				0x00390000  /*!< */
#define	ISC_F_MTP_FP_ECC_P256PC_FBC				0x003A0000  /*!< */
#define	ISC_F_MTP_ECC							0x003B0000  /*!< */
#define	ISC_F_MTP_ECC_FBC						0x003C0000  /*!< */
#define	ISC_F_MTP_ECC_MONT						0x003D0000  /*!< */
#define	ISC_F_MOD								0x003E0000  /*!< */
#define	ISC_F_MOD_ADD							0x003F0000  /*!< */
#define	ISC_F_MOD_INV							0x00400000  /*!< */
#define	ISC_F_MOD_MUL							0x00410000  /*!< */
#define ISC_F_COPY_ECC_KEY						0x00420000  /*!< */
#define ISC_F_SET_ECC_KEY_PRAMS					0x00430000  /*!< */
#define ISC_F_SET_ECC_KEY_PRAMS_EX				0x00440000  /*!< */

#define ISC_L_BLOCK_CIPHER_MAC					0x24000000  /*!< */
#define ISC_F_INIT_BLOCKCIPHER_MAC				0x00010000  /*!< */
#define ISC_F_UPDATE_BLOCKCIPHER_MAC			0x00020000  /*!< */
#define ISC_F_UPDATE_ENCRYPTION_MAC				0x00030000  /*!< */
#define ISC_F_UPDATE_DECRYPTION_MAC				0x00040000  /*!< */
#define ISC_F_FINAL_BLOCKCIPHER_MAC				0x00050000  /*!< */
#define ISC_F_FINAL_ENCRYPTION_MAC				0x00060000  /*!< */
#define ISC_F_FINAL_DECRYPTION_MAC				0x00070000  /*!< */
#define ISC_F_BLOCKCIPHER_MAC					0x00080000  /*!< */
#define ISC_F_INIT_ALGORITHM_MAC				0x00090000  /*!< */

#define ISC_L_LSH								0x25000000	/*!< */
#define ISC_F_LSH256							0x00100000  /*!< */
#define ISC_F_LSH256_224						0x00200000  /*!< */
#define ISC_F_LSH256_256						0x00300000  /*!< */
#define ISC_F_LSH512							0x00400000  /*!< */
#define ISC_F_LSH512_224						0x00500000  /*!< */
#define ISC_F_LSH512_256						0x00600000  /*!< */
#define ISC_F_LSH512_384						0x00700000  /*!< */
#define ISC_F_LSH512_512						0x00800000  /*!< */
#define ISC_F_LSH_INIT							0x00010000  /*!< */
#define ISC_F_LSH_UPDATE						0x00020000  /*!< */
#define ISC_F_LSH_FINAL							0x00030000  /*!< */
#define ISC_F_INIT_LSH256_224					(ISC_F_LSH256_224 | ISC_F_LSH_INIT)
#define ISC_F_UPDATE_LSH256_224					(ISC_F_LSH256_224 | ISC_F_LSH_UPDATE)
#define ISC_F_FINAL_LSH256_224					(ISC_F_LSH256_224 | ISC_F_LSH_FINAL)
#define ISC_F_INIT_LSH256_256					(ISC_F_LSH256_256 | ISC_F_LSH_INIT)
#define ISC_F_UPDATE_LSH256_256					(ISC_F_LSH256_256 | ISC_F_LSH_UPDATE)
#define ISC_F_FINAL_LSH256_256					(ISC_F_LSH256_256 | ISC_F_LSH_FINAL)
#define ISC_F_INIT_LSH512_224					(ISC_F_LSH512_224 | ISC_F_LSH_INIT)
#define ISC_F_UPDATE_LSH512_224					(ISC_F_LSH512_224 | ISC_F_LSH_UPDATE)
#define ISC_F_FINAL_LSH512_224					(ISC_F_LSH512_224 | ISC_F_LSH_FINAL)
#define ISC_F_INIT_LSH512_256					(ISC_F_LSH512_256 | ISC_F_LSH_INIT)
#define ISC_F_UPDATE_LSH512_256					(ISC_F_LSH512_256 | ISC_F_LSH_UPDATE)
#define ISC_F_FINAL_LSH512_256					(ISC_F_LSH512_256 | ISC_F_LSH_FINAL)
#define ISC_F_INIT_LSH512_384					(ISC_F_LSH512_384 | ISC_F_LSH_INIT)
#define ISC_F_UPDATE_LSH512_384					(ISC_F_LSH512_384 | ISC_F_LSH_UPDATE)
#define ISC_F_FINAL_LSH512_384					(ISC_F_LSH512_384 | ISC_F_LSH_FINAL)
#define ISC_F_INIT_LSH512_512					(ISC_F_LSH512_512 | ISC_F_LSH_INIT)
#define ISC_F_UPDATE_LSH512_512					(ISC_F_LSH512_512 | ISC_F_LSH_UPDATE)
#define ISC_F_FINAL_LSH512_512					(ISC_F_LSH512_512 | ISC_F_LSH_FINAL)

#define ISC_L_PBKDF								0x26000000	/*!< */
#define ISC_F_PBKDF2							0x00010000	/*!< */

/*--------------------------------------------------------------*/
/* function list 												*/
/*--------------------------------------------------------------*/

/*--------------------------------------------------------------*/
/* reason list 													*/
/*--------------------------------------------------------------*/
#define ISC_ERR_ADD_BIGINT_FAIL					0x00000001	/*!< */
#define ISC_ERR_BIGINT_FROM_MONTGOMERY_FAIL		0x00000002	/*!< */
#define ISC_ERR_BIGINT_MEM_EXPAND_FAILURE		0x00000003	/*!< */
#define ISC_ERR_BIGINT_TO_MONTGOMERY_FAIL		0x00000004	/*!< */
#define ISC_ERR_BINARY_TO_BIGINT_FAIL			0x00000005  /*!< */
#define ISC_ERR_BUF_TOO_SMALL					0x00000006	/*!< */
#define ISC_ERR_CANNOT_CLOSE_STREAM				0x00000007	/*!< */
#define ISC_ERR_CANNOT_OPEN_STREAM				0x00000008	/*!< */
#define ISC_ERR_CIPHER_DECRYPT_FAILURE			0x00000009	/*!< */
#define ISC_ERR_CIPHER_ENCRYPT_FAILURE			0x0000000A	/*!< */
#define ISC_ERR_CMP_BIGINT_FAIL					0x0000000B  /*!< */
#define ISC_ERR_COMPARE_FAIL					0x0000000C  /*!< */
#define ISC_ERR_COPY_BIGINT_FAIL				0x0000000D	/*!< */
#define ISC_ERR_DECODING_FAILURE				0x0000000E	/*!< */
#define ISC_ERR_DIGEST_FAIL						0x0000000F	/*!< */
#define ISC_ERR_DIV_BIGINT_FAIL					0x00000010	/*!< */
#define ISC_ERR_DIVIDE_BY_ZERO					0x00000011	/*!< */
#define ISC_ERR_ENCODING_FAILURE				0x00000012  /*!< */
#define ISC_ERR_END_OF_STREAM					0x00000013	/*!< */
#define ISC_ERR_ENTROPY_FAIL					0x00000014  /*!< */
#define ISC_ERR_EUCLID_FAIL						0x00000015	/*!< */
#define ISC_ERR_EXPAND_BIGINT_WORD				0x00000016	/*!< */
#define ISC_ERR_FINAL_BLOCKCIPHER_FAIL			0x00000017	/*!< */
#define ISC_ERR_FINAL_DIGEST_FAIL				0x00000018	/*!< */
#define ISC_ERR_FINAL_FAILURE					0x00000019  /*!< */
#define ISC_ERR_GET_ADRESS_LOADLIBRARY			0x0000001A	/*!< */
#define ISC_ERR_GET_BIGINT_POOL_FAIL			0x0000001B  /*!< */
#define ISC_ERR_GET_RAND_DSA_BIGINT_FAIL		0x0000001C	/*!< */
#define ISC_ERR_GET_RAND_FAIL					0x0000001D  /*!< */
#define ISC_ERR_HASH_DF_FAIL					0x0000001E  /*!< */
#define ISC_ERR_HASH_GEN_FAIL					0x0000001F  /*!< */
#define ISC_ERR_INI_BIGINT_FAIL					0x00000020	/*!< */
#define ISC_ERR_INIT_BLOCKCIPHER_FAIL			0x00000021	/*!< */
#define ISC_ERR_INIT_DIGEST_FAIL				0x00000022	/*!< */
#define ISC_ERR_INIT_FAILURE					0x00000023	/*!< */
#define ISC_ERR_INIT_KEY_FAILURE				0x00000024	/*!< */
#define ISC_ERR_INIT_PRNG_FAIL					0x00000025	/*!< */
#define ISC_ERR_INPUT_BUF_TOO_BIG				0x00000026	/*!< */
#define ISC_ERR_INPUT_BUF_TOO_SHORT				0x00000027	/*!< */
#define ISC_ERR_INTERNAL						0x00000028	/*!< */
#define ISC_ERR_INVALID_ALGORITHM_ID			0x00000029	/*!< */
#define ISC_ERR_INVALID_ENCODE_MODE				0x0000002A  /*!< */
#define ISC_ERR_INVALID_INPUT					0x0000002B	/*!< */
#define ISC_ERR_INVALID_IV_LENGTH				0x0000002C	/*!< */
#define ISC_ERR_INVALID_KEY_LENGTH				0x0000002D	/*!< */
#define ISC_ERR_INVALID_KEY_PAIR				0x0000002E	/*!< */
#define ISC_ERR_INVALID_OPERATION_MASK			0x0000002F  /*!< */
#define ISC_ERR_INVALID_OUTPUT					0x00000030	/*!< */
#define ISC_ERR_INVALID_PADDING					0x00000031	/*!< */
#define ISC_ERR_INVALID_PASSWORD				0x00000032	/*!< */
#define ISC_ERR_INVALID_RSA_ENCODING			0x00000033	/*!< */
#define ISC_ERR_INVALID_UNIT					0x00000034	/*!< */
#define ISC_ERR_IO_EOF							0x00000035	/*!< */
#define ISC_ERR_IS_BIGINT_PRIME					0x00000036	/*!< */
#define ISC_ERR_IS_BIGINT_ZERO_FAIL				0x00000037  /*!< */
#define ISC_ERR_KEY_GEN_FAIL					0x00000038  /*!< */
#define ISC_ERR_LEFT_SHIFT_BIGINT_FAIL			0x00000039	/*!< */
#define ISC_ERR_MALLOC							0x0000003A	/*!< */
#define ISC_ERR_MEM_ALLOC						0x0000003B	/*!< */
#define ISC_ERR_MEMORY_ALLOC					0x0000003C	/*!< */
#define ISC_ERR_MESSAGE_TOO_LONG				0x0000003D  /*!< */
#define ISC_ERR_MOD_BIGINT_FAIL					0x0000003E	/*!< */
#define ISC_ERR_MOD_EXP_BIGINT_FAIL				0x0000003F  /*!< */
#define ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL		0x00000040	/*!< */
#define ISC_ERR_MOD_INVERSE_BIGINT_FAIL			0x00000041	/*!< */
#define ISC_ERR_MOD_MTP_BIGINT_FAIL				0x00000042	/*!< */
#define ISC_ERR_MOD_MUL_BIGINT_MONTGOMERY_FAIL	0x00000043	/*!< */
#define ISC_ERR_MTP_BIGINT_FAIL					0x00000044	/*!< */
#define ISC_ERR_NO_PRIVATE_VALUE				0x00000045	/*!< */
#define ISC_ERR_NO_PUBLIC_VALUE					0x00000046	/*!< */
#define ISC_ERR_NOT_FOUNDED						0x00000047	/*!< */
#define ISC_ERR_NOT_SUPPORTED					0x00000048	/*!< */
#define ISC_ERR_NULL_INPUT						0x00000049	/*!< */
#define ISC_ERR_NULL_IV_VALUE					0x0000004A	/*!< */
#define ISC_ERR_NULL_XKEY_VALUE					0x0000004B	/*!< */
#define ISC_ERR_OPERATE_FUNCTION            	0x0000004C  /*!< */
#define ISC_ERR_RAND_BIGINT_FAIL				0x0000004D	/*!< */
#define ISC_ERR_RANDOM_GEN_FAILURE				0x0000004E	/*!< */
#define ISC_ERR_READ_FROM_BINARY				0x0000004F  /*!< */
#define ISC_ERR_READ_FROM_FILE					0x00000050  /*!< */
#define ISC_ERR_RIGHT_SHIFT_BIGINT_FAIL			0x00000051	/*!< */
#define ISC_ERR_SET_BIGINT_FAIL					0x00000052	/*!< */
#define ISC_ERR_SIGN_DSA_FAIL					0x00000053	/*!< */
#define ISC_ERR_SIGN_FAILURE					0x00000054	/*!< */
#define ISC_ERR_SIGNATURE_TOO_LONG				0x00000055	/*!< */
#define ISC_ERR_SQR_BIGINT_FAIL					0x00000056	/*!< */
#define ISC_ERR_START_BIGINT_POOL_FAIL			0x00000057	/*!< */
#define ISC_ERR_SUB_BIGINT_FAIL					0x00000058  /*!< */
#define ISC_ERR_SUB_OPERATION_FAILURE			0x00000059	/*!< */
#define ISC_ERR_UPDATE_BLOCKCIPHER_FAIL			0x0000005A	/*!< */
#define ISC_ERR_UPDATE_DIGEST_FAIL				0x0000005B	/*!< */
#define ISC_ERR_UPDATE_FAILURE					0x0000005C	/*!< */
#define ISC_ERR_VERIFY_DSA_FAIL					0x0000005D	/*!< */
#define ISC_ERR_VERIFY_FAILURE					0x0000005E	/*!< */
#define ISC_ERR_WRITE_TO_BINARY					0x0000005F  /*!< */
#define ISC_ERR_WRITE_TO_FILE					0x00000060  /*!< */
#define ISC_ERR_MUTEX_LOCK_FAIL					0x00000061  /*!< */
#define ISC_ERR_MUTEX_UNLOCK_FAIL				0x00000062  /*!< */
#define ISC_ERR_INIT_DRBG_FAIL					0x00000063  /*!< */
#define ISC_ERR_INSTANTIATE_DRBG_FAIL			0x00000064  /*!< */
#define ISC_ERR_RESEED_DRBG_FAIL				0x00000065  /*!< */
#define ISC_ERR_GENERATE_DRBG_FAIL				0x00000066  /*!< */
#define ISC_ERR_CONDITION_TEST_FAIL				0x00000067  /*!< */
#define ISC_ERR_ADD_FP_ECC						0x00000068  /*!< */
#define ISC_ERR_MTP_FP_ECC						0x00000069  /*!< */
#define ISC_ERR_SIGN_ECDSA_FAIL					0x0000006A  /*!< */
#define ISC_ERR_VERIFY_ECDSA_FAIL				0x0000006B	/*!< */
#define ISC_ERR_NOT_SUPPORTED_CURVE_TYPE		0x0000006C	/*!< */
#define ISC_ERR_MOD_INVERSE_ECC_FAIL			0x0000006D	/*!< */
#define ISC_ERR_MTP_ECC_FBC_FAIL				0x0000006E	/*!< */
#define ISC_ERR_NEW_BIGINT_POOL_FAIL			0x0000006F	/*!< */
#define ISC_ERR_MOD_MTP_ECC_FAIL				0x00000070	/*!< */
#define ISC_ERR_GENERATE_PRIV_KEY				0x00000071	/*!< */
#define ISC_ERR_GENERATE_PUB_KEY				0x00000072	/*!< */
#define ISC_ERR_GENERATE_KEY_PAIR				0x00000073	/*!< */
#define ISC_ERR_MTP_ECC_MONT_FAIL				0x00000074	/*!< */
#define ISC_ERR_ADD_ECC_FAIL					0x00000075	/*!< */
#define ISC_ERR_SET_ECC_KEY_PARAMS_EX			0x00000076	/*!< */
#define ISC_ERR_CRITICAL_ERROR					0x00000077	/*!< */
#define ISC_ERR_NOT_SUPPORT_MODE				0x00000078  /*!> */

/* status proven */
#define ISC_ERR_NOT_PROVEN_ALGORITHM      		0x000000F0 /*!< 검증상태에서 비검증 알고리즘 사용 */
#define ISC_ERR_NOT_CHANGE_NONPROVEN      		0x000000F1 /*!< 초기화진행후에는 비검증모드로 변경 불가 */
#define ISC_ERR_NOT_PROVEN_FUNCTION				0x000000F2 /*!< 비검증용 함수 사용 불가 */


#ifdef __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* 원인메시지를 얻는 함수
*/
ISC_API ISC_STATUS ISC_Get_Reason_String(ISC_STATUS error, char *buf);

/*!
* \brief
* 에러메시지를 얻는 함수
*/
ISC_API ISC_STATUS ISC_Get_Error_String(ISC_STATUS error, char *buf);

/*!
* \brief
* 에러메시지를 출력해주는 함수
*/
ISC_API void ISC_Print_Error_String(int err);

#else

ISC_INTERNAL ISC_VOID_LOADLIB_CRYPTO( void, GetErrorCode, (int error), (error));
ISC_INTERNAL ISC_VOID_LOADLIB_CRYPTO( void, ISC_Get_Error_String, (ISC_STATUS error, char *buf), (error, buf));

#endif

#ifdef __cplusplus
}
#endif

#endif
