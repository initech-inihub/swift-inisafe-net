/*!
* \file foundation.h
* \brief crypto foundation
* crypto 모듈 기본 정의
* \remarks
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_FOUNDATION_H__
#define HEADER_FOUNDATION_H__

#ifdef __cplusplus
extern "C" {
#endif

#define ISC_RSA_BLINDING
#define ISC_MONT_WORD

#if 0
#define ISC_NO_AES
#define ISC_NO_ARIA
#define ISC_NO_DES		/* + ISC_NO_DES_EDE + ISC_NO_MDC2*/
#define ISC_NO_DES_EDE
#define ISC_NO_SEED
#define ISC_NO_RC5
#define ISC_NO_RC2
#define ISC_NO_BF
#define ISC_NO_HAS160	/* + ISC_NO_KCDSA*/
#define ISC_NO_HMAC
#define ISC_NO_CBC_MAC
#define ISC_NO_DES_MAC
#define ISC_NO_MD5
#define ISC_NO_MDC2
#define ISC_NO_SHA		/* SHA 모든 알고리즘 */
#define ISC_NO_SHA1		/* + ISC_NO_DSA*/
#define ISC_NO_SHA256
#define ISC_NO_SHA512
#define ISC_NO_PRNG		/* + 공개키 모든 알고리즘 + bigint_prime.c*/
#define ISC_NO_RSA
#define ISC_NO_DSA
#define ISC_NO_KCDSA
#define ISC_NO_BIGINT
#define ISC_NO_DRBG
#endif

#ifdef ISC_NO_SHA
#define ISC_NO_SHA1
#define ISC_NO_SHA256
#define ISC_NO_SHA512
#define ISC_NO_DSA
#endif

#ifdef ISC_NO_HAS160
#define ISC_NO_KCDSA
#endif

#ifdef ISC_NO_DES
#define ISC_NO_DES_EDE
#define ISC_NO_MDC2
#define ISC_NO_DES_MAC
#endif

#if defined(ISC_NO_PRNG) || defined (ISC_NO_BIGINT) || defined(ISC_NO_DRBG)
#define ISC_NO_RSA
#ifndef ISC_NO_DSA
#define ISC_NO_DSA
#endif
#ifndef ISC_NO_KCDSA
#define ISC_NO_KCDSA
#endif
#endif

#if !defined(WIN32) && !defined(_WIN32) && !defined(_WIN32_WCE) && !defined(ISC_BADA)
#ifndef IOS
#include "config.h"
#else
#include "config_ios.h"
#endif
#endif

#define ISC_BYTES_IN_32L			4
#define ISC_BITS_IN_32L			32
#define ISC_HALF_BITS_IN_32L		16
#define ISC_MASK_4_BYTES			0xffffffffL
#define ISC_MASK_3_BYTES			0xffffff
#define ISC_MASK_2_BYTES			0xffff
#define ISC_MASK_1_BYTES			0xff
#ifdef WIN32
#	define ISC_LLONG_MASK		0xffffffffffffffffL
#else
#	define ISC_LLONG_MASK		0xffffffffffffffffLL
#endif

#define _MAX_INT		       	2147483647

#define ISC_LOW_PART_32(a)		((a)&ISC_MASK_2_BYTES)
#define ISC_HIGH_PART_32(a)		(((a)>>ISC_HALF_BITS_IN_32L)&ISC_MASK_2_BYTES)
#define ISC_HIGH_PARTS_32_UP(a)	(((a)<<ISC_HALF_BITS_IN_32L)&ISC_MASK_4_BYTES)

typedef struct isc_block_cipher_unit_st ISC_BLOCK_CIPHER_UNIT;
typedef struct isc_block_cipher_mac_unit_st ISC_BLOCK_CIPHER_MAC_UNIT;
typedef struct isc_digest_unit_st ISC_DIGEST_UNIT;
typedef struct isc_hmac_unit_st ISC_HMAC_UNIT;
typedef struct isc_cbc_mac_st ISC_CBC_MAC_UNIT;
typedef struct isc_big_integer_st ISC_BIGINT;
typedef struct isc_big_integer_mont_st ISC_BIGINT_MONT;
typedef struct isc_big_integer_pool_item_st ISC_BIGINT_POOL_ITEM;
typedef struct isc_big_integer_pool_st ISC_BIGINT_POOL;
typedef struct isc_rsa_st ISC_RSA_UNIT;
typedef struct isc_dsa_st ISC_DSA_UNIT;
typedef struct isc_kcdsa_st ISC_KCDSA_UNIT;
typedef struct isc_prng_unit_st ISC_PRNG_UNIT;
typedef struct key_unit_st ISC_KEY_UNIT;
typedef struct isc_mempool_st ISC_MEM_POOL;
typedef struct isc_entropy_st ISC_ENTROPY_UNIT;
typedef struct isc_drbg_st ISC_DRBG_UNIT;
typedef struct isc_advanced_block_cipher_unit_st ISC_ADVANCED_BLOCK_CIPHER_UNIT;
typedef struct isc_dh_st ISC_DH_UNIT;
typedef struct isc_ecc_key_st ISC_ECC_KEY_UNIT;
typedef struct isc_ecdsa_st ISC_ECDSA_UNIT;
typedef struct isc_eckcdsa_st ISC_ECKCDSA_UNIT;
typedef struct isc_ecdh_st ISC_ECDH_UNIT;

#define ISC_UNIT_MEM_SAFE 0xFFFFFFFF

#if defined(_WIN32) && defined(_USRDLL)
#	if !defined(ISC_DLL) && !defined(ISC_STATIC)
#		define ISC_DLL
#	endif
#endif

#if defined(_WIN32) && defined(ISC_DLL)
#	if defined(ISC_EXPORTS)
#		define ISC_API __declspec(dllexport)
#		define ISC_INTERNAL
#	else
#		define ISC_API __declspec(dllimport)	
#	endif
#elif (defined(_WIN32) && defined(ISC_BADA)) && !defined(_ISC_STATIC)
#	if defined(ISC_EXPORTS)
#		define ISC_API __declspec(dllexport)
#	else
#		define ISC_API __declspec(dllimport)
#	endif
#else
#	if defined(__GNUC__) && __GNUC__ >= 4 && !(MACOS)
#		define ISC_API __attribute__((visibility("default")))
#       define ISC_INTERNAL __attribute__((visibility("hidden")))
#	else
#       define ISC_INTERNAL
#		define ISC_API 
#	endif
#endif

#if !defined(ISC_API)
#	define ISC_API 
#endif

#define ISC_INLINE __inline

#define ISC_ALIGN(size, boundary) \
    (((size) + ((boundary) - 1)) & ~((boundary) - 1))

#define ISC_ALIGN_DEFAULT(size) ISC_ALIGN(size, 8)

#if defined(ISC_ALIGNED_)
/* do nothing */
#elif defined(_MSC_VER)
#define ISC_ALIGNED_(x) __declspec(align(x))
#elif defined(__GNUC__)
#define ISC_ALIGNED_(x) __attribute__ ((aligned(x)))
#elif defined(__has_attribute)
#if __has_attribute(aligned)
#define ISC_ALIGNED_(x) __attribute__ ((aligned(x)))
#endif
#endif


#include "platform.h"
#if defined(_WIN32)
#include "platform_win.h"
#elif defined(__VMS)
#include "platform_vms.h"
#elif defined(ISC_OS_FAMILY_UNIX)
#include "platform_posix.h"
#endif

#ifdef ISC_WIN_LOADLIBRARY_CRYPTO

#if !defined(_WIN32) || defined(_WIN32_WCE) || defined(ISC_BADA)
#error Can not support "Loadlibrary"
#endif

#include <windows.h>

HMODULE g_inicryptoLibrary;

#define ISC_RET_LOADLIB_CRYPTO(retType, functionName, fullTypeParam, callParam, retFail) \
 	static retType functionName##fullTypeParam { \
 	typedef retType(*p##functionName)##fullTypeParam; \
 	static p##functionName f##functionName = NULL; \
	f##functionName = (f##functionName == NULL) ? \
	(p##functionName)GetProcAddress((HMODULE)g_inicryptoLibrary, #functionName) : f##functionName; \
  	return (f##functionName == NULL) ? retFail : f##functionName##callParam; \
}

#define ISC_VOID_LOADLIB_CRYPTO(retType, functionName, fullTypeParam, callParam) \
	static retType functionName##fullTypeParam { \
	typedef retType(*p##functionName)##fullTypeParam; \
	static p##functionName f##functionName = NULL; \
	f##functionName = (f##functionName == NULL) ? \
	(p##functionName)GetProcAddress((HMODULE)g_inicryptoLibrary, #functionName) : f##functionName; \
	f##functionName##callParam; \
}
#endif

#ifdef _WIN32_WCE
#define _MAX_DRIVE  3   /* max. length of drive component */
#define _MAX_DIR    256 /* max. length of path component */
#define _MAX_FNAME  256 /* max. length of file name component */
#define _MAX_EXT    256 /* max. length of extension component */
#endif

#include "types.h"
#include "mem.h"
#include "error.h"

/* 
crypto status 상태 정의
  ISC_STATUS_POWER_ON	: 적재성공 (전원인가 전)
  ISC_STATUS_SELF_TEST	: 전원인가 성공
  ISC_STATUS_WAIT		: 동작 모드(검증)
  ISC_STATUS_INSERT		: 키/변수 주입 상태(검증)
  ISC_STATUS_OPERATION	: 암호 운영(검증)
  ISC_STATUS_ERROR		: 단순한 오류(검증)
  ISC_STATUS_WAIT_N		: 동작 모드(비검증)
  ISC_STATUS_INSERT_N	: 키/변수 주입 상태(비검증)
  ISC_STATUS_OPERATION_N : 암호 운영(비검증)
  ISC_STATUS_ERROR_N	: 단순한 오류(비검증)
  ISC_STATUS_CRITICAL	: 심각한 오류
*/
#define ISC_STATUS_POWER_ON			0
#define ISC_STATUS_SELF_TEST		1
#define ISC_STATUS_WAIT				2
#define	ISC_STATUS_INSERT			3
#define ISC_STATUS_OPERATION		4
#define ISC_STATUS_ERROR			5
#define ISC_STATUS_WAIT_N			258
#define	ISC_STATUS_INSERT_N			259
#define ISC_STATUS_OPERATION_N		260
#define ISC_STATUS_ERROR_N			261
#define ISC_STATUS_CRITICAL			512

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* 비검증모드로 전환 
* \returns
* -# ISC_SUCCESS
* \returns
* -# ISC_F_CHANGE_NON_PROVENMODE :실패 (초기화 이후에는 비검증모드로 변경불가)
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS ISC_Change_Non_Proven_Mode(void);

/*!
* \brief
* 테스트모드로 전환 
* \returns
* -# ISC_SUCCESS
*/
ISC_API void ISC_Change_Test_Mode(void);

/*!
* \brief
* 운영 모드(검증 모드) 반환
* \returns
* -# 0 : 비검증 모드
* -# 1 : 검증 모드
*/
ISC_API uint8 ISC_Is_Proven();

/*!
* \brief
* 엔트리 포인트에서 자가테스트를 수행하는 함수
* \returns
* -# ISC_L_SELF_TEST^ISC_F_LIB_INTEGRITY_CHECK : 무결성점검 실패
* -# ISC_L_SELF_TEST^ISC_F_CONTEXT_CHECK : 콘텐츠생성 실패
* -# ISC_L_SELF_TEST^ISC_F_VERSION_CHECK : 버전점검 실패
* -# ISC_L_SELF_TEST^ISC_F_DRBG_CHECK : 난수생성 실패
* -# ISC_L_SELF_TEST^ISC_F_HMAC_CHECK :	HMAC 실패
* -# ISC_L_SELF_TEST^ISC_F_DIGEST_CHECK	:	해쉬함수 실패
* -# ISC_L_SELF_TEST^ISC_F_SYMMETIC_KEY_CHECK : 블럭암호키생성실패
* -# ISC_L_SELF_TEST^ISC_F_SYMMETIC_ALGORITHM_CHECK : 블럭암호실패
* -# ISC_L_SELF_TEST^ISC_F_ASYMMETIC_KEY_CHECK : 공개키암호키생성실패
* -# ISC_L_SELF_TEST^ISC_F_RSAES_OAEP_CHECK : 공개키암호실패
* -# ISC_L_SELF_TEST^ISC_F_RSASSA_CHECK : 전자서명실패
*/
ISC_API ISC_STATUS ISC_Crypto_Initialize();

/*!
* \brief
* 암호모듈의 상태 출력
* 자가시험상태(0:전, 1:후) : 심각한오류상태(0:정상,1:오류) : 동작모드상태(0:비검증,1:검증)
* \returns
* -# 0 : 자가시험(0) 심각한오류상태(0) 동작모드상태(0)
* -# 1 : 자가시험(0) 심각한오류상태(0) 동작모드상태(1)
* -# 2 : 자가시험(0) 심각한오류상태(1) 동작모드상태(0)
* -# 3 : 자가시험(0) 심각한오류상태(1) 동작모드상태(1)
* -# 4 : 자가시험(1) 심각한오류상태(0) 동작모드상태(0)
* -# 5 : 자가시험(1) 심각한오류상태(0) 동작모드상태(1)
* -# 6 : 자가시험(1) 심각한오류상태(1) 동작모드상태(0)
* -# 7 : 자가시험(1) 심각한오류상태(1) 동작모드상태(1)
*/
ISC_API uint32 ISC_Get_Crypto_Status();

/*!
* \brief
* 입력되는 코드에 따라 암호모듈 상태의 상태를 설정한다.
* param code
* 입력값 코드(에러 or 성공)
* param s
* 입력된 코드값이 성공일 경우 변환되는 암호모듈의 상태값
* param f
* 입력된 코드값이 실패일 경우 변환되는 암호모듈의 상태값
*/
ISC_INTERNAL void isc_Set_Crypto_Status(uint32 code, uint32 s, uint32 f);

/*!
* \brief
* 암호모듈의 최초 전원인가 시험 결과 출력
* \returns
* -# ISC_Crypto_Initialize()의 에러코드
*/
ISC_API ISC_STATUS ISC_Get_Initialize_Error();

#ifdef ISC_TRACE_CALL_STACK
/*!
* \brief
* 함수 콜 명을 로그에 남기는 함수
* \param strFunc
* 함수명
* \param file
* 현재 파일 명
* \param line
* 함수 라인 
*/
ISC_INTERNAL void isc_IO_Trace_Call_Stack(const char* strFunc, const char* file, int line);

/*!
* \brief
* 로그를 남길 파일 경로
* \param strPath
* 파일 경로
*/
ISC_INTERNAL void isc_IO_Set_Trace_Path(const char* strPath);

#define CRYPTO_TRACE_CALL_STATCK  isc_IO_Trace_Call_Stack(__FUNCTION__, __FILE__, __LINE__);
#else
#define CRYPTO_TRACE_CALL_STATCK
#endif

#else

ISC_VOID_LOADLIB_CRYPTO(ISC_STATUS, ISC_Change_Non_Proven_Mode, (void), () );
ISC_INTERNAL ISC_VOID_LOADLIB_CRYPTO(void, ISC_Change_Test_Mode, (void), () );
ISC_RET_LOADLIB_CRYPTO(uint8, ISC_Is_Proven, (void), (), -1 );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Crypto_Initialize, (void), (), 0 );

#endif

#ifdef __cplusplus
}
#endif

#endif /* HEADER_FOUNDATION_H__ */

