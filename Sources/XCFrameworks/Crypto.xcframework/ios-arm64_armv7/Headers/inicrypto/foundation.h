/*!
* \file foundation.h
* \brief crypto foundation
* crypto ��� �⺻ ����
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
#define ISC_NO_SHA		/* SHA ��� �˰��� */
#define ISC_NO_SHA1		/* + ISC_NO_DSA*/
#define ISC_NO_SHA256
#define ISC_NO_SHA512
#define ISC_NO_PRNG		/* + ����Ű ��� �˰��� + bigint_prime.c*/
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
crypto status ���� ����
  ISC_STATUS_POWER_ON	: ���缺�� (�����ΰ� ��)
  ISC_STATUS_SELF_TEST	: �����ΰ� ����
  ISC_STATUS_WAIT		: ���� ���(����)
  ISC_STATUS_INSERT		: Ű/���� ���� ����(����)
  ISC_STATUS_OPERATION	: ��ȣ �(����)
  ISC_STATUS_ERROR		: �ܼ��� ����(����)
  ISC_STATUS_WAIT_N		: ���� ���(�����)
  ISC_STATUS_INSERT_N	: Ű/���� ���� ����(�����)
  ISC_STATUS_OPERATION_N : ��ȣ �(�����)
  ISC_STATUS_ERROR_N	: �ܼ��� ����(�����)
  ISC_STATUS_CRITICAL	: �ɰ��� ����
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
* ��������� ��ȯ 
* \returns
* -# ISC_SUCCESS
* \returns
* -# ISC_F_CHANGE_NON_PROVENMODE :���� (�ʱ�ȭ ���Ŀ��� ��������� ����Ұ�)
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS ISC_Change_Non_Proven_Mode(void);

/*!
* \brief
* �׽�Ʈ���� ��ȯ 
* \returns
* -# ISC_SUCCESS
*/
ISC_API void ISC_Change_Test_Mode(void);

/*!
* \brief
* � ���(���� ���) ��ȯ
* \returns
* -# 0 : ����� ���
* -# 1 : ���� ���
*/
ISC_API uint8 ISC_Is_Proven();

/*!
* \brief
* ��Ʈ�� ����Ʈ���� �ڰ��׽�Ʈ�� �����ϴ� �Լ�
* \returns
* -# ISC_L_SELF_TEST^ISC_F_LIB_INTEGRITY_CHECK : ���Ἲ���� ����
* -# ISC_L_SELF_TEST^ISC_F_CONTEXT_CHECK : ���������� ����
* -# ISC_L_SELF_TEST^ISC_F_VERSION_CHECK : �������� ����
* -# ISC_L_SELF_TEST^ISC_F_DRBG_CHECK : �������� ����
* -# ISC_L_SELF_TEST^ISC_F_HMAC_CHECK :	HMAC ����
* -# ISC_L_SELF_TEST^ISC_F_DIGEST_CHECK	:	�ؽ��Լ� ����
* -# ISC_L_SELF_TEST^ISC_F_SYMMETIC_KEY_CHECK : ����ȣŰ��������
* -# ISC_L_SELF_TEST^ISC_F_SYMMETIC_ALGORITHM_CHECK : ����ȣ����
* -# ISC_L_SELF_TEST^ISC_F_ASYMMETIC_KEY_CHECK : ����Ű��ȣŰ��������
* -# ISC_L_SELF_TEST^ISC_F_RSAES_OAEP_CHECK : ����Ű��ȣ����
* -# ISC_L_SELF_TEST^ISC_F_RSASSA_CHECK : ���ڼ������
*/
ISC_API ISC_STATUS ISC_Crypto_Initialize();

/*!
* \brief
* ��ȣ����� ���� ���
* �ڰ��������(0:��, 1:��) : �ɰ��ѿ�������(0:����,1:����) : ���۸�����(0:�����,1:����)
* \returns
* -# 0 : �ڰ�����(0) �ɰ��ѿ�������(0) ���۸�����(0)
* -# 1 : �ڰ�����(0) �ɰ��ѿ�������(0) ���۸�����(1)
* -# 2 : �ڰ�����(0) �ɰ��ѿ�������(1) ���۸�����(0)
* -# 3 : �ڰ�����(0) �ɰ��ѿ�������(1) ���۸�����(1)
* -# 4 : �ڰ�����(1) �ɰ��ѿ�������(0) ���۸�����(0)
* -# 5 : �ڰ�����(1) �ɰ��ѿ�������(0) ���۸�����(1)
* -# 6 : �ڰ�����(1) �ɰ��ѿ�������(1) ���۸�����(0)
* -# 7 : �ڰ�����(1) �ɰ��ѿ�������(1) ���۸�����(1)
*/
ISC_API uint32 ISC_Get_Crypto_Status();

/*!
* \brief
* �ԷµǴ� �ڵ忡 ���� ��ȣ��� ������ ���¸� �����Ѵ�.
* param code
* �Է°� �ڵ�(���� or ����)
* param s
* �Էµ� �ڵ尪�� ������ ��� ��ȯ�Ǵ� ��ȣ����� ���°�
* param f
* �Էµ� �ڵ尪�� ������ ��� ��ȯ�Ǵ� ��ȣ����� ���°�
*/
ISC_INTERNAL void isc_Set_Crypto_Status(uint32 code, uint32 s, uint32 f);

/*!
* \brief
* ��ȣ����� ���� �����ΰ� ���� ��� ���
* \returns
* -# ISC_Crypto_Initialize()�� �����ڵ�
*/
ISC_API ISC_STATUS ISC_Get_Initialize_Error();

#ifdef ISC_TRACE_CALL_STACK
/*!
* \brief
* �Լ� �� ���� �α׿� ����� �Լ�
* \param strFunc
* �Լ���
* \param file
* ���� ���� ��
* \param line
* �Լ� ���� 
*/
ISC_INTERNAL void isc_IO_Trace_Call_Stack(const char* strFunc, const char* file, int line);

/*!
* \brief
* �α׸� ���� ���� ���
* \param strPath
* ���� ���
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

