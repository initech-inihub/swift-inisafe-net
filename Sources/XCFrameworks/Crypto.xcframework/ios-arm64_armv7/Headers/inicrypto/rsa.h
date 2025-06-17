/*!
* \file rsa.h
* \brief rsa 헤더파일
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_RSA_H
#define HEADER_RSA_H

#include "biginteger.h"
#include "digest.h"
#include "foundation.h"

#ifdef ISC_NO_RSA
#error ISC_RSA is disabled.
#endif

/* Flag Definition
 |---------------------------------------------------------------|
 |-------------Algorithm Identification-----------|-------|-------|
 | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits |
 |---------------------------------------------------------------|
---------------------------------------------------------------------------------
ISC_RSA Alias				0x20000000 ------------------------------------------------ */
#define ISC_RSA				0x20000000   /*!< ISC_RSA 알고리즘 ID */

/*SHA1withRSA <-- ISC_RSA | ISC_SHA1 (0x25000100) */

/*Pram type */
#define ISC_RSA_N_VALUE_HAVE         0x01   /*!< modulas Value 가 저장됨*/
#define ISC_RSA_E_VALUE_HAVE		 0x02   /*!< e Value 가 저장됨*/
#define ISC_RSA_PUBLIC_VALUE_HAVE	 0x03   /*!< e and n Value 가 저장됨*/
#define ISC_RSA_D_VALUE_HAVE		 0x04   /*!< d Value 가 저장됨*/
#define ISC_RSA_PRIVATE_VALUE_HAVE	 0x05	/*!< d and n Value 가 저장됨*/
#define ISC_RSA_CRT_VALUE_HAVE       0x08   /*!< CRT Value 가 저장됨*/
#define ISC_RSA_FULL_VALUE_HAVE		 0x1F   /*!< ALL Value 가 저장됨 Value*/

/* encode Identification 

|	1byte	|	1byte	|	1byte	|	1byte	|
|-----------------------------------------------|
|	 MGF 	|	SALT	|	MGF		|  PADDING	|
|-----------------------------------------------|

*/

#define ISC_RSA_PADDING_MASK			0x000000FF
#define ISC_RSA_NO_ENCODE				0x00	/*!< ISC_RSA No Encode*/
#define ISC_RSASSA_PKCS1_v1_5_ENCODE	0x01	/*!< ISC_RSA 서명 PKCS1 v1.5 ENCODE*/
#define ISC_RSASSA_PSS_ENCODE			0x02	/*!< ISC_RSA 서명 PSS ENCODE*/

#define ISC_RSAES_OAEP_v2_0_ENCODE		0x08	/*!< ISC_RSA 암호화 OAEP v2.0 ENCODE*/
#define ISC_RSAES_OAEP_v2_1_ENCODE		0x10	/*!< ISC_RSA 암호화 OAEP v2.1 ENCODE*/
#define ISC_RSAES_PKCS1_v1_5_ENCODE		0x20	/*!< ISC_RSA 암호화 PKCS1 v1.5 ENCODE*/

#define ISC_RSA_MGF_MASK				0xFF00FF00
#define ISC_RSA_MGF_SHA1				ISC_SHA1	/*!< MGF ISC_SHA1 알고리즘*/
#define ISC_RSA_MGF_SHA224				ISC_SHA224	/*!< MGF ISC_SHA224 알고리즘*/
#define ISC_RSA_MGF_SHA256				ISC_SHA256	/*!< MGF ISC_SHA256 알고리즘*/
#define ISC_RSA_MGF_SHA384				ISC_SHA384	/*!< MGF ISC_SHA384 알고리즘*/
#define ISC_RSA_MGF_SHA512				ISC_SHA512	/*!< MGF ISC_SHA512 알고리즘*/
#define ISC_RSA_MGF_MD5					ISC_MD5	/*!< MGF ISC_MD5 알고리즘*/

#define ISC_RSASSA_SALT_MASK			0x00FF0000
#define ISC_RSASSA_PSS_SALT_16			0x100000 /*!< PSS Salt 길이 16*/
#define ISC_RSASSA_PSS_SALT_20			0x140000 /*!< PSS Salt 길이 20*/
#define ISC_RSASSA_PSS_SALT_28			0x1C0000 /*!< PSS Salt 길이 28*/
#define ISC_RSASSA_PSS_SALT_32			0x200000 /*!< PSS Salt 길이 32*/
#define ISC_RSASSA_PSS_SALT_48			0x300000 /*!< PSS Salt 길이 48*/
#define ISC_RSASSA_PSS_SALT_64			0x400000 /*!< PSS Salt 길이 64*/

#define ISC_RSAES_PKCS1_v1_5_KEYPAIR	1	/*!< ISC_RSA 암호화 PKCS1 v1.5 키생성*/
#define ISC_RSAES_PKCS1_v2_0_KEYPAIR	2	/*!< ISC_RSA 암호화 PKCS1 v2.0 키생성*/

#define ISC_RSA_SIGN					1	/*!< ISC_RSA 서명*/
#define ISC_RSA_VERIFY					0	/*!< ISC_RSA 검증*/
#define ISC_RSA_ENCRYPTION				0	/*!< ISC_RSA 공개키 암호화*/
#define ISC_RSA_DECRYPTION				1	/*!< ISC_RSA 개인키 복호화*/

/* 특별한 경우에 아래것을 사용하세요. */
#define ISC_RSA_PUBLIC_ENCRYPTION		0  /*!< ISC_RSA 공개키 암호화*/
#define ISC_RSA_PRIVATE_ENCRYPTION		1  /*!< ISC_RSA 개인키 암호화*/

#define ISC_RSA_PUBLIC_DECRYPTION		0	/*!< ISC_RSA 공개키 복호화*/
#define ISC_RSA_PRIVATE_DECRYPTION		1  /*!< ISC_RSA 개인키 복호화*/

/*검증과 비검증 모드 설정하는 부분 */
#define ISC_RSAES_PROVEN_MODE			1    /*!<  0: 비검증 모드, 1: 검증모드 */
#define ISC_RSASSA_PROVEN_MODE			1    /*!<  0: 비검증 모드, 1: 검증모드 */

/* test rsaes oaep encryption */
/*
#define RSAES_VECTORTEST
*/

/*!
* \brief
* ISC_RSA 알고리즘을 위한 구조체
*/
struct isc_rsa_st
{
	int encode; 	/*!< 인코딩 방법*/
	int param_type;	 	/*!< 저장된 Parameter의 형태*/
	ISC_DIGEST_UNIT *d_unit;	/*!< ISC_DIGEST_UNIT*/
	ISC_BIGINT *e;	/*!< 공개키 지수 e*/
	ISC_BIGINT *d;	/*!< 비밀키 지수 e*/
	ISC_BIGINT *n;	/*!< Modulas n*/
	ISC_BIGINT *p;	/*!< 소수 p*/
	ISC_BIGINT *dp; /*!< CRT 값*/
	ISC_BIGINT *q;  /*!< 소수 q*/
	ISC_BIGINT *dq;  /*!< CRT 값*/
	ISC_BIGINT *qInv;  /*!< CRT 값*/
	int is_private;  /*!< Public : 0 , Private : 1*/
	ISC_BIGINT_POOL *pool; /*!< 연산 효율을 위한 풀 */
	int use_crt;	/*<! CRT 연산을 사용할지 여부 */
	int pss_salt_length; /*<! PSS 에서 사용할 salt 길이, 0 설정 시 해쉬 알고리즘의 길이를 사용 */
#ifdef ISC_RSA_BLINDING
	ISC_BIGINT *r_e;  /*!< r^(e)*/
	ISC_BIGINT *r_Inv;  /*!< r^(-1) mod n*/
#endif
};


#ifdef  __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_RSA_UNIT 구조체의 메모리 할당
* \returns
* ISC_RSA_UNIT 구조체
*/
ISC_API ISC_RSA_UNIT *ISC_New_RSA(void);

/*!
* \brief
* ISC_RSA_UNIT 메모리 해제 함수
* \param unit
* 메모리 해제할 ISC_RSA_UNIT
*/
ISC_API void ISC_Free_RSA(ISC_RSA_UNIT *unit);

/*!
* \brief
* ISC_RSA_UNIT 메모리 초기화 함수
* \param unit
* 초기화 할 ISC_RSA_UNIT
*/
ISC_API void ISC_Clean_RSA(ISC_RSA_UNIT *unit);

/*!
* \brief
* ISC_RSA_UNIT 구조체를 복사함
* \returns
* ISC_RSA_UNIT 구조체
*/
ISC_API ISC_RSA_UNIT *ISC_Dup_RSA(ISC_RSA_UNIT *src);

/*!
* \brief
* ISC_RSA Parameter 입력
* \param rsa
* Parameter가 입력될 ISC_RSA_UNIT
* \param n
* modulas n.
* \param e
* 공개키 Exponent
* \param d
* 비밀키 Exponent
* \param p
* prime p.
* \param q
* prime q.
* \param dp
* CRT Value dp.
* \param dq
* CRT Value dq.
* \param inv_q
* CRT Value inv_q.
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# LOCATION^ISC_F_SET_RSA_PRAMS^ISC_ERR_INVALID_INPUT : e와 n이 NULL일 경우
* -# LOCATION^ISC_F_SET_RSA_PRAMS^ISC_ERR_SUB_OPERATION_FAILURE : 내부 함수 오류
*/
ISC_API ISC_STATUS ISC_Set_RSA_Params(ISC_RSA_UNIT *rsa,
				   const ISC_BIGINT *n,
				   const ISC_BIGINT *e,
				   const ISC_BIGINT *d,
				   const ISC_BIGINT *p,
				   const ISC_BIGINT *q,
				   const ISC_BIGINT *dp,
				   const ISC_BIGINT *dq,
				   const ISC_BIGINT *inv_q);

/*!
* \brief
* ISC_RSA Public Parameter 만을 입력
* \param rsa
* Parameter가 입력될 ISC_RSA_UNIT
* \param n
* modulas n.
* \param e
* 공개키 Exponent
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# LOCATION^ISC_F_SET_RSA_PUBLIC_PRAMS^ISC_ERR_INVALID_INPUT : e와 n이 NULL일 경우
*/
ISC_API ISC_STATUS ISC_Set_RSA_Public_Params(ISC_RSA_UNIT *rsa,  const ISC_BIGINT* n, const ISC_BIGINT* e);

/*!
* \brief
* RSA 전자서명 알고리즘 초기화
* \param rsa
* 초기화 될 ISC_RSA_UNIT
* \param digest_alg
* RSA와 함께 사용되는 DIGEST Algorithm ID (digest.h 참조)
* \param encode
* 인코딩 타입 | MGF 해시 알고리즘 | SALT 길이 (ISC_RSASSA_PSS_ENCODE | ISC_RSA_MGF_SHA256 | ISC_RSASSA_PSS_SALT_32)
* \param sign
* (ISC_RSA_SIGN)1 : 서명, (ISC_RSA_VERIFY)0 : 검증
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_RSA^ISC_F_INIT_RSASSA^ISC_ERR_INVALID_RSA_ENCODING : 지원되지 않는 인코딩 타입
* -# ISC_L_RSA^ISC_F_INIT_RSASSA^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에서 비검증 알고리즘 사용 
* -# ISC_L_RSA^ISC_F_INIT_RSASSA^ISC_ERR_NOT_SUPPORTED : 지원되지 않는 키 길이 입력
* -# ISC_L_RSA^ISC_F_INIT_RSASSA^ISC_ERR_INIT_FAILURE : RSASSA INIT 실패
* -# ISC_L_RSA^ISC_F_INIT_RSASSA^ISC_ERR_SUB_OPERATION_FAILURE : ISC_DIGEST Algorithm 초기화 실패
*/
ISC_API ISC_STATUS ISC_Init_RSASSA(ISC_RSA_UNIT *rsa, int digest_alg, int encode, int sign);

/*!
* \brief
* RSA 전자서명 메시지 입력(Update) 함수
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param data
* 입력될 데이터(여러번 입력 가능)
* \param length
* 데이터의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_RSASSA^ISC_ERR_NULL_INPUT : 입력된 ISC_RSA_UNIT이 NULL일 경우
* -# ISC_L_RSA^ISC_F_UPDATE_RSASSA^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(DIGEST) 실패
*/
ISC_API ISC_STATUS ISC_Update_RSASSA(ISC_RSA_UNIT *rsa, const uint8 *data, int length);

/*!
* \brief
* RSA 전자서명의 서명값 생성 / 검증 함수
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param signature
* 서명 데이터
* \param sLen
* 서명값의 길이의 포인터, 서명 생성의 경우 생성된 서명값의 길이가 반환
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_FINAL_RSASSA^ISC_ERR_NULL_INPUT : 입력된 ISC_RSA_UNIT이 NULL일 경우
* -# ISC_L_RSA^ISC_F_FINAL_RSASSA^ISC_ERR_NOT_SUPPORTED : 지원하지 않는 알고리즘 키 길이 입력
* -# ISC_L_RSA^ISC_F_FINAL_RSASSA^ISC_ERR_NO_PRIVATE_VALUE : 비밀키가 없이 서명값 생성 시도
* -# ISC_L_RSA^ISC_F_FINAL_RSASSA^ISC_ERR_NO_PUBLIC_VALUE : 공개키가 없이 서명값 생성 시도
* -# ISC_Sign_RSASSA()의 에러코드
* -# ISC_Verify_RSASSA()의 에러코드
*/
ISC_API ISC_STATUS ISC_Final_RSASSA(ISC_RSA_UNIT *rsa, uint8 *signature, int *sLen);

/*!
* \brief
* RSA 전자서명의 서명값 생성
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param signature
* 서명값
* \param sLen
* 서명값의 길이의 포인터, 서명 생성의 경우 생성된 서명값의 길이가 반환
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_MALLOC : 내부 버퍼의 메모리 할당 실패
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산중 실패
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에서 비검증 대상 알고리즘 사용
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_NOT_SUPPORTED : 지원되지 않는 인코딩 타입 입력
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_MESSAGE_TOO_LONG : 메시지가 Modulas보다 큼
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_ENCODING_FAILURE : 인코딩 실패
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY to BIGINT 전환 실패
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_INVALID_ENCODE_MODE : 잘못된 인코딩 타입 입력
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_MESSAGE_TOO_LONG : 메시지가 n보다 큼
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_INVALID_KEY_PAIR : 키쌍 일치 실패
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_SIGN_FAILURE : 서명 실패
*/
ISC_API ISC_STATUS ISC_Sign_RSASSA(ISC_RSA_UNIT *rsa, uint8 *signature, int *sLen);

/*!
* \brief
* RSA 전자서명의 서명값 검증
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param signature
* 서명값
* \param sLen
* 서명값의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_MALLOC : 내부 버퍼의 메모리 할당 실패
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(DIGEST/BIGINT) 실패
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_SIGNATURE_TOO_LONG : 서명값이 Modulas보다 큼
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에서 비검증 알고리즘 사용
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY to BIGINT 전환 실패
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_DECODING_FAILURE : 서명값 디코딩 실패
*/
ISC_API ISC_STATUS ISC_Verify_RSASSA(ISC_RSA_UNIT *rsa, uint8 *signature, int sLen);

/*!
* \brief
* 지정된 공개키 e에 기반한 RSA Parameters 생성 함수 (해시 알고리즘 입력 받음)
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param e_value
* ISC_RSA 공개키 Exponent
* \param bits
* ISC_RSA Bits Length
* \param version
* PKCS#1 v1.5 : 1
* PKCS#1 v2.0 : 2
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# LOCATION^ISC_F_GENERATE_RSA_PARAMS_EX^ISC_ERR_INVALID_INPUT : 입력 파라미터 오류
* -# LOCATION^ISC_F_GENERATE_RSA_PARAMS_EX^ISC_ERR_NOT_SUPPORTED: 지원하지 않는 알고리즘
* -# LOCATION^ISC_F_GENERATE_RSA_PARAMS_EX^ISC_ERR_GET_BIGINT_POOL_FAIL: BIGINT POOL 생성 실패
* -# LOCATION^ISC_F_GENERATE_RSA_PARAMS_EX^ISC_ERR_MALLOC: 메모리 할당 실패
* -# LOCATION^ISC_F_GENERATE_RSA_PARAMS_EX^ISC_ERR_IS_BIGINT_PRIME: 소수 판별 실패
* -# LOCATION^ISC_F_GENERATE_RSA_PARAMS_EX^ISC_ERR_KEY_GEN_FAIL: 키 유효성 검증 실패
*/
ISC_API ISC_STATUS ISC_Generate_RSA_Params_Ex(ISC_RSA_UNIT *rsa, ISC_BIGINT *e_value, int bits, int version);

/*!
* \brief
* 지정된 공개키 e에 기반한 ISC_RSA Parameters 생성 함수
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param e_value
* ISC_RSA 공개키 Exponent
* \param bits
* ISC_RSA Bits Length
* \param version
* PKCS#1 v1.5 : 1
* PKCS#1 v2.0 : 2
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_RSA^ISC_F_GENERATE_RSA_PARAMS^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
* -# ISC_L_RSA^ISC_F_GENERATE_RSA_PARAMS^ISC_ERR_GET_BIGINT_POOL_FAIL : BIGINT POOL 생성 실패
* -# ISC_L_RSA^ISC_F_GENERATE_RSA_PARAMS^ISC_ERR_MALLOC : 메모리 할당 실패
* -# ISC_L_RSA^ISC_F_GENERATE_RSA_PARAMS^ISC_ERR_IS_BIGINT_PRIME : 소수 판별 실패
* -# ISC_L_RSA^ISC_F_GENERATE_RSA_PARAMS^ISC_ERR_KEY_GEN_FAIL : 키 유효성 검증 실패
*/
ISC_API ISC_STATUS ISC_Generate_RSA_Params(ISC_RSA_UNIT *rsa, ISC_BIGINT *e_value, int bits, int version);


/*!
* \brief
* RSA 암호화 알고리즘 초기화
* \param rsa
* 초기화 될 ISC_RSA_UNIT
* \param encode
* 인코딩 타입 | MGF 해시 알고리즘 (ISC_RSAES_OAEP_v2_1_ENCODE | ISC_RSA_MGF_SHA256)
* \param encryption
* (ISC_RSA_PRIVATE_DECRYPTION)1 : 복호화, (ISC_RSA_ENCRYPTION )0 : 암호화
* \param digest_algo
* 패딩시 사용할 해쉬 알고리즘 입력(default(ISC_SHA1)로 사용하고자 할때는 "0"입력)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_RSA^ISC_F_INIT_RSAES^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_RSA^ISC_F_INIT_RSAES^ISC_ERR_INVALID_RSA_ENCODING : 잘못된 인코딩 입력
* -# ISC_L_RSA^ISC_F_INIT_RSAES^ISC_ERR_NOT_SUPPORTED : 지원하지 않는 키 길이 입력
* -# ISC_L_RSA^ISC_F_INIT_RSAES^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에서 비검증 알고리즘 사용
* -# ISC_L_RSA^ISC_F_INIT_RSAES^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(DIGEST) 실패
*/
ISC_API ISC_STATUS ISC_Init_RSAES(ISC_RSA_UNIT *rsa, int encode, int encryption, int digest_algo);

/*!
* \brief
* RSA 암호화 함수
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param out
* 출력 버퍼
* \param outLen
* 출력 버퍼의 길이 포인터, 함수 종료후에 출력 버퍼에 저장된 길이가 입력됨
* \param in
* 입력
* \param inLen
* 입력 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_NO_PRIVATE_VALUE : 개인키 설정값 없음
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_NO_PUBLIC_VALUE : 공개키 설정값 없음
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_NOT_SUPPORTED : 지원하지 않는 키 길이 사용
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_MALLOC : 동적 메모리 할당 실패
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(BIGINT) 실패
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에서 비검증 알고리즘 사용
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_INVALID_RSA_ENCODING : 잘못된 인코딩 입력
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_ENCODING_FAILURE : 인코딩 실패
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_MESSAGE_TOO_LONG : 입력값(인코딩 된 입력값)이 modulas보다 큼
*/
ISC_API ISC_STATUS ISC_Encrypt_RSAES(ISC_RSA_UNIT *rsa, uint8 *out, int *outLen, const uint8 *in, int inLen);

/*!
* \brief
* RSA 복호화 함수
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param out
* 출력 버퍼
* \param outLen
* 출력 버퍼의 길이, 함수 종료후에 출력 버퍼에 저장된 길이가 입력됨
* \param in
* 입력
* \param inLen
* 입력 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_NO_PRIVATE_VALUE : 개인키 설정값 없음
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_NO_PUBLIC_VALUE : 공개키 설정값 없음
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_NOT_SUPPORTED : 지원하지 않는 키 길이 입력
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_MALLOC : 동젝 메모리 할당 실패
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(BIGINT) 실패
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_MESSAGE_TOO_LONG : 입력값(디코딩 된 입력값)이 modulas보다 큼
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_INVALID_KEY_PAIR : 키쌍 일치 실패
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에서 비검증 알고리즘 사용
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_DECODING_FAILURE : 디코딩 실패
*/
ISC_API ISC_STATUS ISC_Decrypt_RSAES(ISC_RSA_UNIT *rsa, uint8 *out, int *outLen, const uint8 *in, int inLen);

/*!
* \brief
* RSA의 Modulas 길이를 반환
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \returns
* -# Modulas 길이
* -# ISC_INVALID_SIZE : RSA 키 길이 가져오기 실패
*/
ISC_API int ISC_Get_RSA_Length(ISC_RSA_UNIT* rsa);

/*!
* \brief
* EMSA PKCS1 v1.5 인코딩
* \param EM
* EncodedMessage의 버퍼 포인터
* \param emLen
* EncodedMessage 길이
* \param mHash
* 해시값
* \param mHashLen
* 해시 길이
* \param digest_algo
* ISC_DIGEST 알고리즘 ID
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_API ISC_STATUS ISC_Add_EMSA_PKCS1_v1_5_Encode(uint8 *EM, int emLen, const uint8 *mHash, int mHashLen, int digest_algo);

/*!
* \brief
* EMSA PKCS1 v1.5 인코딩 체크
* \param EM
* EncodedMessage의 버퍼 포인터
* \param emLen
* EncodedMessage 길이
* \param nLen
* Modulas 길이
* \param mHash
* 해시값
* \param mHashLen
* 해시 길이
* \param digest_algo
* ISC_DIGEST 알고리즘 ID
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_CHECK_PKCS1_v1_5_ENCODE^ISC_ERR_ENCODING_FAILURE : 인코딩 비교 실패
* -# ISC_L_RSA^ISC_F_CHECK_PKCS1_v1_5_ENCODE^ISC_ERR_MALLOC : 메모리 할당 실패
* -# ISC_L_RSA^ISC_F_CHECK_PKCS1_v1_5_ENCODE^ISC_ERR_COMPARE_FAIL : 인코딩값 비교 실패
*/
ISC_API ISC_STATUS ISC_Check_EMSA_PKCS1_v1_5_Encode(const uint8 *EM, int emLen, int nLen, const uint8 *mHash, int mHashLen, int digest_algo);


/*!
* \brief
* PKCS1 PSS 인코딩
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param EM
* EncodedMessage의 버퍼 포인터
* \param emLen
* EncodedMessage 길이
* \param mHash
* 해시값
* \param mHashLen
* 해시 길이
* \param saltLen
* Salt 길이
* \param d_unit
* ISC_DIGEST_UNIT 구조체 포인터 
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_ADD_RSASSA_ENCODING^ISC_ERR_INVALID_INPUT : 입력 파라미터 오류
* -# ISC_L_RSA^ISC_F_ADD_RSASSA_ENCODING^ISC_ERR_SUB_OPERATION_FAILURE 내부 ISC_DIGEST /PKCS1_MGF1 함수 실패
* -# ISC_L_RSA^ISC_F_ADD_RSASSA_ENCODING^ISC_ERR_ENCODING_FAILURE : 인코딩 실패 
*/
ISC_API ISC_STATUS ISC_Add_RSASSA_PKCS1_PSS_Encode(ISC_RSA_UNIT* rsa, uint8 *EM, int emLen, const uint8 *mHash, int mHashLen, int saltLen, ISC_DIGEST_UNIT *d_unit);

/*!
* \brief
* PKCS1 PSS 인코딩 체크
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param EM
* EncodedMessage의 버퍼 포인터
* \param emLen
* EncodedMessage 길이
* \param mHash
* 해시값
* \param mHashLen
* 해시 길이
* \param saltLen
* Salt 길이
* \param d_unit
* ISC_DIGEST_UNIT 구조체 포인터 
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_CHECK_RSASSA_PKCS1_PSS_ENCODE^ISC_ERR_SUB_OPERATION_FAILURE : 내부 ISC_DIGEST /PKCS1_MGF1 함수 실패
* -# ISC_FAIL : ISC_BIGINT 관련 함수 실패 
*/
ISC_API ISC_STATUS ISC_Check_RSASSA_PKCS1_PSS_Encode(ISC_RSA_UNIT* rsa, uint8 *EM, int emLen, const uint8 *mHash, int mHashLen, int saltLen, ISC_DIGEST_UNIT *d_unit);

/*!
* \brief
* RSAES OAEP 인코딩
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param in
* 입력값 포인터
* \param inLen
* 입력값의 길이
* \param out
* 출력값 포인터
* \param outLen
* 출력값 포인터의 길이
* \param lable
* 레이블
* \param lableLen
* 레이블 길이
* \param version
* OAEP Version v2.1 (1) , OAEP Version v2.0 (0)
* \returns
* -# 인코딩된 메시지의 길이
* -# 0 : Encoding Fail
*/
ISC_API int ISC_Encode_RSAES_OAEP_PADDING(ISC_RSA_UNIT *rsa, const uint8 *in, int inLen, uint8 *out, int outLen,  const uint8 *lable, int lableLen, int version);

/*!
* \brief
* RSAES OAEP 디코딩
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param in
* 입력값 포인터
* \param inLen
* 입력값의 길이
* \param out
* 출력값 포인터
* \param outLen
* 출력값 포인터의 길이
* \param lable
* 레이블
* \param lableLen
* 레이블 길이
* \param version
* OAEP Version v2.1 (1) , OAEP Version v2.0 (0)
* \returns
* -# 인코딩된 메시지의 길이
* -# 0 : Decoding Fail
*/
ISC_API int ISC_Decode_RSAES_OAEP_PADDING(ISC_RSA_UNIT* rsa, const uint8 *in, int inLen, uint8 *out, int outLen, const uint8 *lable, int lableLen, int version);

/*!
* \brief
* RSAES PKCS1 인코딩
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param in
* 입력값 포인터
* \param inLen
* 입력값의 길이
* \param out
* 출력값 포인터
* \param outLen
* 출력값 포인터의 길이
* \returns
* -# 인코딩된 메시지의 길이
* -# 0 : Encoding Fail
*/
ISC_API int ISC_Encode_RSAES_PKCS1_PADDING(ISC_RSA_UNIT *rsa, const uint8 *in, int inLen, uint8 *out, int outLen);

/*!
* \brief
* RSAES PKCS1 디코딩
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param in
* 입력값 포인터
* \param inLen
* 입력값의 길이
* \param out
* 출력값 포인터
* \param outLen
* 출력값 포인터의 길이
* \returns
* -# 인코딩된 메시지의 길이
* -# 0 : Decoding Fail
*/
ISC_API int ISC_Decode_RSAES_PKCS1_PADDING(ISC_RSA_UNIT* rsa, const uint8 *in, int inLen, uint8 *out, int outLen);

/*!
* \brief
* ISC_RSA PSS 서명의 salt 길이 설정
* \param rsa
* ISC_RSA_UNIT 구조체 포인터
* \param saltLen
* salt의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_INTERNAL ISC_STATUS isc_Set_RSASSA_PKCS1_PSS_SALT_Length(ISC_RSA_UNIT* rsa, int saltLen);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_RSA_UNIT*, ISC_New_RSA, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_RSA, (ISC_RSA_UNIT *unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_RSA, (ISC_RSA_UNIT *unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_RSA_UNIT*, ISC_Dup_RSA, (ISC_RSA_UNIT *src), (src), NULL );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_RSA_Params, (ISC_RSA_UNIT *rsa, const ISC_BIGINT *n, const ISC_BIGINT *e, const ISC_BIGINT *d, const ISC_BIGINT *p, const ISC_BIGINT *q, const ISC_BIGINT *dp, const ISC_BIGINT *dq, const ISC_BIGINT *inv_q), (rsa, n, e, d, p, q, dp, dq, inv_q), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_RSA_Public_Params, (ISC_RSA_UNIT *rsa,  const ISC_BIGINT* n, const ISC_BIGINT* e), (rsa, n, e), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_RSASSA, (ISC_RSA_UNIT *rsa, int digest_alg, int padding, int sign), (rsa, digest_alg, padding, sign), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_RSASSA, (ISC_RSA_UNIT *rsa, const uint8 *data, int length), (rsa, data, length), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_RSASSA, (ISC_RSA_UNIT *rsa, uint8 *signature, int *sLen), (rsa, signature, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Sign_RSASSA, (ISC_RSA_UNIT *rsa, uint8 *signature, int *sLen), (rsa, signature, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Verify_RSASSA, (ISC_RSA_UNIT *rsa, uint8 *signature, int sLen), (rsa, signature, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_RSA_Params, (ISC_RSA_UNIT *rsa, ISC_BIGINT *e_value, int bits, int version), (rsa, e_value, bits, version), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_RSAES, (ISC_RSA_UNIT *rsa, int encode, int encryption, int digest_algo), (rsa, encode, encryption, digest_algo), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Encrypt_RSAES, (ISC_RSA_UNIT *rsa, uint8 *out, int *outLen, const uint8 *in, int inLen), (rsa, out, outLen, in, inLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Decrypt_RSAES, (ISC_RSA_UNIT *rsa, uint8 *out, int *outLen, const uint8 *in, int inLen), (rsa, out, outLen, in, inLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_RSA_Length, (ISC_RSA_UNIT* rsa), (rsa), 0 );

#endif

#ifdef  __cplusplus
}
#endif
#endif


