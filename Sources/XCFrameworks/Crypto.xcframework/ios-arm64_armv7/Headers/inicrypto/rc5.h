/*!
* \file rc5.h
* \brief ISC_RC5 알고리즘
* 평문 64bits, 암호문 64bits, 키 128bits\n
* \remarks
* ISC_RC5는 32bit OS를 기반으로 설계, round수는 12로 기본설정
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_RC5_H
#define HEADER_RC5_H

#include "foundation.h"
#include "mem.h"

#ifdef ISC_NO_RC5
#error ISC_RC5 is disabled.
#endif

#define ISC_RC5_ENCRYPT	1			/*!< ISC_RC5의 암호화*/
#define ISC_RC5_DECRYPT	0			/*!< ISC_RC5의 복호화*/

#define ISC_RC5_ROUNDS_8	8
#define ISC_RC5_ROUNDS_12	12
#define ISC_RC5_ROUNDS_16	16

#define ISC_RC5_ROUNDS	ISC_RC5_ROUNDS_12

/*--------------------------------------------------*/
#define ISC_RC5_NAME				"ISC_RC5"
#define ISC_RC5_BLOCK_SIZE			8
#define ISC_RC5_KEY_SIZE			16
#define ISC_RC5_IV_SIZE				ISC_RC5_BLOCK_SIZE		
#define ISC_RC5_INIT				isc_Init_RC5			
#define ISC_RC5_ECB_DO				isc_Do_RC5_ECB			
#define ISC_RC5_CBC_DO				isc_Do_RC5_CBC			
#define ISC_RC5_CFB_DO				isc_Do_RC5_CFB	
#define ISC_RC5_CFB1_DO				isc_Do_RC5_CFB1
#define ISC_RC5_CFB8_DO				isc_Do_RC5_CFB8
#define ISC_RC5_CFB16_DO			isc_Do_RC5_CFB16
#define ISC_RC5_CFB32_DO			isc_Do_RC5_CFB32
#define ISC_RC5_CFB64_DO			isc_Do_RC5_CFB64
#define ISC_RC5_CFB128_DO			isc_Do_RC5_CFB
#define ISC_RC5_OFB_DO				isc_Do_RC5_OFB			
#define ISC_RC5_CTR_DO				isc_Do_RC5_CTR			
#define ISC_RC5_ST_SIZE				sizeof(ISC_RC5_KEY)	
/*--------------------------------------------------*/


#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * ISC_RC5의 키에 쓰이는 정보를 다룰 구조체
 * \remarks
 * rd_key(키), rounds(라운드수)
 */
struct isc_rc5_key_st {
	uint32 rd_key[(ISC_RC5_ROUNDS_16+1)*2];
	int rounds;
} ;

typedef struct isc_rc5_key_st ISC_RC5_KEY;

/*!
* \brief
* ISC_RC5에서 쓰이는 각 단계의 키를 만드는 함수
* \param data
* 초기 키값
* \param len
* 키의 bit 사이즈
* \param key
* 키의 정보를 담고 있는 구조체 변수
* \returns
* -# INI_CRYPT_SUCCESS : Success
* -# INI_CRYPT_FAIL : Fail
* \remarks
* Key값은 기본적으로 128비트
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_RC5_Key(const uint8 *data, int len, ISC_RC5_KEY *key);

/*!
* \brief
* ISC_RC5 초기 키 설정 함수
* \param unit
* ISC_BLOCK_CIPHER_UNIT 구조체
* \param key
* 초기 키값
* \returns
* -# ISC_SUCCESS : Success
* -# L_RC5^ISC_F_INIT_RC5_KEY^ISC_ERR_INIT_KEY_FAILURE : 초기 키 생성 실패
*/
ISC_INTERNAL ISC_STATUS isc_Init_RC5_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key);
/*!
* \brief
* ISC_RC5 초기 함수
* \param unit
* ISC_BLOCK_CIPHER_UNIT 구조체
* \param key
* 초기 키값
* \param iv
* 초기 벡터값
* \param enc
* 1이면 encrypt모드, 0이면 decrypt모드
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# isc_Init_encrypto_RC5_KEY의 에러
*  -# L_RC5^ISC_F_INIT_RC5_KEY^ISC_ERR_INIT_KEY_FAILURE : 초기 키 생성 실패
* \remarks
* iv값과 key값에 따라 함수 실행
*/
ISC_INTERNAL ISC_STATUS isc_Init_RC5(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* 한 블럭 64bit를 암호화하는 ISC_RC5 알고리즘
* \param in_out
* 평문 한 블럭, 출력값이 다시 저장.
* \param key
* 암호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
*/
ISC_INTERNAL void isc_RC5_Encrypt_Block(uint32 *in_out, ISC_RC5_KEY *key);

/*!
* \brief
* 한 블럭 64bit를 복호화하는 ISC_RC5 알고리즘
* \param in_out
* 암호문 한 블럭, 출력값이 다시 저장.
* \param key
* 복호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
*/
ISC_INTERNAL void isc_RC5_Decrypt_Block(uint32 *in_out, ISC_RC5_KEY *key);

/*!
* \brief
* ISC_RC5 ECB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CBC모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param nbits
* 입력길이 비트수(ex:CFB1->1, CFB16->16)
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* ISC_RC5 CFB1모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이(bit 길이)
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CFB8모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CFB16모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CFB32모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CFB64모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFB64(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 OFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CTR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_RC5_H */

