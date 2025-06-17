/*!
 * \file bf.h
 * \brief BlowFish
 * BlowFish 평문 64, 암호문 64bits, 키 4 ~ 56bytes \n
 * \remarks
 * round수는 16로 기본설정, 키는 기본적으로 16바이트로 적용되며, \n
 * 가변키 적용을 위해서 isc_Init_Encrypt_BF_Key를 사용하여야 함
 * \author
 * Copyright (c) 2008 by \<INITech\>
 */
 
#ifndef HEADER_BF_H
#define HEADER_BF_H

#include "foundation.h"
#include "mem.h"

#ifdef ISC_NO_BF
#error ISC_BF is disabled.
#endif

#define ISC_BF_ENCRYPT	1			/*!< ISC_BF의 암호화*/
#define ISC_BF_DECRYPT	0			/*!< ISC_BF의 복호화*/

#define ISC_BF_ROUNDS	16          /*!< Round 횟수(16 or 20) */

/*--------------------------------------------------*/
#define ISC_BF_NAME					"BlowFish"				
#define ISC_BF_BLOCK_SIZE			8					
#define ISC_BF_KEY_SIZE				16					
#define ISC_BF_IV_SIZE				ISC_BF_BLOCK_SIZE		
#define ISC_BF_INIT					isc_Init_BF			
#define ISC_BF_ECB_DO				isc_Do_BF_ECB			
#define ISC_BF_CBC_DO				isc_Do_BF_CBC			
#define ISC_BF_CFB_DO				isc_Do_BF_CFB		
#define ISC_BF_CFB1_DO				isc_Do_BF_CFB1	
#define ISC_BF_CFB8_DO				isc_Do_BF_CFB8	
#define ISC_BF_CFB16_DO				isc_Do_BF_CFB16	
#define ISC_BF_CFB32_DO				isc_Do_BF_CFB32	
#define ISC_BF_OFB_DO				isc_Do_BF_OFB			
#define ISC_BF_CTR_DO				isc_Do_BF_CTR			
#define ISC_BF_ST_SIZE				sizeof(BF_KEY)	
/*--------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * ISC_BF에서 쓰이는 BF_KEY의 구조체
 */
typedef struct isc_bf_key_st {
	uint32 P[ISC_BF_ROUNDS+2];
    uint32 S[4*256];
} BF_KEY;

/*!
* \brief
* 한 블럭 64bit를 암호화하는 BlowFish 알고리즘
* \param in
* 평문 한 블럭, 출력값이 다시 저장.
* \param key
* 암호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
*/
ISC_INTERNAL void isc_BF_Encrypt_Block(uint32 *in, const BF_KEY *key);
/*!
* \brief
* 한 블럭 64bit를 복호화하는 BlowFish 알고리즘
* \param in
* 평문 한 블럭, 출력값이 다시 저장.
* \param key
* 암호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
*/
ISC_INTERNAL void isc_BF_Decrypt_Block(uint32 *in, const BF_KEY *key);


/*!
* \brief
* BlowFish에서 쓰이는 각 단계의 키를 만드는 함수
* \param userKey
* 초기 키값
* \param len
* 키값의 길이
* \param key
* 키의 정보를 담고 있는 구조체 변수
* \returns
* -# INI_CRYPT_SUCCESS : Success
* -# INI_CRYPT_FAIL : Fail
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_BF_Key(const uint8 *userKey, int len, BF_KEY *key);
/*!
* \brief
* BlowFish 초기 키 설정 함수
* \param unit
* ISC_BLOCK_CIPHER_UNIT 구조체
* \param key
* 초기 키값
* \param enc
* 1이면 encrypt모드, 0이면 decrypt모드
* \returns
* -# ISC_SUCCESS : Success
* -# L_BF^ISC_F_INIT_BF_KEY^ISC_ERR_INIT_KEY_FAILURE : Key Init Fail
*/
ISC_INTERNAL ISC_STATUS isc_Init_BF_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, int enc);
/*!
* \brief
* BlowFish 초기 함수
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
* -# L_BF^ISC_F_INIT_BF_KEY^ISC_ERR_INIT_KEY_FAILURE : Key Init Fail
* \remarks
* iv값과 key값에 따라 함수 실행
*/
ISC_INTERNAL ISC_STATUS isc_Init_BF(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* BlowFish ECB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_BF^ISC_F_DO_BF_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CBC모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_BF^ISC_F_DO_BF_CBC^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_BF^ISC_F_DO_BF_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CFBR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param nbits
* 입력길이 비트수(ex:CFB1->1, CFB16->16)
* \returns
* -# L_BF^ISC_F_DO_BF_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* BlowFish CFB1모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이(bit 길이)
* \returns
* -# L_BF^ISC_F_DO_BF_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CFB8모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_BF^ISC_F_DO_BF_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CFB16모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_BF^ISC_F_DO_BF_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CFB32모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_BF^ISC_F_DO_BF_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish OFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_BF^ISC_F_DO_BF_OFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CTR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_BF^ISC_F_DO_BF_CTR^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_BF_H */

