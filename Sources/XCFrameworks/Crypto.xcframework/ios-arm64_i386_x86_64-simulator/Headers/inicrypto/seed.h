/*!
 * \file seed.h
 * \brief ISC_SEED
 
 평문 128, 암호문 128bits, 키 128 bits\n

 * \author
 * Copyright (c) 2008 by \<INITech\>
 */
 
#ifndef HEADER_SEED_H
#define HEADER_SEED_H

#include "foundation.h"
#include "mem.h"
#include "blockcipher_mac.h"

#ifdef ISC_NO_SEED
#error ISC_SEED is disabled.
#endif

#define ISC_SEED_ENCRYPT	1			/*!< ISC_SEED의 암호화*/
#define ISC_SEED_DECRYPT	0			/*!< ISC_SEED의 복호화*/

/*--------------------------------------------------*/
#define ISC_SEED_NAME				"ISC_SEED"				
#define ISC_SEED_BLOCK_SIZE			16					
#define ISC_SEED_KEY_SIZE			16					
#define ISC_SEED_IV_SIZE			ISC_SEED_BLOCK_SIZE		
#define ISC_SEED_INIT				isc_Init_SEED			
#define ISC_SEED_ECB_DO				isc_Do_SEED_ECB			
#define ISC_SEED_CBC_DO				isc_Do_SEED_CBC			
#define ISC_SEED_CFB_DO				isc_Do_SEED_CFB	
#define ISC_SEED_CFB1_DO			isc_Do_SEED_CFB1
#define ISC_SEED_CFB8_DO			isc_Do_SEED_CFB8
#define ISC_SEED_CFB16_DO			isc_Do_SEED_CFB16
#define ISC_SEED_CFB32_DO			isc_Do_SEED_CFB32
#define ISC_SEED_CFB64_DO			isc_Do_SEED_CFB64
#define ISC_SEED_OFB_DO				isc_Do_SEED_OFB			
#define ISC_SEED_CTR_DO				isc_Do_SEED_CTR		
#define ISC_SEED_CCM_DO				isc_Do_SEED_CCM	
#define ISC_SEED_GCM_DO				isc_Do_SEED_GCM	
#define ISC_SEED_ST_SIZE			sizeof(ISC_SEED_KEY)	
/*--------------------------------------------------*/
#define ISC_SEED256_NAME			"SEED_256"				
#define ISC_SEED256_BLOCK_SIZE		ISC_SEED_BLOCK_SIZE					
#define ISC_SEED256_KEY_SIZE		32					
#define ISC_SEED256_IV_SIZE			ISC_SEED_BLOCK_SIZE		
#define ISC_SEED256_INIT			isc_Init_SEED			
#define ISC_SEED256_ECB_DO			isc_Do_SEED_ECB			
#define ISC_SEED256_CBC_DO			isc_Do_SEED_CBC			
#define ISC_SEED256_CFB_DO			isc_Do_SEED_CFB	
#define ISC_SEED256_CFB1_DO			isc_Do_SEED_CFB1
#define ISC_SEED256_CFB8_DO			isc_Do_SEED_CFB8
#define ISC_SEED256_CFB16_DO		isc_Do_SEED_CFB16
#define ISC_SEED256_CFB32_DO		isc_Do_SEED_CFB32
#define ISC_SEED256_CFB64_DO		isc_Do_SEED_CFB64
#define ISC_SEED256_OFB_DO			isc_Do_SEED_OFB			
#define ISC_SEED256_CTR_DO			isc_Do_SEED_CTR		
#define ISC_SEED256_CCM_DO			isc_Do_SEED_CCM	
#define ISC_SEED256_GCM_DO			isc_Do_SEED_GCM	
#define ISC_SEED256_ST_SIZE			sizeof(ISC_SEED_KEY)	
/*--------------------------------------------------*/
#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * ISC_SEED에서 쓰이는 ISC_SEED_KEY의 구조체
 * \remarks
 * uint32 data[32] 자료형
 */
typedef struct isc_seed_key_st {
    uint32 data[48];
	int rounds;
} ISC_SEED_KEY;

/*!
* \brief
* 한 블럭 128bit를 암호화하는 ISC_SEED 알고리즘
* \param in
* 평문 한 블럭
* \param out
* 암호문 한 블럭
* \param ks
* 암호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
* \remarks
* ISC_SEED_KEY key에 저장되어 있는 rounds 변수에 따라 128, 192, 256모드에 맞춰 암호화
*/
ISC_INTERNAL void isc_SEED_Encrypt_Block(const uint8 *in, uint8 *out, const ISC_SEED_KEY *ks);
/*!
* \brief
* 한 블럭 128bit를 복호화하는 ISC_SEED 알고리즘
* \param in
* 암호문 한 블럭
* \param out
* 평문 한 블럭
* \param ks
* 복호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
*/
ISC_INTERNAL void isc_SEED_Decrypt_Block(const uint8 *in, uint8 *out, const ISC_SEED_KEY *ks);

/*!
* \brief
* ISC_SEED에서 쓰이는 각 단계의 키를 만드는 함수
* \param userKey
* 초기 키값
* \param ks
* 키의 정보를 담고 있는 구조체 변수
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_SEED_Key(const uint8 *userKey, ISC_SEED_KEY *ks);

/*!
* \brief
* ISC_SEED에서 쓰이는 각 단계의 키를 만드는 함수(256bit)
* \param userKey
* 초기 키값
* \param ks
* 키의 정보를 담고 있는 구조체 변수
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_SEED_Key_256(const uint8 *userKey, ISC_SEED_KEY *ks);

/*!
* \brief
* ISC_SEED 초기 키 설정 함수
* \param unit
* ISC_BLOCK_CIPHER_UNIT 구조체
* \param key
* 초기 키값
* \param enc
* 1이면 encrypt모드, 0이면 decrypt모드
* \returns
* -# ISC_SUCCESS : Success
* -# L_SEED^ISC_F_INIT_SEED_KEY^ISC_ERR_INIT_KEY_FAILURE : 키 INIT 함수 실패
*/
ISC_INTERNAL ISC_STATUS isc_Init_SEED_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, int enc);
/*!
* \brief
* ISC_SEED 초기 함수
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
* -# L_SEED^ISC_F_INIT_SEED^ISC_ERR_INIT_FAILURE : 초기화 함수 실패
* \remarks
* iv값과 key값에 따라 함수 실행
*/
ISC_INTERNAL ISC_STATUS isc_Init_SEED(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* ISC_SEED ECB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_SEED^ISC_F_DO_SEED_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CBC모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_SEED^ISC_F_DO_SEED_CBC^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CFBR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param nbits
* 입력길이 비트수(ex:CFB1->1, CFB16->16)
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* ISC_SEED CFB1모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이(bit 길이)
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CFB8모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CFB16모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CFB32모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CFB64모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFB64(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* ISC_SEED OFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_SEED^ISC_F_DO_SEED_OFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CTR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_SEED^ISC_F_DO_SEED_CTR^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

ISC_INTERNAL ISC_STATUS isc_Do_SEED_CCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

ISC_INTERNAL ISC_STATUS isc_Do_SEED_GCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
#ifdef  __cplusplus
}
#endif

#endif /* HEADER_SEED_H */

