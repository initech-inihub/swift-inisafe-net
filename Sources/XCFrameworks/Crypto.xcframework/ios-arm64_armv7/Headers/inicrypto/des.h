/*!
* \file des.h
* \brief ISC_DES알고리즘

평문 64, 암호문 64bits, 키 56(64) bits, \n TriDES; 평문 64, 암호문 64bits, 키 112 bits

* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_DES_H
#define HEADER_DES_H

#include "foundation.h"
#include "mem.h"
#include "blockcipher.h"


#ifdef ISC_NO_DES
#error ISC_DES is disabled.
#endif

#define ISC_DES_ENCRYPT ISC_ENCRYPTION	/*!< ISC_DES의 암호화*/
#define ISC_DES_DECRYPT ISC_DECRYPTION	/*!< ISC_DES의 복호화*/

#ifndef ISC_NO_DES_EDE
#define ISC_DES_EDE_ENCRYPT ISC_ENCRYPTION	/*!< Triple ISC_DES의 암호화*/
#define ISC_DES_EDE_DECRYPT ISC_DECRYPTION	/*!< Triple ISC_DES의 복호화*/
#endif

/*--------------------------------------------------*/
#define ISC_DES_NAME			"ISC_DES"		
#define ISC_DES_BLOCK_SIZE		8			
#define ISC_DES_KEY_SIZE		8			
#define ISC_DES_IV_SIZE			ISC_DES_BLOCK_SIZE		
#define ISC_DES_INIT			isc_Init_DES			
#define ISC_DES_ECB_DO			isc_Do_DES_ECB			
#define ISC_DES_CBC_DO			isc_Do_DES_CBC			
#define ISC_DES_CFB_DO			isc_Do_DES_CFB	
#define ISC_DES_CFB1_DO			isc_Do_DES_CFB1	
#define ISC_DES_CFB8_DO			isc_Do_DES_CFB8	
#define ISC_DES_CFB16_DO		isc_Do_DES_CFB16	
#define ISC_DES_CFB32_DO		isc_Do_DES_CFB32
#define ISC_DES_OFB_DO			isc_Do_DES_OFB			
#define ISC_DES_CTR_DO			isc_Do_DES_CTR			
#define ISC_DES_ST_SIZE			sizeof(ISC_DES_KEY)		
/*--------------------------------------------------*/
#define ISC_DES_EDE_NAME			"ISC_DES_EDE"		
#define ISC_DES_EDE_BLOCK_SIZE		8				
#define ISC_DES_EDE_KEY_SIZE		24				
#define ISC_DES_EDE_IV_SIZE			ISC_DES_EDE_BLOCK_SIZE			
#define ISC_DES_EDE_INIT			isc_Init_DES_EDE				
#define ISC_DES_EDE_ECB_DO			isc_Do_DES_EDE_ECB				
#define ISC_DES_EDE_CBC_DO			isc_Do_DES_EDE_CBC				
#define ISC_DES_EDE_CFB_DO			isc_Do_DES_EDE_CFB		
#define ISC_DES_EDE_CFB1_DO			isc_Do_DES_EDE_CFB1	
#define ISC_DES_EDE_CFB8_DO			isc_Do_DES_EDE_CFB8	
#define ISC_DES_EDE_CFB16_DO		isc_Do_DES_EDE_CFB16	
#define ISC_DES_EDE_CFB32_DO		isc_Do_DES_EDE_CFB32
#define ISC_DES_EDE_OFB_DO			isc_Do_DES_EDE_OFB				
#define ISC_DES_EDE_CTR_DO			isc_Do_DES_EDE_CTR				
#define ISC_DES_EDE_ST_SIZE			sizeof(ISC_DES_EDE_KEY)			
/*--------------------------------------------------*/
#define ISC_DES_EDE_2KEY_NAME			"ISC_DES_EDE_2KEY"		
#define ISC_DES_EDE_2KEY_BLOCK_SIZE		8				
#define ISC_DES_EDE_2KEY_KEY_SIZE		16				
#define ISC_DES_EDE_2KEY_IV_SIZE		ISC_DES_EDE_BLOCK_SIZE			
#define ISC_DES_EDE_2KEY_INIT			isc_Init_DES_EDE				
#define ISC_DES_EDE_2KEY_ECB_DO			isc_Do_DES_EDE_ECB				
#define ISC_DES_EDE_2KEY_CBC_DO			isc_Do_DES_EDE_CBC				
#define ISC_DES_EDE_2KEY_CFB_DO			isc_Do_DES_EDE_CFB	
#define ISC_DES_EDE_2KEY_CFB1_DO		isc_Do_DES_EDE_CFB1
#define ISC_DES_EDE_2KEY_CFB8_DO		isc_Do_DES_EDE_CFB8
#define ISC_DES_EDE_2KEY_CFB16_DO		isc_Do_DES_EDE_CFB16
#define ISC_DES_EDE_2KEY_CFB32_DO		isc_Do_DES_EDE_CFB32
#define ISC_DES_EDE_2KEY_OFB_DO			isc_Do_DES_EDE_OFB				
#define ISC_DES_EDE_2KEY_CTR_DO			isc_Do_DES_EDE_CTR				
#define ISC_DES_EDE_2KEY_ST_SIZE		sizeof(ISC_DES_EDE_KEY)			
/*--------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_DES에서 쓰이는 ISC_DES_KEY의 구조체
* \remarks
* uint32 key[32]
*/
typedef struct isc_des_key_st {
	uint32 key[32];
} ISC_DES_KEY;

#ifndef ISC_NO_DES_EDE
/*!
* \brief
* Triple ISC_DES에서 쓰이는 ISC_DES_EDE_KEY의 구조체
* \remarks
* ISC_DES_KEY desKey[3]
*/
typedef struct isc_des3_key_st {
	ISC_DES_KEY desKey[3];
} ISC_DES_EDE_KEY;
#endif

/*!
* \brief
* ISC_DES에서 쓰이는 각 단계의 키를 만드는 함수
* \param userkey
* 초기 키값
* \param desKey
* 키의 정보를 담고 있는 구조체 변수
* \param encMode
* 1이면 Encryption, 2이면 Decryption
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
* \remarks
* Key값은 64bit를 지원
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_DES_Key(const uint8 *userkey, ISC_DES_KEY *desKey, short encMode);
/*!
* \brief
* 한 블럭 64bit를 암호화하는 ISC_DES 알고리즘
* \param in
* 평문 한 블럭
* \param out
* 암호문 한 블럭
* \param desKey
* 암호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
* \remarks
* ISC_DES_KEY desKey에 저장되어 있는 rounds 변수에 따라 암호화
*/
ISC_INTERNAL void isc_DES_Encrypt_Block(const uint8 *in, uint8 *out, ISC_DES_KEY *desKey);

ISC_INTERNAL void isc_DES_Encrypt_Block2(const uint8 *in, uint8 *out, ISC_DES_KEY *desKey);

/*!
* \brief
* ISC_DES 초기 함수
* \param unit
* ISC_BLOCK_CIPHER_UNIT 구조체
* \param userkey
* 초기 키값
* \param iv
* 초기 벡터값
* \param enc
* 1이면 encrypt모드, 0이면 decrypt모드
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# 
* \remarks
* iv값과 key값에 따라 함수 실행
*/
ISC_INTERNAL ISC_STATUS isc_Init_DES(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *userkey, const uint8 *iv, int enc);
/*!
* \brief
* ISC_DES 초기 키 설정 함수
* \param unit
* ISC_BLOCK_CIPHER_UNIT 구조체
* \param userkey
* 초기 키값
* \param enc
* 1이면 encrypt모드, 0이면 decrypt모드
* \returns
* -# ISC_SUCCESS : Success
* -# L_DES^ISC_F_INIT_DES_KEY^ISC_ERR_INIT_KEY_FAILURE : 키생성 실패
* \remarks
* enc 변수값에 따라서 isc_Init_Encrypt_DES_Key와 isc_Init_decrypt_DES_KEY를 실행
*/
ISC_INTERNAL ISC_STATUS isc_Init_DES_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *userkey, int enc);

/*!
* \brief
* ISC_DES ECB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 횟수
* \returns
* -# L_DES^ISC_F_DO_DES_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CBC모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 횟수
* \returns
* -# L_DES^ISC_F_DO_DES_CBC^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 횟수
* \returns
* -# L_DES^ISC_F_DO_DES_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CFBR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param nbits
* 입력길이 비트수(ex:CFB1->1, CFB16->16)
* \returns
* -# L_DES^ISC_F_DO_DES_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* ISC_DES CFB1모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이(bit 길이)
* \returns
* -# L_DES^ISC_F_DO_DES_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CFB8모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_DES^ISC_F_DO_DES_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CFB16모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_DES^ISC_F_DO_DES_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CFB32모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_DES^ISC_F_DO_DES_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES OFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 횟수
* \returns
* -# L_DES^ISC_F_DO_DES_OFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CTR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 횟수
* \returns
* -# L_DES^ISC_F_DO_DES_CTR^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

#ifndef ISC_NO_DES_EDE

/*                           ISC_DES_EDE                                */


/*!
* \brief
* Triple ISC_DES에서 쓰이는 각 단계의 키를 만드는 함수
* \param userKey
* 초기 키값
* \param userKeyLen
* 초기 키 길이
* \param desEdeKey
* 키의 정보를 담고 있는 구조체 변수
* \param encMode
* 1이면 Encryption, 0이면 Decryption
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
/*ISC_STATUS isc_Init_Encrypt_DES_EDE_KEY(const uint8 *userKey, int userKeyLen, ISC_DES_EDE_KEY *desEdeKey, short encMode); */
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_DES_EDE_KEY(const uint8 *userKey, int userKeyLen, ISC_DES_EDE_KEY *desEdeKey, short encMode);
/*!
* \brief
* 한 블럭 64bit를 암호화하는 Triple ISC_DES 알고리즘
* \param in
* 평문 한 블럭
* \param out
* 암호문 한 블럭
* \param desEdeKey
* 암호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
* \remarks
* ISC_DES_EDE_KEY desEdeKey에 저장되어 있는 키값을 따라 암호화한다.
*/
ISC_INTERNAL void DES_EDE_encrypt_block(uint8 *in, uint8 *out, ISC_DES_EDE_KEY *desEdeKey);

/*!
* \brief
* Triple ISC_DES 초기 함수
* \param unit
* ISC_BLOCK_CIPHER_UNIT 구조체
* \param userkey
* 초기 키값
* \param iv
* 초기 벡터값
* \param enc
* 1이면 encrypt모드, 0이면 decrypt모드
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
* \remarks
* iv값과 key값에 따라 함수 실행
*/
ISC_INTERNAL ISC_STATUS isc_Init_DES_EDE(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *userkey, const uint8 *iv, int enc);

/*!
* \brief
* Triple ISC_DES에서 쓰이는 각 단계의 키를 만드는 함수
* \param unit
* 키의 정보를 담고 있는 구조체 변수
* \param userkey
* 초기 키값
* \param enc
* Encryption or Decryption
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_INTERNAL ISC_STATUS isc_Init_DES_EDE_key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *userkey, int enc);

/*!
* \brief
* Triple ISC_DES ECB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 횟수
* \returns
* -# L_DES_EDE^ISC_F_DO_DES_EDE_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, uint8 *in, uint32 inl);
/*!
* \brief
* Triple ISC_DES CBC모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 횟수
* \returns
* -# L_DES_EDE^ISC_F_DO_DES_EDE_CBC^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, uint8 *in, uint32 inl);
/*!
* \brief
* Triple ISC_DES CFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 횟수
* \returns
* -# L_DES_EDE^ISC_F_DO_DES_EDE_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, uint8 *in, uint32 inl);

ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);


/*!
* \brief
* Triple ISC_DES OFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 횟수
* \returns
* -# L_DES_EDE^ISC_F_DO_DES_EDE_OFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, uint8 *in, uint32 inl);
/*!
* \brief
* Triple ISC_DES CTR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 횟수
* \returns
* -# L_DES_EDE^ISC_F_DO_DES_EDE_CTR^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, uint8 *in, uint32 inl);

#endif

#ifdef  __cplusplus
}
#endif

#endif/* HEADER_DES_H */

