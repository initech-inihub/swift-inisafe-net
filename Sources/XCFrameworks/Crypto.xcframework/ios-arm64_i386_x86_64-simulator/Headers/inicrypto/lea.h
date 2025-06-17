/*!
* \file lea.h
* \brief LEA 알고리즘

평문 128, 암호문 128bits, 키 128,192,256 bits\n

* \author
* Copyright (c) 2013 by \<INITech\>
*/

#ifndef HEADER_LEA_H
#define HEADER_LEA_H

#include "foundation.h"
#include "mem.h"
#include "blockcipher_mac.h"

#ifdef NO_LEA
#error LEA is disabled.
#endif

#define ISC_LEA_ENCRYPT	1			/*!< LEA의 암호화*/
#define ISC_LEA_DECRYPT	0			/*!< LEA의 복호화*/

#define ISC_LEA_BLOCK_SIZE	16		/*!< LEA의 BLOCK_SIZE*/
#define ISC_LEA_WORD_SIZE	4

#define ISC_LEA128_RND		24
#define ISC_LEA192_RND		28
#define ISC_LEA256_RND		32

#define ISC_LEA_RND_128_KEY_BYTE_LEN ISC_LEA128_RND*6
#define ISC_LEA_RND_192_KEY_BYTE_LEN ISC_LEA192_RND*6
#define ISC_LEA_RND_256_KEY_BYTE_LEN ISC_LEA256_RND*6
#define ISC_LEA_RND_MAX_KEY_BYTE_LEN ISC_LEA_RND_256_KEY_BYTE_LEN

/*--------------------------------------------------*/
#define ISC_LEA128_NAME				"LEA_128"			
#define ISC_LEA128_BLOCK_SIZE		ISC_LEA_BLOCK_SIZE		
#define ISC_LEA128_KEY_SIZE			16					
#define ISC_LEA128_IV_SIZE			ISC_LEA_BLOCK_SIZE		
#define ISC_LEA128_INIT				isc_Init_LEA			
#define ISC_LEA128_ECB_DO			isc_Do_LEA_ECB			
#define ISC_LEA128_CBC_DO			isc_Do_LEA_CBC			
#define ISC_LEA128_CFB_DO			isc_Do_LEA_CFB		
#define ISC_LEA128_CFB1_DO			isc_Do_LEA_CFB1	
#define ISC_LEA128_CFB8_DO			isc_Do_LEA_CFB8	
#define ISC_LEA128_CFB16_DO			isc_Do_LEA_CFB16	
#define ISC_LEA128_CFB32_DO			isc_Do_LEA_CFB32	
#define ISC_LEA128_CFB64_DO			isc_Do_LEA_CFB64	
#define ISC_LEA128_OFB_DO			isc_Do_LEA_OFB			
#define ISC_LEA128_CTR_DO			isc_Do_LEA_CTR
#define ISC_LEA128_CCM_DO			isc_Do_LEA_CCM	
#define ISC_LEA128_GCM_DO			isc_Do_LEA_GCM	
#define ISC_LEA128_ST_SIZE			sizeof(ISC_LEA_KEY)	
/*--------------------------------------------------*/
/*--------------------------------------------------*/
#define ISC_LEA192_NAME				"LEA_192"			
#define ISC_LEA192_BLOCK_SIZE		ISC_LEA_BLOCK_SIZE		
#define ISC_LEA192_KEY_SIZE			24					
#define ISC_LEA192_IV_SIZE			ISC_LEA_BLOCK_SIZE		
#define ISC_LEA192_INIT				isc_Init_LEA			
#define ISC_LEA192_ECB_DO			isc_Do_LEA_ECB			
#define ISC_LEA192_CBC_DO			isc_Do_LEA_CBC			
#define ISC_LEA192_CFB_DO			isc_Do_LEA_CFB		
#define ISC_LEA192_CFB1_DO			isc_Do_LEA_CFB1	
#define ISC_LEA192_CFB8_DO			isc_Do_LEA_CFB8	
#define ISC_LEA192_CFB16_DO			isc_Do_LEA_CFB16	
#define ISC_LEA192_CFB32_DO			isc_Do_LEA_CFB32	
#define ISC_LEA192_CFB64_DO			isc_Do_LEA_CFB64	
#define ISC_LEA192_OFB_DO			isc_Do_LEA_OFB			
#define ISC_LEA192_CTR_DO			isc_Do_LEA_CTR		
#define ISC_LEA192_CCM_DO			isc_Do_LEA_CCM	
#define ISC_LEA192_GCM_DO			isc_Do_LEA_GCM	
#define ISC_LEA192_ST_SIZE			sizeof(ISC_LEA_KEY)	
/*--------------------------------------------------*/
/*--------------------------------------------------*/
#define ISC_LEA256_NAME				"LEA_256"			
#define ISC_LEA256_BLOCK_SIZE		ISC_LEA_BLOCK_SIZE		
#define ISC_LEA256_KEY_SIZE			32					
#define ISC_LEA256_IV_SIZE			ISC_LEA_BLOCK_SIZE		
#define ISC_LEA256_INIT				isc_Init_LEA			
#define ISC_LEA256_ECB_DO			isc_Do_LEA_ECB			
#define ISC_LEA256_CBC_DO			isc_Do_LEA_CBC			
#define ISC_LEA256_CFB_DO			isc_Do_LEA_CFB	
#define ISC_LEA256_CFB1_DO			isc_Do_LEA_CFB1	
#define ISC_LEA256_CFB8_DO			isc_Do_LEA_CFB8	
#define ISC_LEA256_CFB16_DO			isc_Do_LEA_CFB16	
#define ISC_LEA256_CFB32_DO			isc_Do_LEA_CFB32	
#define ISC_LEA256_CFB64_DO			isc_Do_LEA_CFB64	
#define ISC_LEA256_OFB_DO			isc_Do_LEA_OFB			
#define ISC_LEA256_CTR_DO			isc_Do_LEA_CTR		
#define ISC_LEA256_CCM_DO			isc_Do_LEA_CCM	
#define ISC_LEA256_GCM_DO			isc_Do_LEA_GCM	
#define ISC_LEA256_ST_SIZE			sizeof(ISC_LEA_KEY)	
/*--------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * LEA의 키에 쓰이는 정보를 다룰 구조체
 * \remarks
 * rd_key(라운드키), rounds(라운드수)
 */
struct isc_lea_key_st {
	uint32 rd_key[ISC_LEA_RND_MAX_KEY_BYTE_LEN];
	int rounds;
};

typedef struct isc_lea_key_st ISC_LEA_KEY;
/*!
* \brief
* LEA에서 쓰이는 각 단계의 키를 만드는 함수
* \param KLR
* 초기 키값
* \param keysize
* 키의 사이즈(bytes)
* \param key
* 키의 정보를 담고 있는 구조체 변수
* \returns
* -# INI_CRYPT_SUCCESS : Success
* -# INI_CRYPT_FAIL : Fail
* \remarks
* Key값은 128, 192, 그리고 256비트를 지원
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_LEA_Key(const uint8 *user_key, const int key_size, ISC_LEA_KEY *key);

/*!
* \brief
* LEA 초기 키 설정 함수
* \param unit
* ISC_BLOCK_CIPHER_UNIT 구조체
* \param key
* 초기 키값
* \param enc
* 1이면 encrypt모드, 0이면 decrypt모드
* \returns
* -# ISC_SUCCESS : Success
* -# L_LEA^ISC_F_INIT_LEA_KEY^ISC_ERR_INIT_KEY_FAILURE : 키 생성 실패
* \remarks
* enc 변수값에 따라서 isc_Init_Encrypt_LEA_Key와 isc_Init_decrypt_LEA_KEY를 실행
*/
ISC_INTERNAL ISC_STATUS isc_Init_LEA_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, int enc);

/*!
* \brief
* LEA 초기 함수
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
* -# isc_Init_LEA_Key() 출력 에러
* -# ISC_Crypto_Initialize()의 에러코드
* -# L_LEA^ISC_F_INIT_LEA^ISC_ERR_INIT_FAILURE : 초기화 실패
* \remarks
* iv값과 key값에 따라 함수 실행
*/
ISC_INTERNAL ISC_STATUS isc_Init_LEA(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* 한 블럭 128bit를 암호화하는 LEA 알고리즘
* \param in
* 평문 한 블럭
* \param out
* 암호문 한 블럭
* \param key
* 암호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
* \remarks
* ISC_LEA_KEY key에 저장되어 있는 rounds 변수에 따라 128, 192, 256모드에 맞춰 암호화
*/
ISC_INTERNAL void isc_LEA_Encrypt_Block(const uint8 *in, uint8 *out, const ISC_LEA_KEY *key);

/*!
* \brief
* 한 블럭 128bit를 복호화하는 LEA 알고리즘
* \param in
* 암호문 한 블럭
* \param out
* 평문 한 블럭
* \param key
* 복호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
* \remarks
* ISC_LEA_KEY key에 저장되어 있는 rounds 변수에 따라 128, 192, 256모드에 맞춰 복호화
*/
ISC_INTERNAL void isc_LEA_Decrypt_Block(const uint8 *in, uint8 *out, const ISC_LEA_KEY *key);

/*!
* \brief
* LEA ECB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_LEA^ISC_F_DO_LEA_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CBC모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_LEA^ISC_F_DO_LEA_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA OFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_LEA^ISC_F_DO_LEA_CBC^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CFBR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param nbits
* 입력길이 비트수(ex:CFB1->1, CFB16->16)
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);

/*!
* \brief
* LEA CFB1모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이(bit 길이)
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CFB8모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CFB16모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CFB32모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CFB64모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFB64(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CTR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_LEA^ISC_F_DO_LEA_CTR^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

ISC_INTERNAL ISC_STATUS isc_Do_LEA_CCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_LEA_GCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
#ifdef  __cplusplus
}
#endif
#endif /* HEADER_LEA_H */

