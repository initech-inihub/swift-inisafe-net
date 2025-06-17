/*!
* \file aria.h
* \brief ARIA 알고리즘

평문 128, 암호문 128bits, 키 128,192,256 bits\n

* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_ARIA_H
#define HEADER_ARIA_H

#include "foundation.h"
#include "mem.h"
#include "blockcipher_mac.h"

#ifdef ISC_NO_ARIA
#error ARIA is disabled.
#endif

#define ISC_ARIA_ENCRYPT	1			/*!< ARIA의 암호화*/
#define ISC_ARIA_DECRYPT	0			/*!< ARIA의 복호화*/

#define ISC_ARIA_BLOCK_SIZE	16			/*!< ARIA의 BLOCK_SIZE*/
#define ISC_ARIA_WORD_SIZE  4

#define ISC_ARIA_MAXKB	32
#define ISC_ARIA_MAXNR	16

/*--------------------------------------------------*/
#define ISC_ARIA128_NAME			"ARIA_128"			
#define ISC_ARIA128_BLOCK_SIZE		ISC_ARIA_BLOCK_SIZE		
#define ISC_ARIA128_KEY_SIZE		16					
#define ISC_ARIA128_IV_SIZE			ISC_ARIA_BLOCK_SIZE		
#define ISC_ARIA128_INIT			isc_Init_ARIA			
#define ISC_ARIA128_ECB_DO			isc_Do_ARIA_ECB			
#define ISC_ARIA128_CBC_DO			isc_Do_ARIA_CBC			
#define ISC_ARIA128_CFB_DO			isc_Do_ARIA_CFB		
#define ISC_ARIA128_CFB1_DO			isc_Do_ARIA_CFB1	
#define ISC_ARIA128_CFB8_DO			isc_Do_ARIA_CFB8	
#define ISC_ARIA128_CFB16_DO		isc_Do_ARIA_CFB16	
#define ISC_ARIA128_CFB32_DO		isc_Do_ARIA_CFB32	
#define ISC_ARIA128_CFB64_DO		isc_Do_ARIA_CFB64	
#define ISC_ARIA128_OFB_DO			isc_Do_ARIA_OFB			
#define ISC_ARIA128_CTR_DO			isc_Do_ARIA_CTR	
#define ISC_ARIA128_CCM_DO			isc_Do_ARIA_CCM		
#define ISC_ARIA128_GCM_DO			isc_Do_ARIA_GCM		
#define ISC_ARIA128_ST_SIZE			sizeof(ISC_ARIA_KEY)	
/*--------------------------------------------------*/
/*--------------------------------------------------*/
#define ISC_ARIA192_NAME			"ARIA_192"			
#define ISC_ARIA192_BLOCK_SIZE		ISC_ARIA_BLOCK_SIZE		
#define ISC_ARIA192_KEY_SIZE		24					
#define ISC_ARIA192_IV_SIZE			ISC_ARIA_BLOCK_SIZE		
#define ISC_ARIA192_INIT			isc_Init_ARIA			
#define ISC_ARIA192_ECB_DO			isc_Do_ARIA_ECB			
#define ISC_ARIA192_CBC_DO			isc_Do_ARIA_CBC			
#define ISC_ARIA192_CFB_DO			isc_Do_ARIA_CFB		
#define ISC_ARIA192_CFB1_DO			isc_Do_ARIA_CFB1	
#define ISC_ARIA192_CFB8_DO			isc_Do_ARIA_CFB8	
#define ISC_ARIA192_CFB16_DO		isc_Do_ARIA_CFB16	
#define ISC_ARIA192_CFB32_DO		isc_Do_ARIA_CFB32	
#define ISC_ARIA192_CFB64_DO		isc_Do_ARIA_CFB64	
#define ISC_ARIA192_OFB_DO			isc_Do_ARIA_OFB			
#define ISC_ARIA192_CTR_DO			isc_Do_ARIA_CTR
#define ISC_ARIA192_CCM_DO			isc_Do_ARIA_CCM		
#define ISC_ARIA192_GCM_DO			isc_Do_ARIA_GCM	
#define ISC_ARIA192_ST_SIZE			sizeof(ISC_ARIA_KEY)	
/*--------------------------------------------------*/
/*--------------------------------------------------*/
#define ISC_ARIA256_NAME			"ARIA_256"			
#define ISC_ARIA256_BLOCK_SIZE		ISC_ARIA_BLOCK_SIZE		
#define ISC_ARIA256_KEY_SIZE		32					
#define ISC_ARIA256_IV_SIZE			ISC_ARIA_BLOCK_SIZE		
#define ISC_ARIA256_INIT			isc_Init_ARIA			
#define ISC_ARIA256_ECB_DO			isc_Do_ARIA_ECB			
#define ISC_ARIA256_CBC_DO			isc_Do_ARIA_CBC			
#define ISC_ARIA256_CFB_DO			isc_Do_ARIA_CFB	
#define ISC_ARIA256_CFB1_DO			isc_Do_ARIA_CFB1	
#define ISC_ARIA256_CFB8_DO			isc_Do_ARIA_CFB8	
#define ISC_ARIA256_CFB16_DO		isc_Do_ARIA_CFB16	
#define ISC_ARIA256_CFB32_DO		isc_Do_ARIA_CFB32	
#define ISC_ARIA256_CFB64_DO		isc_Do_ARIA_CFB64	
#define ISC_ARIA256_OFB_DO			isc_Do_ARIA_OFB			
#define ISC_ARIA256_CTR_DO			isc_Do_ARIA_CTR		
#define ISC_ARIA256_CCM_DO			isc_Do_ARIA_CCM		
#define ISC_ARIA256_GCM_DO			isc_Do_ARIA_GCM	
#define ISC_ARIA256_ST_SIZE			sizeof(ISC_ARIA_KEY)	
/*--------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * ARIA의 키에 쓰이는 정보를 다룰 구조체
 * \remarks
 * rd_key1(암호화키), rd_key2(복호화키), rounds(라운드수)
 */
struct isc_aria_key_st {
	uint32 rd_key1[ISC_ARIA_WORD_SIZE * (ISC_ARIA_MAXNR + 1)];
	uint32 rd_key2[ISC_ARIA_WORD_SIZE * (ISC_ARIA_MAXNR + 1)];
	int rounds;
} ;

typedef struct isc_aria_key_st ISC_ARIA_KEY;
/*!
* \brief
* ARIA에서 쓰이는 각 단계의 키를 만드는 함수
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
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_ARIA_Key(const uint8 *KLR, const int keysize, ISC_ARIA_KEY *key);
/*!
* \brief
* 복호화할때 쓰이는 각 단계의 키를 만드는 함수
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
ISC_INTERNAL ISC_STATUS isc_Init_Decrypt_ARIA_Key(const uint8 *KLR, const int keysize, ISC_ARIA_KEY *key);

/*!
* \brief
* ARIA 초기 키 설정 함수
* \param unit
* ISC_BLOCK_CIPHER_UNIT 구조체
* \param key
* 초기 키값
* \param enc
* 1이면 encrypt모드, 0이면 decrypt모드
* \returns
* -# ISC_SUCCESS : Success
* -# L_ARIA^ISC_F_INIT_ARIA_KEY^ISC_ERR_INIT_KEY_FAILURE : 키 생성 실패
* \remarks
* enc 변수값에 따라서 isc_Init_Encrypt_ARIA_Key와 isc_Init_Decrypt_ARIA_Key를 실행
*/
ISC_INTERNAL ISC_STATUS isc_Init_ARIA_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, int enc);
/*!
* \brief
* ARIA 초기 함수
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
* -# isc_Init_ARIA_Key() 출력 에러
* -# ISC_Crypto_Initialize()의 에러코드
* -# L_ARIA^ISC_F_INIT_ARIA^ISC_ERR_INIT_FAILURE : 초기화 실패
* \remarks
* iv값과 key값에 따라 함수 실행
*/
ISC_INTERNAL ISC_STATUS isc_Init_ARIA(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* 한 블럭 128bit를 암호화하는 ARIA 알고리즘
* \param in
* 평문 한 블럭
* \param out
* 암호문 한 블럭
* \param key
* 암호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
* \remarks
* ISC_ARIA_KEY key에 저장되어 있는 rounds 변수에 따라 128, 192, 256모드에 맞춰 암호화
*/
ISC_INTERNAL void isc_ARIA_Encrypt_Block(const uint8 *in, uint8 *out, const ISC_ARIA_KEY *key);
/*!
* \brief
* 한 블럭 128bit를 복호화하는 ARIA 알고리즘
* \param in
* 암호문 한 블럭
* \param out
* 평문 한 블럭
* \param key
* 복호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
* \remarks
* ISC_ARIA_KEY key에 저장되어 있는 rounds 변수에 따라 128, 192, 256모드에 맞춰 복호화
*/
ISC_INTERNAL void isc_ARIA_Decrypt_Block(const uint8 *in, uint8 *out, const ISC_ARIA_KEY *key);

/*!
* \brief
* ARIA ECB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CBC모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA OFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CBC^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CFBR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param nbits
* 입력길이 비트수(ex:CFB1->1, CFB16->16)
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* ARIA CFB1모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이(bit 길이)
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CFB8모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CFB16모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CFB32모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CFB64모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFB64(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* ARIA CTR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CTR^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_GCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_ARIA_H */

