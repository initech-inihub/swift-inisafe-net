/*!
* \file rc2.h
* \brief RC2 알고리즘
* 평문 64bits, 암호문 64bits, 키 128bits\n
* \remarks
* RC2는 32bit OS를 기반으로 설계, round수는 12로 기본설정
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_RC2_H
#define HEADER_RC2_H

#include "foundation.h"
#include "mem.h"

#ifdef ISC_NO_RC2
#error RC2 is disabled.
#endif

#define ISC_RC2_ENCRYPT	1			/*!< RC2의 암호화*/
#define ISC_RC2_DECRYPT	0			/*!< RC2의 복호화*/

#define ISC_RC2_BLOCK_SIZE	8				

/*--------------------------------------------------*/
#define ISC_RC2_40_NAME					"ISC_RC2_40"
#define ISC_RC2_40_BLOCK_SIZE			8
#define ISC_RC2_40_KEY_SIZE				5
#define ISC_RC2_40_IV_SIZE				ISC_RC2_40_BLOCK_SIZE		
#define ISC_RC2_40_INIT					isc_Init_RC2			
#define ISC_RC2_40_ECB_DO				isc_Do_RC2_ECB			
#define ISC_RC2_40_CBC_DO				isc_Do_RC2_CBC			
#define ISC_RC2_40_CFB_DO				isc_Do_RC2_CFB			
#define ISC_RC2_40_CFB1_DO				isc_Do_RC2_CFB1		
#define ISC_RC2_40_CFB8_DO				isc_Do_RC2_CFB8		
#define ISC_RC2_40_CFB16_DO				isc_Do_RC2_CFB16		
#define ISC_RC2_40_CFB32_DO				isc_Do_RC2_CFB32		
#define ISC_RC2_40_OFB_DO				isc_Do_RC2_OFB			
#define ISC_RC2_40_ST_SIZE				sizeof(ISC_RC2_KEY)	
/*--------------------------------------------------*/

/*--------------------------------------------------*/
#define ISC_RC2_64_NAME					"ISC_RC2_64"
#define ISC_RC2_64_BLOCK_SIZE			8
#define ISC_RC2_64_KEY_SIZE				8
#define ISC_RC2_64_IV_SIZE				ISC_RC2_64_BLOCK_SIZE		
#define ISC_RC2_64_INIT					isc_Init_RC2			
#define ISC_RC2_64_ECB_DO				isc_Do_RC2_ECB			
#define ISC_RC2_64_CBC_DO				isc_Do_RC2_CBC			
#define ISC_RC2_64_CFB_DO				isc_Do_RC2_CFB	
#define ISC_RC2_64_CFB1_DO				isc_Do_RC2_CFB1		
#define ISC_RC2_64_CFB8_DO				isc_Do_RC2_CFB8		
#define ISC_RC2_64_CFB16_DO				isc_Do_RC2_CFB16		
#define ISC_RC2_64_CFB32_DO				isc_Do_RC2_CFB32	
#define ISC_RC2_64_OFB_DO				isc_Do_RC2_OFB			
#define ISC_RC2_64_ST_SIZE				sizeof(ISC_RC2_KEY)	
/*--------------------------------------------------*/

/*--------------------------------------------------*/
#define ISC_RC2_128_NAME				"ISC_RC2_128"
#define ISC_RC2_128_BLOCK_SIZE			8
#define ISC_RC2_128_KEY_SIZE			16
#define ISC_RC2_128_IV_SIZE				ISC_RC2_128_BLOCK_SIZE		
#define ISC_RC2_128_INIT				isc_Init_RC2			
#define ISC_RC2_128_ECB_DO				isc_Do_RC2_ECB			
#define ISC_RC2_128_CBC_DO				isc_Do_RC2_CBC			
#define ISC_RC2_128_CFB_DO				isc_Do_RC2_CFB	
#define ISC_RC2_128_CFB1_DO				isc_Do_RC2_CFB1		
#define ISC_RC2_128_CFB8_DO				isc_Do_RC2_CFB8		
#define ISC_RC2_128_CFB16_DO			isc_Do_RC2_CFB16		
#define ISC_RC2_128_CFB32_DO			isc_Do_RC2_CFB32	
#define ISC_RC2_128_OFB_DO				isc_Do_RC2_OFB			
#define ISC_RC2_128_ST_SIZE				sizeof(ISC_RC2_KEY)	
/*--------------------------------------------------*/


#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * RC2의 키에 쓰이는 정보를 다룰 구조체
 * \remarks
 * K(키), R(라운드수), RC2 K생성을 위한 eff_keybit,eff_keybyte,eff_keym
 */
struct isc_rc2_key_st {
	uint16 K[64];
	size_t eff_keybit;
	size_t eff_keybyte;
	size_t eff_keym;
	uint16 *R;
} ;

typedef struct isc_rc2_key_st ISC_RC2_KEY;

/*!
* \brief
* RC2에서 쓰이는 각 단계의 키를 만드는 함수
* \param data
* 초기 키값
* \param len
* 키의 bit 사이즈
* \param key
* 키의 정보를 담고 있는 구조체 변수
* \param bit
* 블럭사이즈
* \returns
* -# INI_CRYPT_SUCCESS : Success
* -# INI_CRYPT_FAIL : Fail
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_RC2_Key(size_t eff_keylen, const uint8 *data, int len, ISC_RC2_KEY *key);

/*!
* \brief
* RC2에서 쓰이는 각 단계의 키를 만드는 함수
* \param data
* 초기 키값
* \param len
* 키의 bit 사이즈
* \param key
* 키의 정보를 담고 있는 구조체 변수
* \param bit
* RC2 블럭 사이즈
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_INTERNAL ISC_STATUS isc_Init_RC2_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key);

/*!
* \brief
* RC2 초기 함수
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
* -# isc_Init_encrypto_RC2_KEY의 에러
*  -# L_RC2^ISC_F_INIT_RC2_KEY^ISC_ERR_INIT_KEY_FAILURE : 초기 키 생성 실패
* \remarks
* iv값과 key값에 따라 함수 실행
*/
ISC_INTERNAL ISC_STATUS isc_Init_RC2(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* 한 블럭 64bit를 암호화하는 RC2 알고리즘
* \param in_out
* 평문 한 블럭, 출력값이 다시 저장.
* \param key
* 암호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
*/
ISC_INTERNAL void isc_RC2_Encrypt_Block(uint16 *in_out, ISC_RC2_KEY *key);

/*!
* \brief
* 한 블럭 64bit를 복호화하는 RC2 알고리즘
* \param in_out
* 암호문 한 블럭, 출력값이 다시 저장.
* \param key
* 복호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
*/
ISC_INTERNAL void isc_RC2_Decrypt_Block(uint16 *in_out, ISC_RC2_KEY *key);

/*!
* \brief
* RC2 ECB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 CBC모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 CFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 CFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param nbits
* 입력길이 비트수(ex:CFB1->1, CFB16->16)
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* RC2 CFB1모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이(bit 길이)
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 CFB8모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 CFB16모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 CFB32모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 OFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_RC2_H */

