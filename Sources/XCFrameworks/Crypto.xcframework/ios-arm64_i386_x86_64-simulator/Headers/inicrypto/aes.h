/*!
* \file aes.h
* \brief AES 알고리즘(Fips 197)

평문 128, 암호문 128bits, 키 128,192,256 bits\n

* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_AES_H
#define HEADER_AES_H

#include "foundation.h"
#include "mem.h"
#include "blockcipher_mac.h"

#ifdef ISC_NO_AES
#error AES is disabled.
#endif

#define ISC_AES_ENCRYPT	ISC_ENCRYPTION		/*!< AES의 암호화*/
#define ISC_AES_DECRYPT	ISC_DECRYPTION		/*!< AES의 복호화*/


#define ISC_AES_BLOCK_SIZE 16			/*!< AES의 BLOCK_SIZE*/

/*--------------------------------------------------*/
#define ISC_AES128_NAME				"AES_128"			
#define ISC_AES128_BLOCK_SIZE		ISC_AES_BLOCK_SIZE		
#define ISC_AES128_KEY_SIZE			16					
#define ISC_AES128_IV_SIZE			ISC_AES_BLOCK_SIZE		
#define ISC_AES128_INIT				isc_Init_AES			
#define ISC_AES128_ECB_DO			isc_Do_AES_ECB			
#define ISC_AES128_CBC_DO			isc_Do_AES_CBC			
#define ISC_AES128_CFB_DO			isc_Do_AES_CFB	
#define ISC_AES128_CFB1_DO			isc_Do_AES_CFB1
#define ISC_AES128_CFB8_DO			isc_Do_AES_CFB8
#define ISC_AES128_CFB16_DO			isc_Do_AES_CFB16
#define ISC_AES128_CFB32_DO			isc_Do_AES_CFB32
#define ISC_AES128_CFB64_DO			isc_Do_AES_CFB64
#define ISC_AES128_OFB_DO			isc_Do_AES_OFB			
#define ISC_AES128_CTR_DO			isc_Do_AES_CTR
#define ISC_AES128_CCM_DO           isc_Do_AES_CCM
#define ISC_AES128_GCM_DO           isc_Do_AES_GCM
#define ISC_AES128_FPE_DO			isc_Do_AES_FPE
#define ISC_AES128_FPE_ASCII_DO		isc_Do_AES_FPE_ASCII
#define ISC_AES128_FPE_ENG_DO		isc_Do_AES_FPE_ENG
#define ISC_AES128_FPE_NUM_DO		isc_Do_AES_FPE_NUM
#define ISC_AES128_FPE_ASCII_NUM_DO	isc_Do_AES_FPE_ASCII_NUM
#define ISC_AES128_OPE_DO			isc_Do_AES_OPE
#define ISC_AES128_ST_SIZE			sizeof(ISC_AES_KEY)		
/*--------------------------------------------------*/
#define ISC_AES192_NAME				"AES_192"			
#define ISC_AES192_BLOCK_SIZE		ISC_AES_BLOCK_SIZE		
#define ISC_AES192_KEY_SIZE			24					
#define ISC_AES192_IV_SIZE			ISC_AES_BLOCK_SIZE		
#define ISC_AES192_INIT				isc_Init_AES			
#define ISC_AES192_ECB_DO			isc_Do_AES_ECB			
#define ISC_AES192_CBC_DO			isc_Do_AES_CBC			
#define ISC_AES192_CFB_DO			isc_Do_AES_CFB	
#define ISC_AES192_CFB1_DO			isc_Do_AES_CFB1
#define ISC_AES192_CFB8_DO			isc_Do_AES_CFB8
#define ISC_AES192_CFB16_DO			isc_Do_AES_CFB16
#define ISC_AES192_CFB32_DO			isc_Do_AES_CFB32
#define ISC_AES192_CFB64_DO			isc_Do_AES_CFB64
#define ISC_AES192_OFB_DO			isc_Do_AES_OFB			
#define ISC_AES192_CTR_DO			isc_Do_AES_CTR
#define ISC_AES192_CCM_DO           isc_Do_AES_CCM
#define ISC_AES192_GCM_DO           isc_Do_AES_GCM
#define ISC_AES192_OPE_DO			isc_Do_AES_OPE
#define ISC_AES192_ST_SIZE			sizeof(ISC_AES_KEY)		
/*--------------------------------------------------*/
#define ISC_AES256_NAME				"AES_256"			
#define ISC_AES256_BLOCK_SIZE		ISC_AES_BLOCK_SIZE		
#define ISC_AES256_KEY_SIZE			32					
#define ISC_AES256_IV_SIZE			ISC_AES_BLOCK_SIZE		
#define ISC_AES256_INIT				isc_Init_AES			
#define ISC_AES256_ECB_DO			isc_Do_AES_ECB			
#define ISC_AES256_CBC_DO			isc_Do_AES_CBC			
#define ISC_AES256_CFB_DO			isc_Do_AES_CFB	
#define ISC_AES256_CFB1_DO			isc_Do_AES_CFB1
#define ISC_AES256_CFB8_DO			isc_Do_AES_CFB8
#define ISC_AES256_CFB16_DO			isc_Do_AES_CFB16
#define ISC_AES256_CFB32_DO			isc_Do_AES_CFB32
#define ISC_AES256_CFB64_DO			isc_Do_AES_CFB64
#define ISC_AES256_OFB_DO			isc_Do_AES_OFB			
#define ISC_AES256_CTR_DO			isc_Do_AES_CTR
#define ISC_AES256_CCM_DO           isc_Do_AES_CCM
#define ISC_AES256_GCM_DO           isc_Do_AES_GCM
#define ISC_AES256_OPE_DO			isc_Do_AES_OPE
#define ISC_AES256_ST_SIZE			sizeof(ISC_AES_KEY)		
/*--------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * AES의 키에 쓰이는 정보를 다룰 구조체
 * \remarks
 * roundKey(암호화키), rounds(라운스 횟수 저장변수)
 */
struct isc_aes_key_st {
	uint32 roundKey[60];
	int rounds;
};

typedef struct isc_aes_key_st ISC_AES_KEY;

#define ISC_MIX(temp) (E_Table4_3[ISC_BYTE(temp, 2)]) ^ (E_Table4_2[ISC_BYTE(temp, 1)]) ^  (E_Table4_1[ISC_BYTE(temp, 0)]) ^  (E_Table4_0[ISC_BYTE(temp, 3)])
#define ISC_E_ROLL(x0,x1,x2,x3,rk_i) E_Table0[x0>>24] ^ E_Table1[(x1>>16) & 0xff] ^ E_Table2[(x2>>8) & 0xff] ^ E_Table3[x3 & 0xff] ^ rk[rk_i]
#define ISC_D_ROLL(x0,x1,x2,x3,rk_i) D_Table0[x0>>24] ^ D_Table1[(x3>>16) & 0xff] ^ D_Table2[(x2>>8) & 0xff] ^ D_Table3[x1 & 0xff] ^ rk[rk_i]

/*!
* \brief
* AES에서 쓰이는 각 단계의 키를 만드는 함수(암호화시)
* \param userKey
* 초기 키값
* \param bits
* 키의 bit 사이즈
* \param key
* 키의 정보를 담고 있는 구조체 변수
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
* \remarks
* Key값은 128, 192, 그리고 256비트를 지원.
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_AES_Key(const uint8 *userKey, const int bits, ISC_AES_KEY *key);

/*!
* \brief
* AES에서 쓰이는 각 단계의 키를 만드는 함수(복호화시)
* \param userKey
* 초기 키값
* \param bits
* 키의 bit 사이즈
* \param key
* 키의 정보를 담고 있는 구조체 변수
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
* \remarks
* Key값은 128, 192, 그리고 256비트를 지원.
*/
ISC_INTERNAL ISC_STATUS isc_Init_Decrypt_AES_Key(const uint8 *userKey, const int bits, ISC_AES_KEY *key);

/*!
* \brief
* 한 블럭 128bit를 암호화하는 AES 알고리즘
* \param in
* 평문 한 블럭
* \param out
* 암호문 한 블럭
* \param key
* 암호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
* \remarks
* ISC_AES_KEY key에 저장되어 있는 rounds 변수에 따라 128, 192, 256모드에 맞춰 암호화
*/
ISC_INTERNAL void isc_AES_Encrypt_Block(const uint8 *in, uint8 *out, const ISC_AES_KEY *key);
/*!
* \brief
* 한 블럭 128bit를 복호화하는 AES 알고리즘
* \param in
* 암호문 한 블럭
* \param out
* 평문 한 블럭
* \param key
* 암호화 할때 쓰일 키값이 저장되어 있는 구조체 변수
* \remarks
* ISC_AES_KEY key에 저장되어 있는 rounds 변수에 따라 128, 192, 256모드에 맞춰 암호화
*/
ISC_INTERNAL void isc_AES_Decrypt_Block(const uint8 *in, uint8 *out, const ISC_AES_KEY *key);

/*!
* \brief
* AES 초기 키 설정 함수
* \param unit
* ISC_BLOCK_CIPHER_UNIT 구조체
* \param key
* 초기 키값
* \param enc
* 1이면 encrypt모드, 0이면 decrypt모드
* \returns
* -# ISC_SUCCESS : Success
* -# L_AES^ISC_F_INIT_AES_KEY^ISC_ERR_INIT_KEY_FAILURE : 초기 키 생성 실패
* \remarks
* enc 변수값에 따라서 isc_Init_Encrypt_AES_Key와 isc_Init_Decrypt_AES_Key를 실행
*/
ISC_INTERNAL ISC_STATUS isc_Init_AES_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, int enc);
/*!
* \brief
* AES 초기 함수
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
* -# ISC_L_AES_INTERFACE^ISC_F_INIT_AES^ISC_ERR_INIT_KEY_FAILURE : 초기화에 실패
* \remarks
* iv값과 key값에 따라 함수 실행
*/
ISC_INTERNAL ISC_STATUS isc_Init_AES(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* AES ECB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_AES^ISC_F_DO_AES_ECB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CBC모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_AES^ISC_F_DO_AES_CBC^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CFBR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT 구조체
* \param out
* 암호문
* \param in
* 평문
* \param nbits
* 입력길이 비트수(ex:CFB1->1, CFB16->16)
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* AES CFB1모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이(bit 길이)
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CFB8모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CFB16모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CFB32모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CFB64모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFB64(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES OFB모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_AES^ISC_F_DO_AES_OFB^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CTR모드
* \param unit
* 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 ISC_BLOCK_CIPHER_UNIT 구조체
* \param out
* 암호문
* \param in
* 평문
* \param inl
* 입력 길이
* \returns
* -# L_AES^ISC_F_DO_AES_CTR^ISC_ERR_INVALID_INPUT : 초기 파라미터 오류
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
 * \brief
 * AES OPE 모드(DB보안팀에서 사용, 순서보존암호모드)
 * \param unit
 * 암/복호화시 사용되는 여러 관련 매개변수를 포함하는 BLOCK_CIPHER_UNIT 구조체
 * \param out
 * 암호문 
 * \param in
 * 평문
 * \param inl
 * 입력 길이
 * \returns
 * -# L_AES^F_DO_AES_CTR^ERR_INVALID_INPUT : 초기 파라미터 오류
 * -# INI_SUCCESS : Success
 */
ISC_INTERNAL ISC_STATUS isc_Do_AES_OPE(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

ISC_INTERNAL ISC_STATUS isc_Do_AES_FPE(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_AES_FPE_ASCII(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_AES_FPE_ENG(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_AES_FPE_NUM(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_AES_FPE_ASCII_NUM(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

ISC_INTERNAL ISC_STATUS isc_Do_AES_CCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_AES_GCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
#ifdef  __cplusplus
}
#endif

#endif /* !HEADER_AES_H */


