/*!
* \file blockcipher.h
* \brief
* 각 알고리즘의 인터페이스 관리
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_BLOCKCIHPER_H
#define HEADER_BLOCKCIHPER_H

#include "foundation.h"
#include "mem.h"

#define ISC_IV_MAX_LENGTH			16
#define ISC_BLOCK_MAX_LENGTH		32
#define ISC_ADVANCED_BLOCK_CIPHER_MAX_ROUND_KEY		788
#define ISC_ADVANCED_BLOCK_CIPHER_KEY_SIZE			ISC_ADVANCED_BLOCK_CIPHER_MAX_ROUND_KEY + 112

#define ISC_DECRYPTION		0			/*!< 복호화 */
#define ISC_ENCRYPTION		1			/*!< 암호화 */

/* Flag Definition
|---------------------------------------------------------------|
|-------------Cipher Identification-------------|--PAD--|--MOD--|
| 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits |
|---------------------------------------------------------------| */
#define ISC_OPERATION_MASK	0xFE
#define ISC_MODE_ECB		0x00				/*!< ECB MODE*/
#define ISC_MODE_CBC		0x20				/*!< CBC MODE*/
#define ISC_MODE_CFB		0x40				/*!< CFB MODE*/
#define ISC_MODE_CFB1		0x42				/*!< CFB1 MODE*/
#define ISC_MODE_CFB8		0x44				/*!< CFB8 MODE*/
#define ISC_MODE_CFB16		0x46				/*!< CFB16 MODE*/
#define ISC_MODE_CFB32		0x48				/*!< CFB32 MODE*/	
#define ISC_MODE_CFB64		0x4A				/*!< CFB64 MODE*/
#define ISC_MODE_CFB128		0x4C				/*!< CFB128 MODE*/
#define ISC_MODE_OFB		0x60				/*!< OFB MODE*/
#define ISC_MODE_CTR		0x80				/*!< CTR MODE*/
#define ISC_MODE_FPE		0x90				/*!< FPE MODE*/
#define ISC_MODE_FPE_ASCII	0x92				/*!< FPE ANCII MODE*/
#define ISC_MODE_FPE_NUM	0x94				/*!< FPE NUM MODE*/
#define ISC_MODE_FPE_ENG	0x96				/*!< FPE ENG MODE*/
#define ISC_MODE_FPE_ASCII_NUM	0x98			/*!< FPE ASCII NUM MODE*/
#define ISC_MODE_OPE		0xA0				/*!< OPE MODE*/

#define ISC_MODE_CCM		0xB0                /*!< CCM MODE */
#define ISC_MODE_GCM		0xC0				/*!< GCM MODE */
#define ISC_NO_PADDING		0x01				/*!< ISC_NO_PADDING MODE*/
#ifdef ISC_PKCS5_PADDING
#undef ISC_PKCS5_PADDING
#endif
#define ISC_PKCS5_PADDING	0x00 				/*!< ISC_PKCS5_PADDING MODE*/ 

/*---------------------------------------------------------------------------------*/
#define ISC_ALGORITHM_MASK	0xFFFFFF00

/*AES Alias				0x01000000 ------------------------------------------------ */
#define ISC_AES128			0x01000100				/*!< AES 128bit 알고리즘 ID*/
#define ISC_AES192			0x01000200				/*!< AES 192bit 알고리즘 ID*/
#define ISC_AES256			0x01000300				/*!< AES 256bit 알고리즘 ID*/

/*ISC_DES Alias				0x02000000 ------------------------------------------------ */
#define ISC_DES				0x02000100				/*!< ISC_DES 알고리즘 ID*/
#define ISC_DES_EDE			0x02000200				/*!< Triple ISC_DES 알고리즘 ID (3-Key)*/
#define ISC_DES_EDE_2KEY	0x02001200				/*!< 2Key Triple ISC_DES 알고리즘 ID*/
#define ISC_DES_EDE_3KEY	0x02010200				/*!< 3Key Triple ISC_DES 알고리즘 ID*/

/*ARIA Alias			0x03000000 ------------------------------------------------*/
#define ISC_ARIA128			0x03000100				/*!< ARIA 128bit 알고리즘 ID*/
#define ISC_ARIA192			0x03000200				/*!< ARIA 192bit 알고리즘 ID*/
#define ISC_ARIA256			0x03000300				/*!< ARIA 256bit 알고리즘 ID*/

/*ISC_SEED Alias			0x04000000 ------------------------------------------------*/
#define ISC_SEED			0x04000100				/*!< ISC_SEED 128bit 알고리즘 ID*/
#define ISC_SEED256			0x04000200				/*!< ISC_SEED 256bit 알고리즘 ID*/
/*---------------------------------------------------------------------------------*/

/*ISC_RC5 Alias				0x05000000 ------------------------------------------------*/
#define ISC_RC5				0x05000100					/*!< ISC_RC5 알고리즘 ID*/
/*---------------------------------------------------------------------------------*/

/*BlowFish Alias		0x06000000 ------------------------------------------------*/
#define ISC_BF				0x06000100					/*!< BlowFish 알고리즘 ID*/
/*---------------------------------------------------------------------------------*/

/*RC2 Alias				0x07000000 ------------------------------------------------*/
#define ISC_RC2_128			0x07000100					/*!< RC2 128bit 알고리즘 ID*/
#define ISC_RC2_40			0x07000200					/*!< RC2 40bit 알고리즘 ID*/
#define ISC_RC2_64			0x07000300					/*!< RC2 64bit알고리즘 ID*/
/*---------------------------------------------------------------------------------*/

/*LEA Alias				0x08000000 ------------------------------------------------ */
#define ISC_LEA128			0x08000100				/*!< LEA 128bit 알고리즘 ID*/
#define ISC_LEA192			0x08000200				/*!< LEA 192bit 알고리즘 ID*/
#define ISC_LEA256			0x08000300				/*!< LEA 256bit 알고리즘 ID*/

/*---------------------------------------------------------------------------------*/
#define ISC_AES_PROVEN_MODE			0    /*!<  0: 비검증 모드, 1: 검증모드 */ 
#define ISC_DES_PROVEN_MODE			0    /*!<  0: 비검증 모드, 1: 검증모드 */
#define ISC_ARIA_PROVEN_MODE		1    /*!<  0: 비검증 모드, 1: 검증모드 */
#define ISC_SEED_PROVEN_MODE		1    /*!<  0: 비검증 모드, 1: 검증모드 */
#define ISC_RC5_PROVEN_MODE			0    /*!<  0: 비검증 모드, 1: 검증모드 */
#define ISC_BF_PROVEN_MODE			0    /*!<  0: 비검증 모드, 1: 검증모드 */

#define ISC_ECB_MODE_PROVEN_MODE    1    /*!<  0: 비검증 모드, 1: 검증모드 */
#define ISC_CBC_MODE_PROVEN_MODE    1    /*!<  0: 비검증 모드, 1: 검증모드 */
#define ISC_CFB_MODE_PROVEN_MODE    1    /*!<  0: 비검증 모드, 1: 검증모드 */
#define ISC_OFB_MODE_PROVEN_MODE    1    /*!<  0: 비검증 모드, 1: 검증모드 */
#define ISC_CTR_MODE_PROVEN_MODE    0    /*!<  0: 비검증 모드, 1: 검증모드 */
#define ISC_FPE_MODE_PROVEN_MODE    0    /*!<  0: 비검증 모드, 1: 검증모드 */
#define ISC_OPE_MODE_PROVEN_MODE    0    /*!<  0: 비검증 모드, 1: 검증모드 */
/*---------------------------------------------------------------------------------*/

#define ISC_DEFINE_BLOCK_CIPHER(cipher, op_mode);\
	unit->block_size=cipher##_BLOCK_SIZE;\
	unit->key_len=cipher##_KEY_SIZE;\
	unit->iv_len=cipher##_IV_SIZE;\
	unit->mode=ISC_MODE##_##op_mode;\
	unit->st_size=cipher##_ST_SIZE;\
	unit->init=(int (*)(ISC_BLOCK_CIPHER_UNIT*,const uint8*,const uint8*,int)) cipher##_INIT;\
	unit->operate=(int (*)(ISC_BLOCK_CIPHER_UNIT*,uint8*,const uint8*,uint32)) cipher##_##op_mode##_DO;\
	unit->key_st=NULL;

#define ISC_BLOCK_XOR(pbDst, phSrc1, phSrc2) {        \
	((uint8 *)(pbDst))[0] = ((uint8 *)(phSrc1))[0]    \
	^ ((uint8 *)(phSrc2))[0];   \
	((uint8 *)(pbDst))[1] = ((uint8 *)(phSrc1))[1]    \
	^ ((uint8 *)(phSrc2))[1];   \
	((uint8 *)(pbDst))[2] = ((uint8 *)(phSrc1))[2]    \
	^ ((uint8 *)(phSrc2))[2];   \
	((uint8 *)(pbDst))[3] = ((uint8 *)(phSrc1))[3]    \
	^ ((uint8 *)(phSrc2))[3];   \
	((uint8 *)(pbDst))[4] = ((uint8 *)(phSrc1))[4]    \
	^ ((uint8 *)(phSrc2))[4];   \
	((uint8 *)(pbDst))[5] = ((uint8 *)(phSrc1))[5]    \
	^ ((uint8 *)(phSrc2))[5];   \
	((uint8 *)(pbDst))[6] = ((uint8 *)(phSrc1))[6]    \
	^ ((uint8 *)(phSrc2))[6];   \
	((uint8 *)(pbDst))[7] = ((uint8 *)(phSrc1))[7]    \
	^ ((uint8 *)(phSrc2))[7];   \
	((uint8 *)(pbDst))[8] = ((uint8 *)(phSrc1))[8]    \
	^ ((uint8 *)(phSrc2))[8];   \
	((uint8 *)(pbDst))[9] = ((uint8 *)(phSrc1))[9]    \
	^ ((uint8 *)(phSrc2))[9];   \
	((uint8 *)(pbDst))[10] = ((uint8 *)(phSrc1))[10]    \
	^ ((uint8 *)(phSrc2))[10];   \
	((uint8 *)(pbDst))[11] = ((uint8 *)(phSrc1))[11]    \
	^ ((uint8 *)(phSrc2))[11];   \
	((uint8 *)(pbDst))[12] = ((uint8 *)(phSrc1))[12]    \
	^ ((uint8 *)(phSrc2))[12];   \
	((uint8 *)(pbDst))[13] = ((uint8 *)(phSrc1))[13]    \
	^ ((uint8 *)(phSrc2))[13];   \
	((uint8 *)(pbDst))[14] = ((uint8 *)(phSrc1))[14]    \
	^ ((uint8 *)(phSrc2))[14];   \
	((uint8 *)(pbDst))[15] = ((uint8 *)(phSrc1))[15]    \
	^ ((uint8 *)(phSrc2))[15];}\


#define ISC_BLOCK_RSHIFT_1(v)						\
	(v)[15] = ((v)[15] >> 1) | ((v)[14] << 7),		\
	(v)[14] = ((v)[14] >> 1) | ((v)[13] << 7),		\
	(v)[13] = ((v)[13] >> 1) | ((v)[12] << 7),		\
	(v)[12] = ((v)[12] >> 1) | ((v)[11] << 7),		\
	(v)[11] = ((v)[11] >> 1) | ((v)[10] << 7),		\
	(v)[10] = ((v)[10] >> 1) | ((v)[ 9] << 7),		\
	(v)[ 9] = ((v)[ 9] >> 1) | ((v)[ 8] << 7),		\
	(v)[ 8] = ((v)[ 8] >> 1) | ((v)[ 7] << 7),		\
	(v)[ 7] = ((v)[ 7] >> 1) | ((v)[ 6] << 7),		\
	(v)[ 6] = ((v)[ 6] >> 1) | ((v)[ 5] << 7),		\
	(v)[ 5] = ((v)[ 5] >> 1) | ((v)[ 4] << 7),		\
	(v)[ 4] = ((v)[ 4] >> 1) | ((v)[ 3] << 7),		\
	(v)[ 3] = ((v)[ 3] >> 1) | ((v)[ 2] << 7),		\
	(v)[ 2] = ((v)[ 2] >> 1) | ((v)[ 1] << 7),		\
	(v)[ 1] = ((v)[ 1] >> 1) | ((v)[ 0] << 7),		\
	(v)[ 0] = ((v)[ 0] >> 1)

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* Block cipher에 대한 정보를 갖고 있는 구조체
*/
struct isc_block_cipher_unit_st
{
	uint32 algorithm;				 /**< 암호화 알고리즘*/
	int block_size;				 /**< 단위 블럭의 길이 */
	int key_len;			     /**< 키의 길이 */
	int iv_len;				     /**<초기벡터의 길이 */
	size_t effective_key_len;		/**rc2를 지원하기 위해 */
	uint8 mode;			         /**< 운영모드 CBC, ECB, CFB, OFB */
	uint8 padding;				 /**<패딩의 여부; padding을 원치않을 경우 ISC_NO_PADDING */
	int (*init)(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key,const uint8 *iv, int enc); /**< 설정 알고리즘에 맞는 초기화 함수*/
	int (*operate)(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out,const uint8 *in, uint32 inl); /**< 설정 알고리즘에 맞는 운영 함수*/
	int encrypt;				 /**< 암호화(1)과 복호화(0)*/
	uint8  ivec[ISC_IV_MAX_LENGTH];				 /**< 초기벡터 배열*/
	uint8  active_ivec [ISC_IV_MAX_LENGTH];				 /**< 운영모드 단계에서 적용되는 벡터 값*/
	uint8  buf[ISC_BLOCK_MAX_LENGTH];				 /**< buf 배열*/
	uint8  ctr_buf[ISC_BLOCK_MAX_LENGTH];				 /**< ctr mode buf 배열*/
	int buf_len;				 /**< buf의 길이*/
	int count;					 /**< OFB / CFB count*/
	void *key_st;				 /**< 암호 알고리즘시 사용되는 key*/ 
	int st_size;				 /**< key_st의 사이즈*/
	int final_used;				 /**< final check*/
	int block_mask;				 /**< block mask*/
	uint8 final[ISC_BLOCK_MAX_LENGTH];					 /**< 최종블럭 버퍼*/
	int unit_status;
	uint8 isproven;			     /*!< 암호화 검증에 사용된 알고리즘만 제한 여부 */
	uint8 block_num;			/**< 몇번째 블록인지 저장. fpe 모드를 지원하기 위해 추가*/	
	uint8 block_position;		/**< 블록내 위치. fpe 모드를 지원하기 위해 추가*/
};

struct isc_advanced_block_cipher_unit_st
{
	uint32 algorithm;				/**< 암호화 알고리즘*/
	int block_size;					/**< 단위 블럭의 길이 */
	int key_len;					/**< 키의 길이 */
	int iv_len;						/**<초기벡터의 길이 */
	size_t effective_key_len;		/**rc2를 지원하기 위해 */
	uint8 mode;						/**< 운영모드 CBC, ECB, CFB, OFB */
	uint8 padding;					/**<패딩의 여부; padding을 원치않을 경우 ISC_NO_PADDING */
	int (*init)(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key,const uint8 *iv, int enc); /**< 설정 알고리즘에 맞는 초기화 함수*/
	int (*operate)(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out,const uint8 *in, uint32 inl); /**< 설정 알고리즘에 맞는 운영 함수*/
	int encrypt;									/**< 암호화(1)과 복호화(0)*/
	uint8  ivec[ISC_IV_MAX_LENGTH];						/**< 초기벡터 배열*/
	uint8  active_ivec [ISC_IV_MAX_LENGTH];				 /**< 운영모드 단계에서 적용되는 벡터 값*/
	uint8 key_st[ISC_ADVANCED_BLOCK_CIPHER_MAX_ROUND_KEY];				 /**< 암호 알고리즘시 사용되는 key*/ 
	int st_size;					/**< key_st의 사이즈*/
	int final_used;					/**< final check*/
	int block_mask;					/**< block mask*/
	int unit_status;
	uint8 isproven;					/*!< 암호화 검증에 사용된 알고리즘만 제한 여부 */
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_BLOCK_CIPHER_UNIT 구조체의 초기화 함수
* \returns
* ISC_BLOCK_CIPHER_UNIT unit
*/
ISC_API ISC_BLOCK_CIPHER_UNIT *ISC_New_BLOCK_CIPHER_Unit(void);

/*!
* \brief
* ISC_BLOCK_CIPHER_UNIT 구조체를 리셋
* \param c
* 리셋할 ISC_BLOCK_CIPHER_UNIT 구조체
*/
ISC_API void ISC_Clean_BLOCK_CIPHER_Unit(ISC_BLOCK_CIPHER_UNIT *c);

/*!
* \brief
* ISC_BLOCK_CIPHER_UNIT 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(free)
*/
ISC_API void ISC_Free_BLOCK_CIPHER_Unit(ISC_BLOCK_CIPHER_UNIT *unit);

/*!
* \brief
* Block 알고리즘을 초기화하는 함수
* \param unit
* 알고리즘을 초기화 할 때 사용될 여러 값들(key_st, padding, num, ivec, init)
* \param cipher_id
* Test 소스에서 입력한 변수 (ex; ISC_AES128|ISC_MODE_CBC|ISC_NO_PADDING)
* \param key
* 초기 키값
* \param iv
* -# ECB모드 : 0
* -# CFB, OFB모드 : 초기벡터 생성 후 카운팅할 unit->num = 0으로 초기화
* -# CBC모드 : 초기벡터 생성 
* \param enc
* 0이면 Decryption, 그렇지 않으면 Encryption
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_INIT_FAILURE : 내부 초기화 함수 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_MALLOC : 동적 메모리 할당 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_INVALID_IV_LENGTH : 잘못된 IV 길이
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_NULL_IV_VALUE : IV값이 NULL
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에서 비검증 대상 알고리즘 사용 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_INVALID_OPERATION_MASK : 잘못된 운영모드 입력
*/
ISC_API ISC_STATUS ISC_Init_BLOCK_CIPHER(ISC_BLOCK_CIPHER_UNIT *unit, int cipher_id, const uint8 *key, const uint8 *iv, int enc);
ISC_INTERNAL ISC_STATUS isc_Init_BLOCK_CIPHER_Ex(ISC_BLOCK_CIPHER_UNIT *unit, int cipher_id, const uint8 *key, const uint8 *iv, int enc, uint8 ivlen, uint8 *adata, uint32 alen, uint8 tlen);

/*!
* \brief
* Block 알고리즘을 실행하는 함수(Enc, Dec의 여부 확인)
* \param unit
* 알고리즘을 초기화 할 때 저장되어 함수 운영시 사용될 여러 값들(key_st, padding, num, ivec, init)
* \param out
* 알고리즘 수행 결과 얻게 되는 암호문 블럭 (혹은 평문 블럭)
* \param outl
* 암호문 블럭(혹은 평문 블럭)의 길이
* \param in
* 알고리즘을 수행하기 위해 입력하는 평문 블럭 (혹은 암호문 블럭)
* \param inl
* 평문 블럭(혹은 암호문 블럭)의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_BLOCKCIPHER^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_OPERATE_FUNCTION : 암호화 or 복호화 알고리즘 수행중 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_CIPHER_ENCRYPT_FAILURE : UPDATE BLOCKCIPHER 암호화 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_DECRYPTION^ISC_ERR_CIPHER_DECRYPT_FAILURE : UPDATE BLOCKCIPHER 복호화 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_DECRYPTION^ISC_ERR_UPDATE_FAILURE : UPDATE BLOCKCIPHER 복호화 실패
* \remarks
* unit->encrypt가 0이면 updateDecryption함수, 그렇지 않으면 updateEncryption함수 실행
*/
ISC_API ISC_STATUS ISC_Update_BLOCK_CIPHER(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl, const uint8 *in, int inl);

/*!
* \brief
* Block 알고리즘을 출력하는 함수
* \param unit
* 알고리즘을 초기화 할 때 저장되어 함수 운영시 사용될 여러 값들(key_st, padding, num, ivec, init)
* \param out
* 알고리즘 수행 결과 얻게 되는 암호문 블럭 (혹은 평문 블럭)
* \param outl
* 암호문 블럭(혹은 평문 블럭)의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_BLOCKCIPHER^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_BLOCKCIPHER^ISC_ERR_CIPHER_ENCRYPT_FAILURE : FINAL BLOCKCIPHER 암호화 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_BLOCKCIPHER^ISC_ERR_CIPHER_DECRYPT_FAILURE : FINAL BLOCKCIPHER 복호화 실패
* \remarks
* unit->encrypt가 0이면 updateDecryption함수, 그렇지 않으면 updateEncryption함수 실행
*/
ISC_API ISC_STATUS ISC_Final_BLOCK_CIPHER(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl);
ISC_INTERNAL ISC_STATUS isc_Final_BLOCK_CIPHER_Ex(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl, uint8 *tag, int *tagl);

/*!
* \brief
* INIT, UPDATE, FINAL을 한번에 처리하는 BLOCK CIPHER 함수
* \param cipher_id
* 처음에 입력해주는 flag값
* \param enc
* ISC_ENCRYPTION, ISC_DECRYPTION
* \param key
* 처음 유저가 설정한 키값을 담은 배열
* \param iv
* 처음 유저가 설정한 초기벡터값을 담은 배열
* \param in
* 처음 유저가 설정한 평문값을 담은 배열
* \param inl
* 평문 배열의 길이
* \param out
* 출력값(암호문)을 담을 배열
* \param outl
* 출력값(암호문) 배열의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Init_BLOCK_CIPHER()의 에러 코드
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER^ISC_ERR_INIT_BLOCKCIPHER_FAIL : INIT BLOCKCIPHER 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER^ISC_ERR_UPDATE_BLOCKCIPHER_FAIL : UPDATE BLOCKCIPHER 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER^ISC_ERR_FINAL_BLOCKCIPHER_FAIL : FINAL BLOCKCIPHER 실패
*/
ISC_API ISC_STATUS ISC_BLOCK_CIPHER(int cipher_id, int enc,	const uint8 *key, const uint8 *iv, const uint8 *in, int inl, uint8 *out, int *outl);

/*!
* \brief
* Init, DoFinal 형식으로 사용하는 대칭키 초기화 함수
* \param cipher_id
* 대칭키 암호 알고리즘 입력
* \param key
* 처음 유저가 설정한 키값을 담은 배열
* \param iv
* 처음 유저가 설정한 초기벡터값을 담은 배열
* \param enc
* ISC_ENCRYPTION, ISC_DECRYPTION
* \param outKey
* 입력 : 라운드키의 주소값. 메모리 할당 해야함. (size : ISC_ADVANCED_BLOCK_CIPHER_KEY_SIZE). 출력 : 생성된 라운드 키의 출력값
* \param outKeyLen
* 입력 : outKey 의 메모리 크기, 출력 : 생성된 라운드 키의 출력 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_ADVANCED_BLOCKCIPHER^ISC_ERR_NULL_INPUT : NULL 데이터 입력
* -# LOCATION^ISC_F_INIT_ADVANCED_BLOCKCIPHER^ISC_ERR_INIT_BLOCKCIPHER_FAIL : INIT BLOCKCIPHER 실패
* -# LOCATION^ISC_F_INIT_ADVANCED_BLOCKCIPHER^ISC_ERR_BUF_TOO_SMALL : 전달된 outKey 크기가 복사할 데이터 크기 보다 작을때 실패
* -# LOCATION^ISC_F_INIT_ADVANCED_BLOCKCIPHER^ISC_ERR_SUB_OPERATION_FAILURE : 초기화 설정값 복사 실패
*/
ISC_API ISC_STATUS ISC_Init_Advanced_BLOCK_CIPHER(int cipher_id, const uint8 *key, const uint8 *iv, int enc, uint8* outKey, int *outKeyLen);

/*!
* \brief
* Init, DoFinal 형식으로 사용하는 대칭키 암복호화 함수
* \param binaryKey
* 암복호화에 사용될 라운드 키
* \param binaryKeyLen
* 암복호화에 사용될 라운드 키길이
* \param in
* 알고리즘을 수행하기 위해 입력하는 평문
* \param inl
* 평문의 길이
* \param out
* 알고리즘 수행 결과 얻게 되는 암호문 블럭
* \param outl
* 암호문 블럭의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_DO_FINAL_ADVANCED_BLOCKCIPHER^ISC_ERR_NULL_INPUT : NULL 데이터 입력
* -# LOCATION^ISC_F_DO_FINAL_ADVANCED_BLOCKCIPHER^ISC_ERR_SUB_OPERATION_FAILURE : 초기화 설정값 복사 실패
* -# LOCATION^ISC_F_DO_FINAL_ADVANCED_BLOCKCIPHER^ISC_ERR_UPDATE_BLOCKCIPHER_FAIL : UPDATE BLOCKCIPHER 실패
* -# LOCATION^ISC_F_DO_FINAL_ADVANCED_BLOCKCIPHER^ISC_ERR_FINAL_BLOCKCIPHER_FAIL : FINAL BLOCKCIPHER 실패
*/
ISC_API ISC_STATUS ISC_DoFinal_Advanced_BLOCK_CIPHER(uint8* binaryKey, int binaryKeyLen , const uint8 *in, int inl, uint8 *out, int *outl);

/*!
* \brief
* ISC_BLOCK_CIPHER_UNIT 구조체에서 algorithm_id를 얻기 위한 함수
* \param unit
* 알고리즘을 초기화 할 때 저장되어 함수 운영시 사용될 여러 값들(key_st, padding, num, ivec, init)
* \returns
* unit->algorithm
*/
ISC_API int ISC_Get_Block_Alg_ID(ISC_BLOCK_CIPHER_UNIT *unit);

/*!
* \brief
* algorithm_id에서 Block algorithm의 이름을 얻기 위한 함수
* \param algorithm_id
* 알아내고자 하는 algorithm_id 값
* \returns
* 해당 알고리즘의 이름 (ex. ISC_AES128_NAME)
* -# ISC_NULL_STRING : 이름 가져오기 실패
*/
ISC_API char* ISC_Get_Block_Alg_Name(int algorithm_id);

/*!
* \brief
* algorithm_id에서 Block 길이를 얻기 위한 함수
* \param algorithm_id
* 알아내고자 하는 algorithm_id 값
* \returns
* 해당 알고리즘 BLOCK의 길이 (ex. ISC_AES_BLOCK_SIZE, ISC_ARIA_BLOCK_SIZE)
* -# ISC_INVALID_SIZE : 블록 길이 가져오기 실패
*/
ISC_API int ISC_Get_Block_Length(int algorithm_id);

/*!
* \brief
* algorithm_id에서 Key 길이를 얻기 위한 함수
* \param algorithm_id
* 알아내고자 하는 algorithm_id 값
* \returns
* 해당 알고리즘 Key의 길이 (ex. ISC_AES128_KEY_SIZE, ISC_ARIA128_KEY_SIZE)
* -# ISC_INVALID_SIZE : 키 길이 가져오기 실패
*/
ISC_API int ISC_Get_Key_Length(int algorithm_id);

/*!
* \brief
* algorithm_id에서 초기벡터 크기를 얻기 위한 함수
* \param algorithm_id
* 알아내고자 하는 algorithm_id 값
* \returns
* 해당 알고리즘 초기벡터의 크기 (ex. ISC_AES_BLOCK_SIZE, ISC_ARIA_BLOCK_SIZE)
* -# ISC_INVALID_SIZE : IV 길이 가져오기 실패
* \remarks
* 초기벡터의 크기는 결국 해당 알고리즘의 블록 크기와 같음
*/
ISC_API int ISC_Get_IV_Length(int algorithm_id);

/*!
* \brief
* algorithm_id에서 Mode 이름을 얻기 위한 함수
* \param algorithm_id
* 알아내고자 하는 algorithm_id 값
* \returns
* 해당 알고리즘 Mode의 이름 (ex. "ECB", "CBC")
* -# ISC_NULL_STRING : 이름 가져오기 실패    
*/
ISC_API char* ISC_Get_Mode_Name(int algorithm_id);

/*!
* \brief
* mode에서 길이 shift 값을 얻기 위한 함수
* \param mode
* 알아내고자 하는 mode
* \returns
* 해당 알고리즘 Mode의 길이값
* -# ISC_INVALID_SIZE : 모드 길이 가져오기 실패
*/
ISC_INTERNAL int isc_Get_Mode_Length(ISC_BLOCK_CIPHER_UNIT *unit);

/*!
* \brief
* ISC_BLOCK_CIPHER_UNIT 구조체의 초기화 함수
* \param isproven 암호화 검증 모듈 제한 여부
* \returns
* ISC_BLOCK_CIPHER_UNIT unit
*/
ISC_INTERNAL ISC_BLOCK_CIPHER_UNIT *isc_New_BLOCK_CIPHER_Unit_Ex(uint8 isproven);

/*!
* \brief
* cipher_id에 서술된 알고리즘에 맞게 unit를 초기화
* \param unit
* 알고리즘을 초기화 할 때 사용될 여러 값들을 포함하는 ISC_BLOCK_CIPHER_UNIT
* \param cipher_id
* Test 소스에서 입력한 변수 (ex; ISC_AES128|ISC_MODE_CBC|ISC_NO_PADDING)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에서 비검증 대상 알고리즘 사용 실패 
* -# LOCATION^ISC_F_INIT_ALGORITHM^ISC_ERR_INVALID_ALGORITHM_ID : 입력된 알고리즘 ID 오류
* \remarks
* 각 알고리즘과 운영모드에 맞춰서 unit->init과 operate함수 설정
*/
ISC_INTERNAL ISC_STATUS isc_Init_Block_Alg(ISC_BLOCK_CIPHER_UNIT* unit, int cipher_id);

/*!
* \brief
* Block 알고리즘을 실제 실행하는 함수(Encrypt)
* \param unit
* 알고리즘을 초기화 할 때 저장되어 함수 운영시 사용될 여러 값들(key_st, padding, num, ivec, init)
* \param out
* 알고리즘 수행 결과 얻게 되는 암호문 블럭
* \param outl
* 암호문 블럭의 길이
* \param in
* 알고리즘을 수행하기 위해 입력하는 평문 블럭
* \param inl
* 평문 블럭의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_OPERATE_FUNCTION unit->operate 오류
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_INVALID_INPUT : 입력 파라미터 오류
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_CIPHER_ENCRYPT_FAILURE : 블럭 크기 오류
* \remarks
* unit->operate를 실제 수행 및 패딩 작업 수행
*/
ISC_INTERNAL ISC_STATUS isc_Update_Encryption(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl, const uint8 *in, int inl);

/*!
* \brief
* Block 알고리즘을 실제 실행하는 함수(Decrypt) 
* \param unit
* 알고리즘을 초기화 할 때 저장되어 함수 운영시 사용될 여러 값들(key_st, padding, num, ivec, init)
* \param out
* 알고리즘 수행 결과 얻게 되는 평문 블럭
* \param outl
* 평문 블럭의 길이
* \param in
* 알고리즘을 수행하기 위해 입력하는 암호문 블럭
* \param inl
* 암호문 블럭의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : 함수내 isc_Update_Encryption실행시 unit->operate 오류
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_DECRYPTION^ISC_ERR_CIPHER_DECRYPT_FAILURE : 블럭 크기 오류 or update error
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_INVALID_INPUT : 입력 파라미터 오류
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_CIPHER_ENCRYPT_FAILURE : 블럭 크기 오류
* \remarks
* 패딩작업과 dec설정 작업후 updateEncryption함수 수행
*/
ISC_INTERNAL ISC_STATUS isc_Update_Decryption(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl, const uint8 *in, int inl);

/*!
* \brief
* Block 알고리즘을 출력하는 함수(Encrypt)
* \param unit
* 알고리즘을 초기화 할 때 저장되어 함수 운영시 사용될 여러 값들(key_st, padding, num, ivec, init)
* \param out
* 알고리즘 수행 결과 얻게 되는 암호문 블럭
* \param outl
* 암호문 블럭의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_ENCRYPTION^ISC_ERR_CIPHER_ENCRYPT_FAILURE : 입력 파라미터 오류
* -# 그외 다른 오류 : unit->operator의 에러코드(각 BLOCK CIPHER의 ECB, CBC, CFB, OFB, CTR 모드 실행 함수 참조)
* \remarks
* unit->operate를 실제 수행 및 패딩 작업 수행
*/
ISC_INTERNAL ISC_STATUS isc_Final_Encryption(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl);

/*!
* \brief
* Block 알고리즘을 출력하는 함수(Decrypt)
* \param unit
* 알고리즘을 초기화 할 때 저장되어 함수 운영시 사용될 여러 값들(key_st, padding, num, ivec, init)
* \param out
* 알고리즘 수행 결과 얻게 되는 평문 블럭
* \param outl
* 평문 블럭의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_ENCRYPTION^ISC_ERR_CIPHER_ENCRYPT_FAILURE : 입력 파라미터 오류
* -# 그외 다른 오류 : unit->operator의 에러코드(각 BLOCK CIPHER의 ECB, CBC, CFB, OFB, CTR 모드 실행 함수 참조)
* \remarks
* unit->operate를 실제 수행 및 패딩 작업 수행
*/
ISC_INTERNAL ISC_STATUS isc_Final_Decryption(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl);

/*!
* \brief
* 바이너리 타입의 숫자 1 증가
* \param counter
* 1 증가시킬 대상
*/
ISC_INTERNAL void isc_Increase_Counter(uint8 *counter);

ISC_INTERNAL void isc_Increase_Counter_FPE(uint8 *ctr);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_BLOCK_CIPHER_UNIT*, ISC_New_BLOCK_CIPHER_Unit, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_BLOCK_CIPHER_Unit, (ISC_BLOCK_CIPHER_UNIT *c), (c) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_BLOCK_CIPHER_Unit, (ISC_BLOCK_CIPHER_UNIT *unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_BLOCK_CIPHER, (ISC_BLOCK_CIPHER_UNIT *unit, int cipher_id, const uint8 *key, const uint8 *iv, int enc), (unit, cipher_id, key, iv, enc), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_BLOCK_CIPHER, (ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl, const uint8 *in, int inl), (unit, out, outl, in, inl), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_BLOCK_CIPHER, (ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl), (unit, out, outl), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_BLOCK_CIPHER, (int cipher_id, int enc,	const uint8 *key, const uint8 *iv, const uint8 *in, int inl, uint8 *out, int *outl), (cipher_id, enc, key, iv, in, inl, out, outl), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_Block_Alg_ID, (ISC_BLOCK_CIPHER_UNIT *unit), (unit), 0 );
ISC_RET_LOADLIB_CRYPTO(char*, ISC_Get_Block_Alg_Name, (int algorithm_id), (algorithm_id), NULL );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_Block_Length, (int algorithm_id), (algorithm_id), 0 );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_Key_Length, (int algorithm_id), (algorithm_id), 0 );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_IV_Length, (int algorithm_id), (algorithm_id), 0 );
ISC_RET_LOADLIB_CRYPTO(char*, ISC_Get_Mode_Name, (int algorithm_id), (algorithm_id), NULL );
ISC_RET_LOADLIB_CRYPTO(int, isc_Get_Mode_Length, (ISC_BLOCK_CIPHER_UNIT *unit), (unit), 0 );

#endif

#ifdef  __cplusplus
}
#endif

#endif /* !HEADER_CIPHER_INTERFACE */


