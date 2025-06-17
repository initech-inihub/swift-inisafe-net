
#ifndef HEADER_BLOCKCIPHER_MAC_H
#define HEADER_BLOCKCIPHER_MAC_H


#include "blockcipher.h"
#include "utils.h"

/* CCM MODE */
#define ISC_CCM_NONCE_MAX_LENGTH					13
#define ISC_CCM_NONCE_MIN_LENGTH					7
#define ISC_CCM_TAG_MIN_LENGTH						4
#define ISC_CCM_TAG_MAX_LENGTH						16
/* #define ISC_CCM_INPUT_MAX_LENGTH					4096*/
#define ISC_CCM_INPUT_FORMAT_MAX_LENGTH				(16+(16*((ISC_CCM_ADATA_MAX_LENGTH+10+15)/16)) + (16*((ISC_CCM_INPUT_MAX_LENGTH+15)/16)))
/* #define ISC_CCM_ENC_MAX_LENGTH						ISC_CCM_INPUT_MAX_LENGTH + ISC_CCM_T_MAX_LENGTH */

/* GCM MODE */
#define ISC_GCM_TAG_MIN_LENGTH						4
#define ISC_GCM_TAG_MAX_LENGTH						16
#define ISC_GCM_NONCE_MAX_LENGTH					128

/* CCM, GCM 운영모드 연산 함수포인터 */
#define ISC_DEFINE_BLOCK_CIPHER_MAC(cipher, op_mode);\
	unit->operate_mac=(int (*)(ISC_BLOCK_CIPHER_MAC_UNIT*,uint8*,const uint8*,uint32)) cipher##_##op_mode##_DO;

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * 16바이트 배열을 오른쪽으로 1비트 시프트
 */
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

/*!
* \brief
* Block cipher에 대한 정보를 갖고 있는 구조체
*/
struct isc_block_cipher_mac_unit_st
{
	uint8 *adata;			/* CCM, GCM : associated data */
	int adata_len;		/* CCM, GCM : associated data length */
							/* CCM : nonce, GCM : iv */
							/* CCM : nonce length, GCM : iv length 1 <= len(iv) <= 2^64-1 */
	uint8 tag[16];			/* GCM Tag */
	int tag_len;			/* tag length  CCM : {4,6,8,10,12,14,16}, GCM : {12,13,14,15,16} */
	uint8 *block_mac_buf;	/* CCM, GCM : Plaintext or ciphertext */
	int block_mac_len;	/* CCM, GCM : input length */

	uint8  nonce[ISC_GCM_NONCE_MAX_LENGTH];			/**< nonce 배열*/
	int nonce_len;
	uint8  active_nonce[ISC_GCM_NONCE_MAX_LENGTH];	/**< 운영모드 단계에서 적용되는 nonce 값*/
	
	/* CCM, GCM 전용 연산함수 */
	int (*operate_mac)(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out,const uint8 *in, uint32 inl); /**< 설정 알고리즘에 맞는 운영 함수*/

	ISC_BLOCK_CIPHER_UNIT *block_cipher_unit;	/* block cipher unit */
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_BLOCK_CIPHER_MAC_UNIT 구조체의 초기화 함수
* \returns
* ISC_BLOCK_CIPHER_MAC_UNIT unit
*/
ISC_API ISC_BLOCK_CIPHER_MAC_UNIT *ISC_New_BLOCK_CIPHER_MAC_Unit(void);

/*!
* \brief
* ISC_BLOCK_CIPHER_MAC_UNIT 구조체를 리셋
* \param unit
* 리셋할 ISC_BLOCK_CIPHER_MAC_UNIT 구조체
*/
ISC_API void ISC_Clean_BLOCK_CIPHER_MAC_Unit(ISC_BLOCK_CIPHER_MAC_UNIT *unit);

/*!
* \brief
* ISC_BLOCK_CIPHER_MAC_UNIT 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(free)
*/
ISC_API void ISC_Free_BLOCK_CIPHER_MAC_Unit(ISC_BLOCK_CIPHER_MAC_UNIT *unit);

/*!
* \brief
* Block 알고리즘을 초기화하는 함수
* \param unit
* 알고리즘을 초기화 할 때 사용될 여러 값들(key_st, padding, num, ivec, init)
* \param enc
* 0이면 Decryption, 그렇지 않으면 Encryption
* \param cipher_id
* Test 소스에서 입력한 변수 (ex; ISC_ARIA128|ISC_MODE_CCM|ISC_NO_PADDING)
* \param key
* 초기 키값
* \param iv
* -# ECB모드 : 0
* -# CFB, OFB모드 : 초기벡터 생성 후 카운팅할 unit->num = 0으로 초기화
* -# CBC모드 : 초기벡터 생성 
* \param iv_len
* iv의 길이
* \param adata
* 추가 데이터
* \param adata_len
* adata의 길이
* \param tlen
* t의 길이
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
ISC_API ISC_STATUS ISC_Init_BLOCK_CIPHER_MAC(ISC_BLOCK_CIPHER_MAC_UNIT *unit, int enc, int cipher_id, const uint8 *key, const uint8 *iv, int iv_len, uint8 *adata, int adata_len, int tlen);

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
ISC_API ISC_STATUS ISC_Update_BLOCK_CIPHER_MAC(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, int *outl, const uint8 *in, int inl);

/*!
* \brief
* Block 알고리즘을 출력하는 함수
* \param unit
* 알고리즘을 초기화 할 때 저장되어 함수 운영시 사용될 여러 값들(key_st, padding, num, ivec, init)
* \param out
* 알고리즘 수행 결과 얻게 되는 암호문 블럭 (혹은 평문 블럭)
* \param outl
* 암호문 블럭(혹은 평문 블럭)의 길이
* \param tag
* GCM 모드에서 사용되는 tag
* \param tagl
* GCM 모드에서 사용되는 tag의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_BLOCKCIPHER^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_BLOCKCIPHER^ISC_ERR_CIPHER_ENCRYPT_FAILURE : FINAL BLOCKCIPHER 암호화 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_BLOCKCIPHER^ISC_ERR_CIPHER_DECRYPT_FAILURE : FINAL BLOCKCIPHER 복호화 실패
* \remarks
* unit->encrypt가 0이면 updateDecryption함수, 그렇지 않으면 updateEncryption함수 실행
*/
ISC_API ISC_STATUS ISC_Final_BLOCK_CIPHER_MAC(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, int *outl, uint8 *tag, int *tagl);

/*!
* \brief
* INIT, UPDATE, FINAL을 한번에 처리하는 BLOCK CIPHER MAC함수
* \param cipher_id
* 처음에 입력해주는 flag값
* \param enc
* ISC_ENCRYPTION, ISC_DECRYPTION
* \param key
* 처음 유저가 설정한 키값을 담은 배열
* \param iv
* 처음 유저가 설정한 초기벡터값을 담은 배열
* \param iv_len
* iv의 길이
* \param in
* 처음 유저가 설정한 평문값을 담은 배열
* \param inl
* 평문 배열의 길이
* \param out
* 출력값(암호문)을 담을 배열
* \param outl
* 출력값(암호문) 배열의 길이
* \param adata
* 처음 유저가 설정한 adata를 담은 배열
* \param adata_len
* adata 배열의 길이
* \param tag
* 처음 유저가 설정한 태그을 담은 배열
* \param tlen
* 태그 배열의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Init_BLOCK_CIPHER_MAC()의 에러 코드
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER_MAC^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER_MAC^ISC_ERR_INIT_BLOCKCIPHER_FAIL : INIT BLOCKCIPHER 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER_MAC^ISC_ERR_UPDATE_BLOCKCIPHER_FAIL : UPDATE BLOCKCIPHER 실패
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER_MAC^ISC_ERR_FINAL_BLOCKCIPHER_FAIL : FINAL BLOCKCIPHER 실패
*/
ISC_API ISC_STATUS ISC_BLOCK_CIPHER_MAC(int cipher_id, int enc,	const uint8 *key, const uint8 *iv, int iv_len, const uint8 *in, int inl, uint8 *out, int *outl, uint8 *adata, int adata_len, uint8 *tag, int tlen);

ISC_INTERNAL ISC_STATUS isc_Update_Encryption_Mac(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, int *outl, const uint8 *in, int inl);

ISC_INTERNAL ISC_STATUS isc_Update_Decryption_Mac(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, int *outl, const uint8 *in, int inl);

ISC_INTERNAL ISC_STATUS isc_Final_Encryption_Mac(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, int *outl);

ISC_INTERNAL ISC_STATUS isc_Final_Decryption_Mac(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, int *outl);

ISC_INTERNAL ISC_STATUS isc_Init_Block_Mac_Alg(ISC_BLOCK_CIPHER_MAC_UNIT* unit, int cipher_id);

/**************************************************************
* CCM MODE 
***************************************************************/
ISC_INTERNAL ISC_STATUS isc_Set_CCM_Param(
					  ISC_BLOCK_CIPHER_MAC_UNIT *unit,
					  const uint8 *n, 
					  uint8 nlen,
					  uint8 *a,				   
					  uint32 alen, 
					  uint8 tlen);

ISC_INTERNAL void isc_CCM_Formatting_Input(
						  uint8 *p, 
						  uint32 plen,
						  uint8 *n, 
						  uint8 nlen,
						  uint8 *a,				   
						  uint32 alen, 
						  uint8 tlen, 
						  uint8 qlen,
						  uint8 *out);

ISC_INTERNAL void isc_Init_CCM_Formatting_Counterblock(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 qlen);

ISC_INTERNAL void isc_Get_CCM_Formatting_Input_Length(uint32 alen, uint32 plen, uint32 *outlen);

/**************************************************************
* GCM MODE 
***************************************************************/

/*!
* \brief
* GCM 파라미터 설정하는 함수
* \param unit
* unit 구조체
* \param iv
* IV 값(필수)
* \param ivlen
* IV의 길이(바이트)
* \param a
* associated data(없을 경우, NULL 입력)
* \param alen
* associated data(없을 경우, 0 입력)
* \param tlen
* tag length(12~16)
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_SET_GCM_PARAM^ISC_ERR_INVALID_INPUT : 파라미터 입력 오류
* \remarks
*/
ISC_INTERNAL ISC_STATUS isc_Set_GCM_Param(
					  ISC_BLOCK_CIPHER_MAC_UNIT *unit,
					  const uint8 *iv, 
					  uint32 ivlen,
					  uint8 *a,				   
					  uint32 alen,
					  uint8 tlen);

/*!
* \brief
* GHASH 함수
* \param y
* GHASH의 출력 값
* \param x
* 입력 값
* \param xlen
* 입력 값 x의 길이(바이트)
* \param h
* 해쉬 서브키 블록 H
* \returns
* \remarks
* 블록(128비트) 단위
* 처음에 항상 y와 x를 XOR한 값에 H를 곱하도록 구성되어 있음
*/
ISC_INTERNAL void isc_GCM_GHash(uint8 *y, uint8 *x, uint32 xlen, uint8 *h);

/*!
* \brief
* Galois Field 곱 연산 함수
* \param out
* 생성된 블록 S
* \param x
* 입력 값(len(x)=128)
* \param y
* 입력 값(len(y)=128)
* \returns
* \remarks
* x^128 + x^7 + x^2 + x + 1 다항식을 사용
*/
ISC_INTERNAL void isc_GCM_GFMul(uint8 *out, uint8 *x, uint8 *y);

/*!
* \brief
* 블록 S를 생성하는 함수
* S = GHASH_H(A | 0^v | C | 0^u | [len(A)]_64 | [len(C)]_64)
* \param s
* 생성된 블록 S
* \param a
* associated data
* \param alen
* associated data length(바이트)
* \param c
* 암호문, GCTR_K(inc_32(J_0), P)
* \param clen
* 암호문 길이(바이트)
* \param h
* GHASH의 해쉬 서브키 H
* \returns
* \remarks
*/
ISC_INTERNAL void isc_Get_GCM_S(uint8 *s, uint8 *a, uint32 alen, uint8 *c, int clen, uint8 *h);

/*!
* \brief
* GCTR에 사용할 카운터 값을 생성하는 함수(J_0)
* \param j
* 생성된 카운터 값(len(j)=128)
* \param iv
* 입력된 IV 값
* \param ivlen
* IV 길이(바이트)
* \param h
* GHASH의 해쉬 서브키 H
* \returns
* \remarks
*/
ISC_INTERNAL void isc_Set_GCM_Counter(uint8 *j, uint8 *iv, uint32 ivlen, uint8 *h);

/*!
* \brief
* inc_s(X) : GCTR의 카운터 증가 함수
* 비트열의 오른쪽 상위 s비트를 1만큼 증가하는 함수
* 왼쪽 상위 len(X)-s는 변하지 않음.
* \param ctr
* 초기 카운터
* \returns
* -# ctr : 1만큼 증가한 카운터
* \remarks
*/
ISC_INTERNAL void isc_Increase_Counter_GCM(uint8 *ctr);

#endif

#ifdef  __cplusplus
}
#endif

#endif
