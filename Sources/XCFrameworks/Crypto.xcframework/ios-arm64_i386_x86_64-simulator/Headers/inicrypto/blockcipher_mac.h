
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

/* CCM, GCM ���� ���� �Լ������� */
#define ISC_DEFINE_BLOCK_CIPHER_MAC(cipher, op_mode);\
	unit->operate_mac=(int (*)(ISC_BLOCK_CIPHER_MAC_UNIT*,uint8*,const uint8*,uint32)) cipher##_##op_mode##_DO;

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * 16����Ʈ �迭�� ���������� 1��Ʈ ����Ʈ
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
* Block cipher�� ���� ������ ���� �ִ� ����ü
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

	uint8  nonce[ISC_GCM_NONCE_MAX_LENGTH];			/**< nonce �迭*/
	int nonce_len;
	uint8  active_nonce[ISC_GCM_NONCE_MAX_LENGTH];	/**< ���� �ܰ迡�� ����Ǵ� nonce ��*/
	
	/* CCM, GCM ���� �����Լ� */
	int (*operate_mac)(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out,const uint8 *in, uint32 inl); /**< ���� �˰��� �´� � �Լ�*/

	ISC_BLOCK_CIPHER_UNIT *block_cipher_unit;	/* block cipher unit */
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_BLOCK_CIPHER_MAC_UNIT ����ü�� �ʱ�ȭ �Լ�
* \returns
* ISC_BLOCK_CIPHER_MAC_UNIT unit
*/
ISC_API ISC_BLOCK_CIPHER_MAC_UNIT *ISC_New_BLOCK_CIPHER_MAC_Unit(void);

/*!
* \brief
* ISC_BLOCK_CIPHER_MAC_UNIT ����ü�� ����
* \param unit
* ������ ISC_BLOCK_CIPHER_MAC_UNIT ����ü
*/
ISC_API void ISC_Clean_BLOCK_CIPHER_MAC_Unit(ISC_BLOCK_CIPHER_MAC_UNIT *unit);

/*!
* \brief
* ISC_BLOCK_CIPHER_MAC_UNIT ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(free)
*/
ISC_API void ISC_Free_BLOCK_CIPHER_MAC_Unit(ISC_BLOCK_CIPHER_MAC_UNIT *unit);

/*!
* \brief
* Block �˰����� �ʱ�ȭ�ϴ� �Լ�
* \param unit
* �˰����� �ʱ�ȭ �� �� ���� ���� ����(key_st, padding, num, ivec, init)
* \param enc
* 0�̸� Decryption, �׷��� ������ Encryption
* \param cipher_id
* Test �ҽ����� �Է��� ���� (ex; ISC_ARIA128|ISC_MODE_CCM|ISC_NO_PADDING)
* \param key
* �ʱ� Ű��
* \param iv
* -# ECB��� : 0
* -# CFB, OFB��� : �ʱ⺤�� ���� �� ī������ unit->num = 0���� �ʱ�ȭ
* -# CBC��� : �ʱ⺤�� ���� 
* \param iv_len
* iv�� ����
* \param adata
* �߰� ������
* \param adata_len
* adata�� ����
* \param tlen
* t�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_INIT_FAILURE : ���� �ʱ�ȭ �Լ� ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_MALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_INVALID_IV_LENGTH : �߸��� IV ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_NULL_IV_VALUE : IV���� NULL
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡�� ����� ��� �˰��� ��� ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_INIT_BLOCKCIPHER^ISC_ERR_INVALID_OPERATION_MASK : �߸��� ���� �Է�
*/
ISC_API ISC_STATUS ISC_Init_BLOCK_CIPHER_MAC(ISC_BLOCK_CIPHER_MAC_UNIT *unit, int enc, int cipher_id, const uint8 *key, const uint8 *iv, int iv_len, uint8 *adata, int adata_len, int tlen);

/*!
* \brief
* Block �˰����� �����ϴ� �Լ�(Enc, Dec�� ���� Ȯ��)
* \param unit
* �˰����� �ʱ�ȭ �� �� ����Ǿ� �Լ� ��� ���� ���� ����(key_st, padding, num, ivec, init)
* \param out
* �˰��� ���� ��� ��� �Ǵ� ��ȣ�� �� (Ȥ�� �� ��)
* \param outl
* ��ȣ�� ��(Ȥ�� �� ��)�� ����
* \param in
* �˰����� �����ϱ� ���� �Է��ϴ� �� �� (Ȥ�� ��ȣ�� ��)
* \param inl
* �� ��(Ȥ�� ��ȣ�� ��)�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_BLOCKCIPHER^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_OPERATE_FUNCTION : ��ȣȭ or ��ȣȭ �˰��� ������ ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_CIPHER_ENCRYPT_FAILURE : UPDATE BLOCKCIPHER ��ȣȭ ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_DECRYPTION^ISC_ERR_CIPHER_DECRYPT_FAILURE : UPDATE BLOCKCIPHER ��ȣȭ ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_DECRYPTION^ISC_ERR_UPDATE_FAILURE : UPDATE BLOCKCIPHER ��ȣȭ ����
* \remarks
* unit->encrypt�� 0�̸� updateDecryption�Լ�, �׷��� ������ updateEncryption�Լ� ����
*/
ISC_API ISC_STATUS ISC_Update_BLOCK_CIPHER_MAC(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, int *outl, const uint8 *in, int inl);

/*!
* \brief
* Block �˰����� ����ϴ� �Լ�
* \param unit
* �˰����� �ʱ�ȭ �� �� ����Ǿ� �Լ� ��� ���� ���� ����(key_st, padding, num, ivec, init)
* \param out
* �˰��� ���� ��� ��� �Ǵ� ��ȣ�� �� (Ȥ�� �� ��)
* \param outl
* ��ȣ�� ��(Ȥ�� �� ��)�� ����
* \param tag
* GCM ��忡�� ���Ǵ� tag
* \param tagl
* GCM ��忡�� ���Ǵ� tag�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_BLOCKCIPHER^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_BLOCKCIPHER^ISC_ERR_CIPHER_ENCRYPT_FAILURE : FINAL BLOCKCIPHER ��ȣȭ ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_BLOCKCIPHER^ISC_ERR_CIPHER_DECRYPT_FAILURE : FINAL BLOCKCIPHER ��ȣȭ ����
* \remarks
* unit->encrypt�� 0�̸� updateDecryption�Լ�, �׷��� ������ updateEncryption�Լ� ����
*/
ISC_API ISC_STATUS ISC_Final_BLOCK_CIPHER_MAC(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, int *outl, uint8 *tag, int *tagl);

/*!
* \brief
* INIT, UPDATE, FINAL�� �ѹ��� ó���ϴ� BLOCK CIPHER MAC�Լ�
* \param cipher_id
* ó���� �Է����ִ� flag��
* \param enc
* ISC_ENCRYPTION, ISC_DECRYPTION
* \param key
* ó�� ������ ������ Ű���� ���� �迭
* \param iv
* ó�� ������ ������ �ʱ⺤�Ͱ��� ���� �迭
* \param iv_len
* iv�� ����
* \param in
* ó�� ������ ������ �򹮰��� ���� �迭
* \param inl
* �� �迭�� ����
* \param out
* ��°�(��ȣ��)�� ���� �迭
* \param outl
* ��°�(��ȣ��) �迭�� ����
* \param adata
* ó�� ������ ������ adata�� ���� �迭
* \param adata_len
* adata �迭�� ����
* \param tag
* ó�� ������ ������ �±��� ���� �迭
* \param tlen
* �±� �迭�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Init_BLOCK_CIPHER_MAC()�� ���� �ڵ�
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER_MAC^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER_MAC^ISC_ERR_INIT_BLOCKCIPHER_FAIL : INIT BLOCKCIPHER ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER_MAC^ISC_ERR_UPDATE_BLOCKCIPHER_FAIL : UPDATE BLOCKCIPHER ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER_MAC^ISC_ERR_FINAL_BLOCKCIPHER_FAIL : FINAL BLOCKCIPHER ����
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
* GCM �Ķ���� �����ϴ� �Լ�
* \param unit
* unit ����ü
* \param iv
* IV ��(�ʼ�)
* \param ivlen
* IV�� ����(����Ʈ)
* \param a
* associated data(���� ���, NULL �Է�)
* \param alen
* associated data(���� ���, 0 �Է�)
* \param tlen
* tag length(12~16)
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_SET_GCM_PARAM^ISC_ERR_INVALID_INPUT : �Ķ���� �Է� ����
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
* GHASH �Լ�
* \param y
* GHASH�� ��� ��
* \param x
* �Է� ��
* \param xlen
* �Է� �� x�� ����(����Ʈ)
* \param h
* �ؽ� ����Ű ��� H
* \returns
* \remarks
* ���(128��Ʈ) ����
* ó���� �׻� y�� x�� XOR�� ���� H�� ���ϵ��� �����Ǿ� ����
*/
ISC_INTERNAL void isc_GCM_GHash(uint8 *y, uint8 *x, uint32 xlen, uint8 *h);

/*!
* \brief
* Galois Field �� ���� �Լ�
* \param out
* ������ ��� S
* \param x
* �Է� ��(len(x)=128)
* \param y
* �Է� ��(len(y)=128)
* \returns
* \remarks
* x^128 + x^7 + x^2 + x + 1 ���׽��� ���
*/
ISC_INTERNAL void isc_GCM_GFMul(uint8 *out, uint8 *x, uint8 *y);

/*!
* \brief
* ��� S�� �����ϴ� �Լ�
* S = GHASH_H(A | 0^v | C | 0^u | [len(A)]_64 | [len(C)]_64)
* \param s
* ������ ��� S
* \param a
* associated data
* \param alen
* associated data length(����Ʈ)
* \param c
* ��ȣ��, GCTR_K(inc_32(J_0), P)
* \param clen
* ��ȣ�� ����(����Ʈ)
* \param h
* GHASH�� �ؽ� ����Ű H
* \returns
* \remarks
*/
ISC_INTERNAL void isc_Get_GCM_S(uint8 *s, uint8 *a, uint32 alen, uint8 *c, int clen, uint8 *h);

/*!
* \brief
* GCTR�� ����� ī���� ���� �����ϴ� �Լ�(J_0)
* \param j
* ������ ī���� ��(len(j)=128)
* \param iv
* �Էµ� IV ��
* \param ivlen
* IV ����(����Ʈ)
* \param h
* GHASH�� �ؽ� ����Ű H
* \returns
* \remarks
*/
ISC_INTERNAL void isc_Set_GCM_Counter(uint8 *j, uint8 *iv, uint32 ivlen, uint8 *h);

/*!
* \brief
* inc_s(X) : GCTR�� ī���� ���� �Լ�
* ��Ʈ���� ������ ���� s��Ʈ�� 1��ŭ �����ϴ� �Լ�
* ���� ���� len(X)-s�� ������ ����.
* \param ctr
* �ʱ� ī����
* \returns
* -# ctr : 1��ŭ ������ ī����
* \remarks
*/
ISC_INTERNAL void isc_Increase_Counter_GCM(uint8 *ctr);

#endif

#ifdef  __cplusplus
}
#endif

#endif
