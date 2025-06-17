/*!
* \file blockcipher.h
* \brief
* �� �˰����� �������̽� ����
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

#define ISC_DECRYPTION		0			/*!< ��ȣȭ */
#define ISC_ENCRYPTION		1			/*!< ��ȣȭ */

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
#define ISC_AES128			0x01000100				/*!< AES 128bit �˰��� ID*/
#define ISC_AES192			0x01000200				/*!< AES 192bit �˰��� ID*/
#define ISC_AES256			0x01000300				/*!< AES 256bit �˰��� ID*/

/*ISC_DES Alias				0x02000000 ------------------------------------------------ */
#define ISC_DES				0x02000100				/*!< ISC_DES �˰��� ID*/
#define ISC_DES_EDE			0x02000200				/*!< Triple ISC_DES �˰��� ID (3-Key)*/
#define ISC_DES_EDE_2KEY	0x02001200				/*!< 2Key Triple ISC_DES �˰��� ID*/
#define ISC_DES_EDE_3KEY	0x02010200				/*!< 3Key Triple ISC_DES �˰��� ID*/

/*ARIA Alias			0x03000000 ------------------------------------------------*/
#define ISC_ARIA128			0x03000100				/*!< ARIA 128bit �˰��� ID*/
#define ISC_ARIA192			0x03000200				/*!< ARIA 192bit �˰��� ID*/
#define ISC_ARIA256			0x03000300				/*!< ARIA 256bit �˰��� ID*/

/*ISC_SEED Alias			0x04000000 ------------------------------------------------*/
#define ISC_SEED			0x04000100				/*!< ISC_SEED 128bit �˰��� ID*/
#define ISC_SEED256			0x04000200				/*!< ISC_SEED 256bit �˰��� ID*/
/*---------------------------------------------------------------------------------*/

/*ISC_RC5 Alias				0x05000000 ------------------------------------------------*/
#define ISC_RC5				0x05000100					/*!< ISC_RC5 �˰��� ID*/
/*---------------------------------------------------------------------------------*/

/*BlowFish Alias		0x06000000 ------------------------------------------------*/
#define ISC_BF				0x06000100					/*!< BlowFish �˰��� ID*/
/*---------------------------------------------------------------------------------*/

/*RC2 Alias				0x07000000 ------------------------------------------------*/
#define ISC_RC2_128			0x07000100					/*!< RC2 128bit �˰��� ID*/
#define ISC_RC2_40			0x07000200					/*!< RC2 40bit �˰��� ID*/
#define ISC_RC2_64			0x07000300					/*!< RC2 64bit�˰��� ID*/
/*---------------------------------------------------------------------------------*/

/*LEA Alias				0x08000000 ------------------------------------------------ */
#define ISC_LEA128			0x08000100				/*!< LEA 128bit �˰��� ID*/
#define ISC_LEA192			0x08000200				/*!< LEA 192bit �˰��� ID*/
#define ISC_LEA256			0x08000300				/*!< LEA 256bit �˰��� ID*/

/*---------------------------------------------------------------------------------*/
#define ISC_AES_PROVEN_MODE			0    /*!<  0: ����� ���, 1: ������� */ 
#define ISC_DES_PROVEN_MODE			0    /*!<  0: ����� ���, 1: ������� */
#define ISC_ARIA_PROVEN_MODE		1    /*!<  0: ����� ���, 1: ������� */
#define ISC_SEED_PROVEN_MODE		1    /*!<  0: ����� ���, 1: ������� */
#define ISC_RC5_PROVEN_MODE			0    /*!<  0: ����� ���, 1: ������� */
#define ISC_BF_PROVEN_MODE			0    /*!<  0: ����� ���, 1: ������� */

#define ISC_ECB_MODE_PROVEN_MODE    1    /*!<  0: ����� ���, 1: ������� */
#define ISC_CBC_MODE_PROVEN_MODE    1    /*!<  0: ����� ���, 1: ������� */
#define ISC_CFB_MODE_PROVEN_MODE    1    /*!<  0: ����� ���, 1: ������� */
#define ISC_OFB_MODE_PROVEN_MODE    1    /*!<  0: ����� ���, 1: ������� */
#define ISC_CTR_MODE_PROVEN_MODE    0    /*!<  0: ����� ���, 1: ������� */
#define ISC_FPE_MODE_PROVEN_MODE    0    /*!<  0: ����� ���, 1: ������� */
#define ISC_OPE_MODE_PROVEN_MODE    0    /*!<  0: ����� ���, 1: ������� */
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
* Block cipher�� ���� ������ ���� �ִ� ����ü
*/
struct isc_block_cipher_unit_st
{
	uint32 algorithm;				 /**< ��ȣȭ �˰���*/
	int block_size;				 /**< ���� ���� ���� */
	int key_len;			     /**< Ű�� ���� */
	int iv_len;				     /**<�ʱ⺤���� ���� */
	size_t effective_key_len;		/**rc2�� �����ϱ� ���� */
	uint8 mode;			         /**< ���� CBC, ECB, CFB, OFB */
	uint8 padding;				 /**<�е��� ����; padding�� ��ġ���� ��� ISC_NO_PADDING */
	int (*init)(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key,const uint8 *iv, int enc); /**< ���� �˰��� �´� �ʱ�ȭ �Լ�*/
	int (*operate)(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out,const uint8 *in, uint32 inl); /**< ���� �˰��� �´� � �Լ�*/
	int encrypt;				 /**< ��ȣȭ(1)�� ��ȣȭ(0)*/
	uint8  ivec[ISC_IV_MAX_LENGTH];				 /**< �ʱ⺤�� �迭*/
	uint8  active_ivec [ISC_IV_MAX_LENGTH];				 /**< ���� �ܰ迡�� ����Ǵ� ���� ��*/
	uint8  buf[ISC_BLOCK_MAX_LENGTH];				 /**< buf �迭*/
	uint8  ctr_buf[ISC_BLOCK_MAX_LENGTH];				 /**< ctr mode buf �迭*/
	int buf_len;				 /**< buf�� ����*/
	int count;					 /**< OFB / CFB count*/
	void *key_st;				 /**< ��ȣ �˰���� ���Ǵ� key*/ 
	int st_size;				 /**< key_st�� ������*/
	int final_used;				 /**< final check*/
	int block_mask;				 /**< block mask*/
	uint8 final[ISC_BLOCK_MAX_LENGTH];					 /**< ������ ����*/
	int unit_status;
	uint8 isproven;			     /*!< ��ȣȭ ������ ���� �˰��� ���� ���� */
	uint8 block_num;			/**< ���° ������� ����. fpe ��带 �����ϱ� ���� �߰�*/	
	uint8 block_position;		/**< ��ϳ� ��ġ. fpe ��带 �����ϱ� ���� �߰�*/
};

struct isc_advanced_block_cipher_unit_st
{
	uint32 algorithm;				/**< ��ȣȭ �˰���*/
	int block_size;					/**< ���� ���� ���� */
	int key_len;					/**< Ű�� ���� */
	int iv_len;						/**<�ʱ⺤���� ���� */
	size_t effective_key_len;		/**rc2�� �����ϱ� ���� */
	uint8 mode;						/**< ���� CBC, ECB, CFB, OFB */
	uint8 padding;					/**<�е��� ����; padding�� ��ġ���� ��� ISC_NO_PADDING */
	int (*init)(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key,const uint8 *iv, int enc); /**< ���� �˰��� �´� �ʱ�ȭ �Լ�*/
	int (*operate)(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out,const uint8 *in, uint32 inl); /**< ���� �˰��� �´� � �Լ�*/
	int encrypt;									/**< ��ȣȭ(1)�� ��ȣȭ(0)*/
	uint8  ivec[ISC_IV_MAX_LENGTH];						/**< �ʱ⺤�� �迭*/
	uint8  active_ivec [ISC_IV_MAX_LENGTH];				 /**< ���� �ܰ迡�� ����Ǵ� ���� ��*/
	uint8 key_st[ISC_ADVANCED_BLOCK_CIPHER_MAX_ROUND_KEY];				 /**< ��ȣ �˰���� ���Ǵ� key*/ 
	int st_size;					/**< key_st�� ������*/
	int final_used;					/**< final check*/
	int block_mask;					/**< block mask*/
	int unit_status;
	uint8 isproven;					/*!< ��ȣȭ ������ ���� �˰��� ���� ���� */
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_BLOCK_CIPHER_UNIT ����ü�� �ʱ�ȭ �Լ�
* \returns
* ISC_BLOCK_CIPHER_UNIT unit
*/
ISC_API ISC_BLOCK_CIPHER_UNIT *ISC_New_BLOCK_CIPHER_Unit(void);

/*!
* \brief
* ISC_BLOCK_CIPHER_UNIT ����ü�� ����
* \param c
* ������ ISC_BLOCK_CIPHER_UNIT ����ü
*/
ISC_API void ISC_Clean_BLOCK_CIPHER_Unit(ISC_BLOCK_CIPHER_UNIT *c);

/*!
* \brief
* ISC_BLOCK_CIPHER_UNIT ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(free)
*/
ISC_API void ISC_Free_BLOCK_CIPHER_Unit(ISC_BLOCK_CIPHER_UNIT *unit);

/*!
* \brief
* Block �˰����� �ʱ�ȭ�ϴ� �Լ�
* \param unit
* �˰����� �ʱ�ȭ �� �� ���� ���� ����(key_st, padding, num, ivec, init)
* \param cipher_id
* Test �ҽ����� �Է��� ���� (ex; ISC_AES128|ISC_MODE_CBC|ISC_NO_PADDING)
* \param key
* �ʱ� Ű��
* \param iv
* -# ECB��� : 0
* -# CFB, OFB��� : �ʱ⺤�� ���� �� ī������ unit->num = 0���� �ʱ�ȭ
* -# CBC��� : �ʱ⺤�� ���� 
* \param enc
* 0�̸� Decryption, �׷��� ������ Encryption
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
ISC_API ISC_STATUS ISC_Init_BLOCK_CIPHER(ISC_BLOCK_CIPHER_UNIT *unit, int cipher_id, const uint8 *key, const uint8 *iv, int enc);
ISC_INTERNAL ISC_STATUS isc_Init_BLOCK_CIPHER_Ex(ISC_BLOCK_CIPHER_UNIT *unit, int cipher_id, const uint8 *key, const uint8 *iv, int enc, uint8 ivlen, uint8 *adata, uint32 alen, uint8 tlen);

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
ISC_API ISC_STATUS ISC_Update_BLOCK_CIPHER(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl, const uint8 *in, int inl);

/*!
* \brief
* Block �˰����� ����ϴ� �Լ�
* \param unit
* �˰����� �ʱ�ȭ �� �� ����Ǿ� �Լ� ��� ���� ���� ����(key_st, padding, num, ivec, init)
* \param out
* �˰��� ���� ��� ��� �Ǵ� ��ȣ�� �� (Ȥ�� �� ��)
* \param outl
* ��ȣ�� ��(Ȥ�� �� ��)�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_BLOCKCIPHER^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_BLOCKCIPHER^ISC_ERR_CIPHER_ENCRYPT_FAILURE : FINAL BLOCKCIPHER ��ȣȭ ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_BLOCKCIPHER^ISC_ERR_CIPHER_DECRYPT_FAILURE : FINAL BLOCKCIPHER ��ȣȭ ����
* \remarks
* unit->encrypt�� 0�̸� updateDecryption�Լ�, �׷��� ������ updateEncryption�Լ� ����
*/
ISC_API ISC_STATUS ISC_Final_BLOCK_CIPHER(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl);
ISC_INTERNAL ISC_STATUS isc_Final_BLOCK_CIPHER_Ex(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl, uint8 *tag, int *tagl);

/*!
* \brief
* INIT, UPDATE, FINAL�� �ѹ��� ó���ϴ� BLOCK CIPHER �Լ�
* \param cipher_id
* ó���� �Է����ִ� flag��
* \param enc
* ISC_ENCRYPTION, ISC_DECRYPTION
* \param key
* ó�� ������ ������ Ű���� ���� �迭
* \param iv
* ó�� ������ ������ �ʱ⺤�Ͱ��� ���� �迭
* \param in
* ó�� ������ ������ �򹮰��� ���� �迭
* \param inl
* �� �迭�� ����
* \param out
* ��°�(��ȣ��)�� ���� �迭
* \param outl
* ��°�(��ȣ��) �迭�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Init_BLOCK_CIPHER()�� ���� �ڵ�
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER^ISC_ERR_INIT_BLOCKCIPHER_FAIL : INIT BLOCKCIPHER ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER^ISC_ERR_UPDATE_BLOCKCIPHER_FAIL : UPDATE BLOCKCIPHER ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_BLOCKCIPHER^ISC_ERR_FINAL_BLOCKCIPHER_FAIL : FINAL BLOCKCIPHER ����
*/
ISC_API ISC_STATUS ISC_BLOCK_CIPHER(int cipher_id, int enc,	const uint8 *key, const uint8 *iv, const uint8 *in, int inl, uint8 *out, int *outl);

/*!
* \brief
* Init, DoFinal �������� ����ϴ� ��ĪŰ �ʱ�ȭ �Լ�
* \param cipher_id
* ��ĪŰ ��ȣ �˰��� �Է�
* \param key
* ó�� ������ ������ Ű���� ���� �迭
* \param iv
* ó�� ������ ������ �ʱ⺤�Ͱ��� ���� �迭
* \param enc
* ISC_ENCRYPTION, ISC_DECRYPTION
* \param outKey
* �Է� : ����Ű�� �ּҰ�. �޸� �Ҵ� �ؾ���. (size : ISC_ADVANCED_BLOCK_CIPHER_KEY_SIZE). ��� : ������ ���� Ű�� ��°�
* \param outKeyLen
* �Է� : outKey �� �޸� ũ��, ��� : ������ ���� Ű�� ��� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_ADVANCED_BLOCKCIPHER^ISC_ERR_NULL_INPUT : NULL ������ �Է�
* -# LOCATION^ISC_F_INIT_ADVANCED_BLOCKCIPHER^ISC_ERR_INIT_BLOCKCIPHER_FAIL : INIT BLOCKCIPHER ����
* -# LOCATION^ISC_F_INIT_ADVANCED_BLOCKCIPHER^ISC_ERR_BUF_TOO_SMALL : ���޵� outKey ũ�Ⱑ ������ ������ ũ�� ���� ������ ����
* -# LOCATION^ISC_F_INIT_ADVANCED_BLOCKCIPHER^ISC_ERR_SUB_OPERATION_FAILURE : �ʱ�ȭ ������ ���� ����
*/
ISC_API ISC_STATUS ISC_Init_Advanced_BLOCK_CIPHER(int cipher_id, const uint8 *key, const uint8 *iv, int enc, uint8* outKey, int *outKeyLen);

/*!
* \brief
* Init, DoFinal �������� ����ϴ� ��ĪŰ �Ϻ�ȣȭ �Լ�
* \param binaryKey
* �Ϻ�ȣȭ�� ���� ���� Ű
* \param binaryKeyLen
* �Ϻ�ȣȭ�� ���� ���� Ű����
* \param in
* �˰����� �����ϱ� ���� �Է��ϴ� ��
* \param inl
* ���� ����
* \param out
* �˰��� ���� ��� ��� �Ǵ� ��ȣ�� ��
* \param outl
* ��ȣ�� ���� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_DO_FINAL_ADVANCED_BLOCKCIPHER^ISC_ERR_NULL_INPUT : NULL ������ �Է�
* -# LOCATION^ISC_F_DO_FINAL_ADVANCED_BLOCKCIPHER^ISC_ERR_SUB_OPERATION_FAILURE : �ʱ�ȭ ������ ���� ����
* -# LOCATION^ISC_F_DO_FINAL_ADVANCED_BLOCKCIPHER^ISC_ERR_UPDATE_BLOCKCIPHER_FAIL : UPDATE BLOCKCIPHER ����
* -# LOCATION^ISC_F_DO_FINAL_ADVANCED_BLOCKCIPHER^ISC_ERR_FINAL_BLOCKCIPHER_FAIL : FINAL BLOCKCIPHER ����
*/
ISC_API ISC_STATUS ISC_DoFinal_Advanced_BLOCK_CIPHER(uint8* binaryKey, int binaryKeyLen , const uint8 *in, int inl, uint8 *out, int *outl);

/*!
* \brief
* ISC_BLOCK_CIPHER_UNIT ����ü���� algorithm_id�� ��� ���� �Լ�
* \param unit
* �˰����� �ʱ�ȭ �� �� ����Ǿ� �Լ� ��� ���� ���� ����(key_st, padding, num, ivec, init)
* \returns
* unit->algorithm
*/
ISC_API int ISC_Get_Block_Alg_ID(ISC_BLOCK_CIPHER_UNIT *unit);

/*!
* \brief
* algorithm_id���� Block algorithm�� �̸��� ��� ���� �Լ�
* \param algorithm_id
* �˾Ƴ����� �ϴ� algorithm_id ��
* \returns
* �ش� �˰����� �̸� (ex. ISC_AES128_NAME)
* -# ISC_NULL_STRING : �̸� �������� ����
*/
ISC_API char* ISC_Get_Block_Alg_Name(int algorithm_id);

/*!
* \brief
* algorithm_id���� Block ���̸� ��� ���� �Լ�
* \param algorithm_id
* �˾Ƴ����� �ϴ� algorithm_id ��
* \returns
* �ش� �˰��� BLOCK�� ���� (ex. ISC_AES_BLOCK_SIZE, ISC_ARIA_BLOCK_SIZE)
* -# ISC_INVALID_SIZE : ��� ���� �������� ����
*/
ISC_API int ISC_Get_Block_Length(int algorithm_id);

/*!
* \brief
* algorithm_id���� Key ���̸� ��� ���� �Լ�
* \param algorithm_id
* �˾Ƴ����� �ϴ� algorithm_id ��
* \returns
* �ش� �˰��� Key�� ���� (ex. ISC_AES128_KEY_SIZE, ISC_ARIA128_KEY_SIZE)
* -# ISC_INVALID_SIZE : Ű ���� �������� ����
*/
ISC_API int ISC_Get_Key_Length(int algorithm_id);

/*!
* \brief
* algorithm_id���� �ʱ⺤�� ũ�⸦ ��� ���� �Լ�
* \param algorithm_id
* �˾Ƴ����� �ϴ� algorithm_id ��
* \returns
* �ش� �˰��� �ʱ⺤���� ũ�� (ex. ISC_AES_BLOCK_SIZE, ISC_ARIA_BLOCK_SIZE)
* -# ISC_INVALID_SIZE : IV ���� �������� ����
* \remarks
* �ʱ⺤���� ũ��� �ᱹ �ش� �˰����� ��� ũ��� ����
*/
ISC_API int ISC_Get_IV_Length(int algorithm_id);

/*!
* \brief
* algorithm_id���� Mode �̸��� ��� ���� �Լ�
* \param algorithm_id
* �˾Ƴ����� �ϴ� algorithm_id ��
* \returns
* �ش� �˰��� Mode�� �̸� (ex. "ECB", "CBC")
* -# ISC_NULL_STRING : �̸� �������� ����    
*/
ISC_API char* ISC_Get_Mode_Name(int algorithm_id);

/*!
* \brief
* mode���� ���� shift ���� ��� ���� �Լ�
* \param mode
* �˾Ƴ����� �ϴ� mode
* \returns
* �ش� �˰��� Mode�� ���̰�
* -# ISC_INVALID_SIZE : ��� ���� �������� ����
*/
ISC_INTERNAL int isc_Get_Mode_Length(ISC_BLOCK_CIPHER_UNIT *unit);

/*!
* \brief
* ISC_BLOCK_CIPHER_UNIT ����ü�� �ʱ�ȭ �Լ�
* \param isproven ��ȣȭ ���� ��� ���� ����
* \returns
* ISC_BLOCK_CIPHER_UNIT unit
*/
ISC_INTERNAL ISC_BLOCK_CIPHER_UNIT *isc_New_BLOCK_CIPHER_Unit_Ex(uint8 isproven);

/*!
* \brief
* cipher_id�� ������ �˰��� �°� unit�� �ʱ�ȭ
* \param unit
* �˰����� �ʱ�ȭ �� �� ���� ���� ������ �����ϴ� ISC_BLOCK_CIPHER_UNIT
* \param cipher_id
* Test �ҽ����� �Է��� ���� (ex; ISC_AES128|ISC_MODE_CBC|ISC_NO_PADDING)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡�� ����� ��� �˰��� ��� ���� 
* -# LOCATION^ISC_F_INIT_ALGORITHM^ISC_ERR_INVALID_ALGORITHM_ID : �Էµ� �˰��� ID ����
* \remarks
* �� �˰���� ���忡 ���缭 unit->init�� operate�Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_Block_Alg(ISC_BLOCK_CIPHER_UNIT* unit, int cipher_id);

/*!
* \brief
* Block �˰����� ���� �����ϴ� �Լ�(Encrypt)
* \param unit
* �˰����� �ʱ�ȭ �� �� ����Ǿ� �Լ� ��� ���� ���� ����(key_st, padding, num, ivec, init)
* \param out
* �˰��� ���� ��� ��� �Ǵ� ��ȣ�� ��
* \param outl
* ��ȣ�� ���� ����
* \param in
* �˰����� �����ϱ� ���� �Է��ϴ� �� ��
* \param inl
* �� ���� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_OPERATE_FUNCTION unit->operate ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_CIPHER_ENCRYPT_FAILURE : �� ũ�� ����
* \remarks
* unit->operate�� ���� ���� �� �е� �۾� ����
*/
ISC_INTERNAL ISC_STATUS isc_Update_Encryption(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl, const uint8 *in, int inl);

/*!
* \brief
* Block �˰����� ���� �����ϴ� �Լ�(Decrypt) 
* \param unit
* �˰����� �ʱ�ȭ �� �� ����Ǿ� �Լ� ��� ���� ���� ����(key_st, padding, num, ivec, init)
* \param out
* �˰��� ���� ��� ��� �Ǵ� �� ��
* \param outl
* �� ���� ����
* \param in
* �˰����� �����ϱ� ���� �Է��ϴ� ��ȣ�� ��
* \param inl
* ��ȣ�� ���� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : �Լ��� isc_Update_Encryption����� unit->operate ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_DECRYPTION^ISC_ERR_CIPHER_DECRYPT_FAILURE : �� ũ�� ���� or update error
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ����
* -# ISC_L_BLOCK_CIPHER^ISC_F_UPDATE_ENCRYPTION^ISC_ERR_CIPHER_ENCRYPT_FAILURE : �� ũ�� ����
* \remarks
* �е��۾��� dec���� �۾��� updateEncryption�Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Update_Decryption(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl, const uint8 *in, int inl);

/*!
* \brief
* Block �˰����� ����ϴ� �Լ�(Encrypt)
* \param unit
* �˰����� �ʱ�ȭ �� �� ����Ǿ� �Լ� ��� ���� ���� ����(key_st, padding, num, ivec, init)
* \param out
* �˰��� ���� ��� ��� �Ǵ� ��ȣ�� ��
* \param outl
* ��ȣ�� ���� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_ENCRYPTION^ISC_ERR_CIPHER_ENCRYPT_FAILURE : �Է� �Ķ���� ����
* -# �׿� �ٸ� ���� : unit->operator�� �����ڵ�(�� BLOCK CIPHER�� ECB, CBC, CFB, OFB, CTR ��� ���� �Լ� ����)
* \remarks
* unit->operate�� ���� ���� �� �е� �۾� ����
*/
ISC_INTERNAL ISC_STATUS isc_Final_Encryption(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl);

/*!
* \brief
* Block �˰����� ����ϴ� �Լ�(Decrypt)
* \param unit
* �˰����� �ʱ�ȭ �� �� ����Ǿ� �Լ� ��� ���� ���� ����(key_st, padding, num, ivec, init)
* \param out
* �˰��� ���� ��� ��� �Ǵ� �� ��
* \param outl
* �� ���� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_BLOCK_CIPHER^ISC_F_FINAL_ENCRYPTION^ISC_ERR_CIPHER_ENCRYPT_FAILURE : �Է� �Ķ���� ����
* -# �׿� �ٸ� ���� : unit->operator�� �����ڵ�(�� BLOCK CIPHER�� ECB, CBC, CFB, OFB, CTR ��� ���� �Լ� ����)
* \remarks
* unit->operate�� ���� ���� �� �е� �۾� ����
*/
ISC_INTERNAL ISC_STATUS isc_Final_Decryption(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, int *outl);

/*!
* \brief
* ���̳ʸ� Ÿ���� ���� 1 ����
* \param counter
* 1 ������ų ���
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


