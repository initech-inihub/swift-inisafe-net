/*!
* \file aes.h
* \brief AES �˰���(Fips 197)

�� 128, ��ȣ�� 128bits, Ű 128,192,256 bits\n

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

#define ISC_AES_ENCRYPT	ISC_ENCRYPTION		/*!< AES�� ��ȣȭ*/
#define ISC_AES_DECRYPT	ISC_DECRYPTION		/*!< AES�� ��ȣȭ*/


#define ISC_AES_BLOCK_SIZE 16			/*!< AES�� BLOCK_SIZE*/

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
 * AES�� Ű�� ���̴� ������ �ٷ� ����ü
 * \remarks
 * roundKey(��ȣȭŰ), rounds(�� Ƚ�� ���庯��)
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
* AES���� ���̴� �� �ܰ��� Ű�� ����� �Լ�(��ȣȭ��)
* \param userKey
* �ʱ� Ű��
* \param bits
* Ű�� bit ������
* \param key
* Ű�� ������ ��� �ִ� ����ü ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
* \remarks
* Key���� 128, 192, �׸��� 256��Ʈ�� ����.
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_AES_Key(const uint8 *userKey, const int bits, ISC_AES_KEY *key);

/*!
* \brief
* AES���� ���̴� �� �ܰ��� Ű�� ����� �Լ�(��ȣȭ��)
* \param userKey
* �ʱ� Ű��
* \param bits
* Ű�� bit ������
* \param key
* Ű�� ������ ��� �ִ� ����ü ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
* \remarks
* Key���� 128, 192, �׸��� 256��Ʈ�� ����.
*/
ISC_INTERNAL ISC_STATUS isc_Init_Decrypt_AES_Key(const uint8 *userKey, const int bits, ISC_AES_KEY *key);

/*!
* \brief
* �� �� 128bit�� ��ȣȭ�ϴ� AES �˰���
* \param in
* �� �� ��
* \param out
* ��ȣ�� �� ��
* \param key
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
* \remarks
* ISC_AES_KEY key�� ����Ǿ� �ִ� rounds ������ ���� 128, 192, 256��忡 ���� ��ȣȭ
*/
ISC_INTERNAL void isc_AES_Encrypt_Block(const uint8 *in, uint8 *out, const ISC_AES_KEY *key);
/*!
* \brief
* �� �� 128bit�� ��ȣȭ�ϴ� AES �˰���
* \param in
* ��ȣ�� �� ��
* \param out
* �� �� ��
* \param key
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
* \remarks
* ISC_AES_KEY key�� ����Ǿ� �ִ� rounds ������ ���� 128, 192, 256��忡 ���� ��ȣȭ
*/
ISC_INTERNAL void isc_AES_Decrypt_Block(const uint8 *in, uint8 *out, const ISC_AES_KEY *key);

/*!
* \brief
* AES �ʱ� Ű ���� �Լ�
* \param unit
* ISC_BLOCK_CIPHER_UNIT ����ü
* \param key
* �ʱ� Ű��
* \param enc
* 1�̸� encrypt���, 0�̸� decrypt���
* \returns
* -# ISC_SUCCESS : Success
* -# L_AES^ISC_F_INIT_AES_KEY^ISC_ERR_INIT_KEY_FAILURE : �ʱ� Ű ���� ����
* \remarks
* enc �������� ���� isc_Init_Encrypt_AES_Key�� isc_Init_Decrypt_AES_Key�� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_AES_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, int enc);
/*!
* \brief
* AES �ʱ� �Լ�
* \param unit
* ISC_BLOCK_CIPHER_UNIT ����ü
* \param key
* �ʱ� Ű��
* \param iv
* �ʱ� ���Ͱ�
* \param enc
* 1�̸� encrypt���, 0�̸� decrypt���
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_AES_INTERFACE^ISC_F_INIT_AES^ISC_ERR_INIT_KEY_FAILURE : �ʱ�ȭ�� ����
* \remarks
* iv���� key���� ���� �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_AES(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* AES ECB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_AES^ISC_F_DO_AES_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CBC���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_AES^ISC_F_DO_AES_CBC^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CFBR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param nbits
* �Է±��� ��Ʈ��(ex:CFB1->1, CFB16->16)
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* AES CFB1���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����(bit ����)
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CFB8���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CFB16���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CFB32���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CFB64���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_AES^ISC_F_DO_AES_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CFB64(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES OFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_AES^ISC_F_DO_AES_OFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* AES CTR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_AES^ISC_F_DO_AES_CTR^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_AES_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
 * \brief
 * AES OPE ���(DB���������� ���, ����������ȣ���)
 * \param unit
 * ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� BLOCK_CIPHER_UNIT ����ü
 * \param out
 * ��ȣ�� 
 * \param in
 * ��
 * \param inl
 * �Է� ����
 * \returns
 * -# L_AES^F_DO_AES_CTR^ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
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


