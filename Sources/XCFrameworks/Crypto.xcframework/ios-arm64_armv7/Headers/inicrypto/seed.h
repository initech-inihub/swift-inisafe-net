/*!
 * \file seed.h
 * \brief ISC_SEED
 
 �� 128, ��ȣ�� 128bits, Ű 128 bits\n

 * \author
 * Copyright (c) 2008 by \<INITech\>
 */
 
#ifndef HEADER_SEED_H
#define HEADER_SEED_H

#include "foundation.h"
#include "mem.h"
#include "blockcipher_mac.h"

#ifdef ISC_NO_SEED
#error ISC_SEED is disabled.
#endif

#define ISC_SEED_ENCRYPT	1			/*!< ISC_SEED�� ��ȣȭ*/
#define ISC_SEED_DECRYPT	0			/*!< ISC_SEED�� ��ȣȭ*/

/*--------------------------------------------------*/
#define ISC_SEED_NAME				"ISC_SEED"				
#define ISC_SEED_BLOCK_SIZE			16					
#define ISC_SEED_KEY_SIZE			16					
#define ISC_SEED_IV_SIZE			ISC_SEED_BLOCK_SIZE		
#define ISC_SEED_INIT				isc_Init_SEED			
#define ISC_SEED_ECB_DO				isc_Do_SEED_ECB			
#define ISC_SEED_CBC_DO				isc_Do_SEED_CBC			
#define ISC_SEED_CFB_DO				isc_Do_SEED_CFB	
#define ISC_SEED_CFB1_DO			isc_Do_SEED_CFB1
#define ISC_SEED_CFB8_DO			isc_Do_SEED_CFB8
#define ISC_SEED_CFB16_DO			isc_Do_SEED_CFB16
#define ISC_SEED_CFB32_DO			isc_Do_SEED_CFB32
#define ISC_SEED_CFB64_DO			isc_Do_SEED_CFB64
#define ISC_SEED_OFB_DO				isc_Do_SEED_OFB			
#define ISC_SEED_CTR_DO				isc_Do_SEED_CTR		
#define ISC_SEED_CCM_DO				isc_Do_SEED_CCM	
#define ISC_SEED_GCM_DO				isc_Do_SEED_GCM	
#define ISC_SEED_ST_SIZE			sizeof(ISC_SEED_KEY)	
/*--------------------------------------------------*/
#define ISC_SEED256_NAME			"SEED_256"				
#define ISC_SEED256_BLOCK_SIZE		ISC_SEED_BLOCK_SIZE					
#define ISC_SEED256_KEY_SIZE		32					
#define ISC_SEED256_IV_SIZE			ISC_SEED_BLOCK_SIZE		
#define ISC_SEED256_INIT			isc_Init_SEED			
#define ISC_SEED256_ECB_DO			isc_Do_SEED_ECB			
#define ISC_SEED256_CBC_DO			isc_Do_SEED_CBC			
#define ISC_SEED256_CFB_DO			isc_Do_SEED_CFB	
#define ISC_SEED256_CFB1_DO			isc_Do_SEED_CFB1
#define ISC_SEED256_CFB8_DO			isc_Do_SEED_CFB8
#define ISC_SEED256_CFB16_DO		isc_Do_SEED_CFB16
#define ISC_SEED256_CFB32_DO		isc_Do_SEED_CFB32
#define ISC_SEED256_CFB64_DO		isc_Do_SEED_CFB64
#define ISC_SEED256_OFB_DO			isc_Do_SEED_OFB			
#define ISC_SEED256_CTR_DO			isc_Do_SEED_CTR		
#define ISC_SEED256_CCM_DO			isc_Do_SEED_CCM	
#define ISC_SEED256_GCM_DO			isc_Do_SEED_GCM	
#define ISC_SEED256_ST_SIZE			sizeof(ISC_SEED_KEY)	
/*--------------------------------------------------*/
#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * ISC_SEED���� ���̴� ISC_SEED_KEY�� ����ü
 * \remarks
 * uint32 data[32] �ڷ���
 */
typedef struct isc_seed_key_st {
    uint32 data[48];
	int rounds;
} ISC_SEED_KEY;

/*!
* \brief
* �� �� 128bit�� ��ȣȭ�ϴ� ISC_SEED �˰���
* \param in
* �� �� ��
* \param out
* ��ȣ�� �� ��
* \param ks
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
* \remarks
* ISC_SEED_KEY key�� ����Ǿ� �ִ� rounds ������ ���� 128, 192, 256��忡 ���� ��ȣȭ
*/
ISC_INTERNAL void isc_SEED_Encrypt_Block(const uint8 *in, uint8 *out, const ISC_SEED_KEY *ks);
/*!
* \brief
* �� �� 128bit�� ��ȣȭ�ϴ� ISC_SEED �˰���
* \param in
* ��ȣ�� �� ��
* \param out
* �� �� ��
* \param ks
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
*/
ISC_INTERNAL void isc_SEED_Decrypt_Block(const uint8 *in, uint8 *out, const ISC_SEED_KEY *ks);

/*!
* \brief
* ISC_SEED���� ���̴� �� �ܰ��� Ű�� ����� �Լ�
* \param userKey
* �ʱ� Ű��
* \param ks
* Ű�� ������ ��� �ִ� ����ü ����
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_SEED_Key(const uint8 *userKey, ISC_SEED_KEY *ks);

/*!
* \brief
* ISC_SEED���� ���̴� �� �ܰ��� Ű�� ����� �Լ�(256bit)
* \param userKey
* �ʱ� Ű��
* \param ks
* Ű�� ������ ��� �ִ� ����ü ����
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_SEED_Key_256(const uint8 *userKey, ISC_SEED_KEY *ks);

/*!
* \brief
* ISC_SEED �ʱ� Ű ���� �Լ�
* \param unit
* ISC_BLOCK_CIPHER_UNIT ����ü
* \param key
* �ʱ� Ű��
* \param enc
* 1�̸� encrypt���, 0�̸� decrypt���
* \returns
* -# ISC_SUCCESS : Success
* -# L_SEED^ISC_F_INIT_SEED_KEY^ISC_ERR_INIT_KEY_FAILURE : Ű INIT �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_SEED_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, int enc);
/*!
* \brief
* ISC_SEED �ʱ� �Լ�
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
* -# L_SEED^ISC_F_INIT_SEED^ISC_ERR_INIT_FAILURE : �ʱ�ȭ �Լ� ����
* \remarks
* iv���� key���� ���� �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_SEED(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* ISC_SEED ECB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_SEED^ISC_F_DO_SEED_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CBC���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_SEED^ISC_F_DO_SEED_CBC^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CFBR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param nbits
* �Է±��� ��Ʈ��(ex:CFB1->1, CFB16->16)
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* ISC_SEED CFB1���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����(bit ����)
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CFB8���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CFB16���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CFB32���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CFB64���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_SEED^ISC_F_DO_SEED_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CFB64(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* ISC_SEED OFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_SEED^ISC_F_DO_SEED_OFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_SEED CTR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_SEED^ISC_F_DO_SEED_CTR^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_SEED_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

ISC_INTERNAL ISC_STATUS isc_Do_SEED_CCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

ISC_INTERNAL ISC_STATUS isc_Do_SEED_GCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
#ifdef  __cplusplus
}
#endif

#endif /* HEADER_SEED_H */

