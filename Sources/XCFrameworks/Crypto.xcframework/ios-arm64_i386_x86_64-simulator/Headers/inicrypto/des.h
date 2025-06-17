/*!
* \file des.h
* \brief ISC_DES�˰���

�� 64, ��ȣ�� 64bits, Ű 56(64) bits, \n TriDES; �� 64, ��ȣ�� 64bits, Ű 112 bits

* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_DES_H
#define HEADER_DES_H

#include "foundation.h"
#include "mem.h"
#include "blockcipher.h"


#ifdef ISC_NO_DES
#error ISC_DES is disabled.
#endif

#define ISC_DES_ENCRYPT ISC_ENCRYPTION	/*!< ISC_DES�� ��ȣȭ*/
#define ISC_DES_DECRYPT ISC_DECRYPTION	/*!< ISC_DES�� ��ȣȭ*/

#ifndef ISC_NO_DES_EDE
#define ISC_DES_EDE_ENCRYPT ISC_ENCRYPTION	/*!< Triple ISC_DES�� ��ȣȭ*/
#define ISC_DES_EDE_DECRYPT ISC_DECRYPTION	/*!< Triple ISC_DES�� ��ȣȭ*/
#endif

/*--------------------------------------------------*/
#define ISC_DES_NAME			"ISC_DES"		
#define ISC_DES_BLOCK_SIZE		8			
#define ISC_DES_KEY_SIZE		8			
#define ISC_DES_IV_SIZE			ISC_DES_BLOCK_SIZE		
#define ISC_DES_INIT			isc_Init_DES			
#define ISC_DES_ECB_DO			isc_Do_DES_ECB			
#define ISC_DES_CBC_DO			isc_Do_DES_CBC			
#define ISC_DES_CFB_DO			isc_Do_DES_CFB	
#define ISC_DES_CFB1_DO			isc_Do_DES_CFB1	
#define ISC_DES_CFB8_DO			isc_Do_DES_CFB8	
#define ISC_DES_CFB16_DO		isc_Do_DES_CFB16	
#define ISC_DES_CFB32_DO		isc_Do_DES_CFB32
#define ISC_DES_OFB_DO			isc_Do_DES_OFB			
#define ISC_DES_CTR_DO			isc_Do_DES_CTR			
#define ISC_DES_ST_SIZE			sizeof(ISC_DES_KEY)		
/*--------------------------------------------------*/
#define ISC_DES_EDE_NAME			"ISC_DES_EDE"		
#define ISC_DES_EDE_BLOCK_SIZE		8				
#define ISC_DES_EDE_KEY_SIZE		24				
#define ISC_DES_EDE_IV_SIZE			ISC_DES_EDE_BLOCK_SIZE			
#define ISC_DES_EDE_INIT			isc_Init_DES_EDE				
#define ISC_DES_EDE_ECB_DO			isc_Do_DES_EDE_ECB				
#define ISC_DES_EDE_CBC_DO			isc_Do_DES_EDE_CBC				
#define ISC_DES_EDE_CFB_DO			isc_Do_DES_EDE_CFB		
#define ISC_DES_EDE_CFB1_DO			isc_Do_DES_EDE_CFB1	
#define ISC_DES_EDE_CFB8_DO			isc_Do_DES_EDE_CFB8	
#define ISC_DES_EDE_CFB16_DO		isc_Do_DES_EDE_CFB16	
#define ISC_DES_EDE_CFB32_DO		isc_Do_DES_EDE_CFB32
#define ISC_DES_EDE_OFB_DO			isc_Do_DES_EDE_OFB				
#define ISC_DES_EDE_CTR_DO			isc_Do_DES_EDE_CTR				
#define ISC_DES_EDE_ST_SIZE			sizeof(ISC_DES_EDE_KEY)			
/*--------------------------------------------------*/
#define ISC_DES_EDE_2KEY_NAME			"ISC_DES_EDE_2KEY"		
#define ISC_DES_EDE_2KEY_BLOCK_SIZE		8				
#define ISC_DES_EDE_2KEY_KEY_SIZE		16				
#define ISC_DES_EDE_2KEY_IV_SIZE		ISC_DES_EDE_BLOCK_SIZE			
#define ISC_DES_EDE_2KEY_INIT			isc_Init_DES_EDE				
#define ISC_DES_EDE_2KEY_ECB_DO			isc_Do_DES_EDE_ECB				
#define ISC_DES_EDE_2KEY_CBC_DO			isc_Do_DES_EDE_CBC				
#define ISC_DES_EDE_2KEY_CFB_DO			isc_Do_DES_EDE_CFB	
#define ISC_DES_EDE_2KEY_CFB1_DO		isc_Do_DES_EDE_CFB1
#define ISC_DES_EDE_2KEY_CFB8_DO		isc_Do_DES_EDE_CFB8
#define ISC_DES_EDE_2KEY_CFB16_DO		isc_Do_DES_EDE_CFB16
#define ISC_DES_EDE_2KEY_CFB32_DO		isc_Do_DES_EDE_CFB32
#define ISC_DES_EDE_2KEY_OFB_DO			isc_Do_DES_EDE_OFB				
#define ISC_DES_EDE_2KEY_CTR_DO			isc_Do_DES_EDE_CTR				
#define ISC_DES_EDE_2KEY_ST_SIZE		sizeof(ISC_DES_EDE_KEY)			
/*--------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_DES���� ���̴� ISC_DES_KEY�� ����ü
* \remarks
* uint32 key[32]
*/
typedef struct isc_des_key_st {
	uint32 key[32];
} ISC_DES_KEY;

#ifndef ISC_NO_DES_EDE
/*!
* \brief
* Triple ISC_DES���� ���̴� ISC_DES_EDE_KEY�� ����ü
* \remarks
* ISC_DES_KEY desKey[3]
*/
typedef struct isc_des3_key_st {
	ISC_DES_KEY desKey[3];
} ISC_DES_EDE_KEY;
#endif

/*!
* \brief
* ISC_DES���� ���̴� �� �ܰ��� Ű�� ����� �Լ�
* \param userkey
* �ʱ� Ű��
* \param desKey
* Ű�� ������ ��� �ִ� ����ü ����
* \param encMode
* 1�̸� Encryption, 2�̸� Decryption
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
* \remarks
* Key���� 64bit�� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_DES_Key(const uint8 *userkey, ISC_DES_KEY *desKey, short encMode);
/*!
* \brief
* �� �� 64bit�� ��ȣȭ�ϴ� ISC_DES �˰���
* \param in
* �� �� ��
* \param out
* ��ȣ�� �� ��
* \param desKey
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
* \remarks
* ISC_DES_KEY desKey�� ����Ǿ� �ִ� rounds ������ ���� ��ȣȭ
*/
ISC_INTERNAL void isc_DES_Encrypt_Block(const uint8 *in, uint8 *out, ISC_DES_KEY *desKey);

ISC_INTERNAL void isc_DES_Encrypt_Block2(const uint8 *in, uint8 *out, ISC_DES_KEY *desKey);

/*!
* \brief
* ISC_DES �ʱ� �Լ�
* \param unit
* ISC_BLOCK_CIPHER_UNIT ����ü
* \param userkey
* �ʱ� Ű��
* \param iv
* �ʱ� ���Ͱ�
* \param enc
* 1�̸� encrypt���, 0�̸� decrypt���
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# 
* \remarks
* iv���� key���� ���� �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_DES(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *userkey, const uint8 *iv, int enc);
/*!
* \brief
* ISC_DES �ʱ� Ű ���� �Լ�
* \param unit
* ISC_BLOCK_CIPHER_UNIT ����ü
* \param userkey
* �ʱ� Ű��
* \param enc
* 1�̸� encrypt���, 0�̸� decrypt���
* \returns
* -# ISC_SUCCESS : Success
* -# L_DES^ISC_F_INIT_DES_KEY^ISC_ERR_INIT_KEY_FAILURE : Ű���� ����
* \remarks
* enc �������� ���� isc_Init_Encrypt_DES_Key�� isc_Init_decrypt_DES_KEY�� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_DES_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *userkey, int enc);

/*!
* \brief
* ISC_DES ECB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* Ƚ��
* \returns
* -# L_DES^ISC_F_DO_DES_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CBC���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* Ƚ��
* \returns
* -# L_DES^ISC_F_DO_DES_CBC^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* Ƚ��
* \returns
* -# L_DES^ISC_F_DO_DES_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CFBR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param nbits
* �Է±��� ��Ʈ��(ex:CFB1->1, CFB16->16)
* \returns
* -# L_DES^ISC_F_DO_DES_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* ISC_DES CFB1���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����(bit ����)
* \returns
* -# L_DES^ISC_F_DO_DES_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CFB8���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_DES^ISC_F_DO_DES_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CFB16���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_DES^ISC_F_DO_DES_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CFB32���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_DES^ISC_F_DO_DES_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES OFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* Ƚ��
* \returns
* -# L_DES^ISC_F_DO_DES_OFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_DES CTR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* Ƚ��
* \returns
* -# L_DES^ISC_F_DO_DES_CTR^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

#ifndef ISC_NO_DES_EDE

/*                           ISC_DES_EDE                                */


/*!
* \brief
* Triple ISC_DES���� ���̴� �� �ܰ��� Ű�� ����� �Լ�
* \param userKey
* �ʱ� Ű��
* \param userKeyLen
* �ʱ� Ű ����
* \param desEdeKey
* Ű�� ������ ��� �ִ� ����ü ����
* \param encMode
* 1�̸� Encryption, 0�̸� Decryption
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
/*ISC_STATUS isc_Init_Encrypt_DES_EDE_KEY(const uint8 *userKey, int userKeyLen, ISC_DES_EDE_KEY *desEdeKey, short encMode); */
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_DES_EDE_KEY(const uint8 *userKey, int userKeyLen, ISC_DES_EDE_KEY *desEdeKey, short encMode);
/*!
* \brief
* �� �� 64bit�� ��ȣȭ�ϴ� Triple ISC_DES �˰���
* \param in
* �� �� ��
* \param out
* ��ȣ�� �� ��
* \param desEdeKey
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
* \remarks
* ISC_DES_EDE_KEY desEdeKey�� ����Ǿ� �ִ� Ű���� ���� ��ȣȭ�Ѵ�.
*/
ISC_INTERNAL void DES_EDE_encrypt_block(uint8 *in, uint8 *out, ISC_DES_EDE_KEY *desEdeKey);

/*!
* \brief
* Triple ISC_DES �ʱ� �Լ�
* \param unit
* ISC_BLOCK_CIPHER_UNIT ����ü
* \param userkey
* �ʱ� Ű��
* \param iv
* �ʱ� ���Ͱ�
* \param enc
* 1�̸� encrypt���, 0�̸� decrypt���
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
* \remarks
* iv���� key���� ���� �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_DES_EDE(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *userkey, const uint8 *iv, int enc);

/*!
* \brief
* Triple ISC_DES���� ���̴� �� �ܰ��� Ű�� ����� �Լ�
* \param unit
* Ű�� ������ ��� �ִ� ����ü ����
* \param userkey
* �ʱ� Ű��
* \param enc
* Encryption or Decryption
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_INTERNAL ISC_STATUS isc_Init_DES_EDE_key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *userkey, int enc);

/*!
* \brief
* Triple ISC_DES ECB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* Ƚ��
* \returns
* -# L_DES_EDE^ISC_F_DO_DES_EDE_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, uint8 *in, uint32 inl);
/*!
* \brief
* Triple ISC_DES CBC���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* Ƚ��
* \returns
* -# L_DES_EDE^ISC_F_DO_DES_EDE_CBC^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, uint8 *in, uint32 inl);
/*!
* \brief
* Triple ISC_DES CFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* Ƚ��
* \returns
* -# L_DES_EDE^ISC_F_DO_DES_EDE_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, uint8 *in, uint32 inl);

ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);


/*!
* \brief
* Triple ISC_DES OFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* Ƚ��
* \returns
* -# L_DES_EDE^ISC_F_DO_DES_EDE_OFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, uint8 *in, uint32 inl);
/*!
* \brief
* Triple ISC_DES CTR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* Ƚ��
* \returns
* -# L_DES_EDE^ISC_F_DO_DES_EDE_CTR^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_DES_EDE_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, uint8 *in, uint32 inl);

#endif

#ifdef  __cplusplus
}
#endif

#endif/* HEADER_DES_H */

