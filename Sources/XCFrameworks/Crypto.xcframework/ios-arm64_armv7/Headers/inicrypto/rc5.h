/*!
* \file rc5.h
* \brief ISC_RC5 �˰���
* �� 64bits, ��ȣ�� 64bits, Ű 128bits\n
* \remarks
* ISC_RC5�� 32bit OS�� ������� ����, round���� 12�� �⺻����
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_RC5_H
#define HEADER_RC5_H

#include "foundation.h"
#include "mem.h"

#ifdef ISC_NO_RC5
#error ISC_RC5 is disabled.
#endif

#define ISC_RC5_ENCRYPT	1			/*!< ISC_RC5�� ��ȣȭ*/
#define ISC_RC5_DECRYPT	0			/*!< ISC_RC5�� ��ȣȭ*/

#define ISC_RC5_ROUNDS_8	8
#define ISC_RC5_ROUNDS_12	12
#define ISC_RC5_ROUNDS_16	16

#define ISC_RC5_ROUNDS	ISC_RC5_ROUNDS_12

/*--------------------------------------------------*/
#define ISC_RC5_NAME				"ISC_RC5"
#define ISC_RC5_BLOCK_SIZE			8
#define ISC_RC5_KEY_SIZE			16
#define ISC_RC5_IV_SIZE				ISC_RC5_BLOCK_SIZE		
#define ISC_RC5_INIT				isc_Init_RC5			
#define ISC_RC5_ECB_DO				isc_Do_RC5_ECB			
#define ISC_RC5_CBC_DO				isc_Do_RC5_CBC			
#define ISC_RC5_CFB_DO				isc_Do_RC5_CFB	
#define ISC_RC5_CFB1_DO				isc_Do_RC5_CFB1
#define ISC_RC5_CFB8_DO				isc_Do_RC5_CFB8
#define ISC_RC5_CFB16_DO			isc_Do_RC5_CFB16
#define ISC_RC5_CFB32_DO			isc_Do_RC5_CFB32
#define ISC_RC5_CFB64_DO			isc_Do_RC5_CFB64
#define ISC_RC5_CFB128_DO			isc_Do_RC5_CFB
#define ISC_RC5_OFB_DO				isc_Do_RC5_OFB			
#define ISC_RC5_CTR_DO				isc_Do_RC5_CTR			
#define ISC_RC5_ST_SIZE				sizeof(ISC_RC5_KEY)	
/*--------------------------------------------------*/


#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * ISC_RC5�� Ű�� ���̴� ������ �ٷ� ����ü
 * \remarks
 * rd_key(Ű), rounds(�����)
 */
struct isc_rc5_key_st {
	uint32 rd_key[(ISC_RC5_ROUNDS_16+1)*2];
	int rounds;
} ;

typedef struct isc_rc5_key_st ISC_RC5_KEY;

/*!
* \brief
* ISC_RC5���� ���̴� �� �ܰ��� Ű�� ����� �Լ�
* \param data
* �ʱ� Ű��
* \param len
* Ű�� bit ������
* \param key
* Ű�� ������ ��� �ִ� ����ü ����
* \returns
* -# INI_CRYPT_SUCCESS : Success
* -# INI_CRYPT_FAIL : Fail
* \remarks
* Key���� �⺻������ 128��Ʈ
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_RC5_Key(const uint8 *data, int len, ISC_RC5_KEY *key);

/*!
* \brief
* ISC_RC5 �ʱ� Ű ���� �Լ�
* \param unit
* ISC_BLOCK_CIPHER_UNIT ����ü
* \param key
* �ʱ� Ű��
* \returns
* -# ISC_SUCCESS : Success
* -# L_RC5^ISC_F_INIT_RC5_KEY^ISC_ERR_INIT_KEY_FAILURE : �ʱ� Ű ���� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_RC5_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key);
/*!
* \brief
* ISC_RC5 �ʱ� �Լ�
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
* -# isc_Init_encrypto_RC5_KEY�� ����
*  -# L_RC5^ISC_F_INIT_RC5_KEY^ISC_ERR_INIT_KEY_FAILURE : �ʱ� Ű ���� ����
* \remarks
* iv���� key���� ���� �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_RC5(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* �� �� 64bit�� ��ȣȭ�ϴ� ISC_RC5 �˰���
* \param in_out
* �� �� ��, ��°��� �ٽ� ����.
* \param key
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
*/
ISC_INTERNAL void isc_RC5_Encrypt_Block(uint32 *in_out, ISC_RC5_KEY *key);

/*!
* \brief
* �� �� 64bit�� ��ȣȭ�ϴ� ISC_RC5 �˰���
* \param in_out
* ��ȣ�� �� ��, ��°��� �ٽ� ����.
* \param key
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
*/
ISC_INTERNAL void isc_RC5_Decrypt_Block(uint32 *in_out, ISC_RC5_KEY *key);

/*!
* \brief
* ISC_RC5 ECB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CBC���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param nbits
* �Է±��� ��Ʈ��(ex:CFB1->1, CFB16->16)
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* ISC_RC5 CFB1���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����(bit ����)
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CFB8���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CFB16���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CFB32���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CFB64���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CFB64(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 OFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ISC_RC5 CTR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC5^ISC_F_DO_RC5_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC5_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_RC5_H */

