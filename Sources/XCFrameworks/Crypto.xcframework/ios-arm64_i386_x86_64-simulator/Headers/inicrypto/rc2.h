/*!
* \file rc2.h
* \brief RC2 �˰���
* �� 64bits, ��ȣ�� 64bits, Ű 128bits\n
* \remarks
* RC2�� 32bit OS�� ������� ����, round���� 12�� �⺻����
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

#define ISC_RC2_ENCRYPT	1			/*!< RC2�� ��ȣȭ*/
#define ISC_RC2_DECRYPT	0			/*!< RC2�� ��ȣȭ*/

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
 * RC2�� Ű�� ���̴� ������ �ٷ� ����ü
 * \remarks
 * K(Ű), R(�����), RC2 K������ ���� eff_keybit,eff_keybyte,eff_keym
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
* RC2���� ���̴� �� �ܰ��� Ű�� ����� �Լ�
* \param data
* �ʱ� Ű��
* \param len
* Ű�� bit ������
* \param key
* Ű�� ������ ��� �ִ� ����ü ����
* \param bit
* ��������
* \returns
* -# INI_CRYPT_SUCCESS : Success
* -# INI_CRYPT_FAIL : Fail
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_RC2_Key(size_t eff_keylen, const uint8 *data, int len, ISC_RC2_KEY *key);

/*!
* \brief
* RC2���� ���̴� �� �ܰ��� Ű�� ����� �Լ�
* \param data
* �ʱ� Ű��
* \param len
* Ű�� bit ������
* \param key
* Ű�� ������ ��� �ִ� ����ü ����
* \param bit
* RC2 �� ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_INTERNAL ISC_STATUS isc_Init_RC2_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key);

/*!
* \brief
* RC2 �ʱ� �Լ�
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
* -# isc_Init_encrypto_RC2_KEY�� ����
*  -# L_RC2^ISC_F_INIT_RC2_KEY^ISC_ERR_INIT_KEY_FAILURE : �ʱ� Ű ���� ����
* \remarks
* iv���� key���� ���� �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_RC2(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* �� �� 64bit�� ��ȣȭ�ϴ� RC2 �˰���
* \param in_out
* �� �� ��, ��°��� �ٽ� ����.
* \param key
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
*/
ISC_INTERNAL void isc_RC2_Encrypt_Block(uint16 *in_out, ISC_RC2_KEY *key);

/*!
* \brief
* �� �� 64bit�� ��ȣȭ�ϴ� RC2 �˰���
* \param in_out
* ��ȣ�� �� ��, ��°��� �ٽ� ����.
* \param key
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
*/
ISC_INTERNAL void isc_RC2_Decrypt_Block(uint16 *in_out, ISC_RC2_KEY *key);

/*!
* \brief
* RC2 ECB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 CBC���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 CFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 CFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param nbits
* �Է±��� ��Ʈ��(ex:CFB1->1, CFB16->16)
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* RC2 CFB1���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����(bit ����)
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 CFB8���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 CFB16���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 CFB32���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* RC2 OFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_RC2^ISC_F_DO_RC2_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_RC2_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_RC2_H */

