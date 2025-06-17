/*!
* \file aria.h
* \brief ARIA �˰���

�� 128, ��ȣ�� 128bits, Ű 128,192,256 bits\n

* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_ARIA_H
#define HEADER_ARIA_H

#include "foundation.h"
#include "mem.h"
#include "blockcipher_mac.h"

#ifdef ISC_NO_ARIA
#error ARIA is disabled.
#endif

#define ISC_ARIA_ENCRYPT	1			/*!< ARIA�� ��ȣȭ*/
#define ISC_ARIA_DECRYPT	0			/*!< ARIA�� ��ȣȭ*/

#define ISC_ARIA_BLOCK_SIZE	16			/*!< ARIA�� BLOCK_SIZE*/
#define ISC_ARIA_WORD_SIZE  4

#define ISC_ARIA_MAXKB	32
#define ISC_ARIA_MAXNR	16

/*--------------------------------------------------*/
#define ISC_ARIA128_NAME			"ARIA_128"			
#define ISC_ARIA128_BLOCK_SIZE		ISC_ARIA_BLOCK_SIZE		
#define ISC_ARIA128_KEY_SIZE		16					
#define ISC_ARIA128_IV_SIZE			ISC_ARIA_BLOCK_SIZE		
#define ISC_ARIA128_INIT			isc_Init_ARIA			
#define ISC_ARIA128_ECB_DO			isc_Do_ARIA_ECB			
#define ISC_ARIA128_CBC_DO			isc_Do_ARIA_CBC			
#define ISC_ARIA128_CFB_DO			isc_Do_ARIA_CFB		
#define ISC_ARIA128_CFB1_DO			isc_Do_ARIA_CFB1	
#define ISC_ARIA128_CFB8_DO			isc_Do_ARIA_CFB8	
#define ISC_ARIA128_CFB16_DO		isc_Do_ARIA_CFB16	
#define ISC_ARIA128_CFB32_DO		isc_Do_ARIA_CFB32	
#define ISC_ARIA128_CFB64_DO		isc_Do_ARIA_CFB64	
#define ISC_ARIA128_OFB_DO			isc_Do_ARIA_OFB			
#define ISC_ARIA128_CTR_DO			isc_Do_ARIA_CTR	
#define ISC_ARIA128_CCM_DO			isc_Do_ARIA_CCM		
#define ISC_ARIA128_GCM_DO			isc_Do_ARIA_GCM		
#define ISC_ARIA128_ST_SIZE			sizeof(ISC_ARIA_KEY)	
/*--------------------------------------------------*/
/*--------------------------------------------------*/
#define ISC_ARIA192_NAME			"ARIA_192"			
#define ISC_ARIA192_BLOCK_SIZE		ISC_ARIA_BLOCK_SIZE		
#define ISC_ARIA192_KEY_SIZE		24					
#define ISC_ARIA192_IV_SIZE			ISC_ARIA_BLOCK_SIZE		
#define ISC_ARIA192_INIT			isc_Init_ARIA			
#define ISC_ARIA192_ECB_DO			isc_Do_ARIA_ECB			
#define ISC_ARIA192_CBC_DO			isc_Do_ARIA_CBC			
#define ISC_ARIA192_CFB_DO			isc_Do_ARIA_CFB		
#define ISC_ARIA192_CFB1_DO			isc_Do_ARIA_CFB1	
#define ISC_ARIA192_CFB8_DO			isc_Do_ARIA_CFB8	
#define ISC_ARIA192_CFB16_DO		isc_Do_ARIA_CFB16	
#define ISC_ARIA192_CFB32_DO		isc_Do_ARIA_CFB32	
#define ISC_ARIA192_CFB64_DO		isc_Do_ARIA_CFB64	
#define ISC_ARIA192_OFB_DO			isc_Do_ARIA_OFB			
#define ISC_ARIA192_CTR_DO			isc_Do_ARIA_CTR
#define ISC_ARIA192_CCM_DO			isc_Do_ARIA_CCM		
#define ISC_ARIA192_GCM_DO			isc_Do_ARIA_GCM	
#define ISC_ARIA192_ST_SIZE			sizeof(ISC_ARIA_KEY)	
/*--------------------------------------------------*/
/*--------------------------------------------------*/
#define ISC_ARIA256_NAME			"ARIA_256"			
#define ISC_ARIA256_BLOCK_SIZE		ISC_ARIA_BLOCK_SIZE		
#define ISC_ARIA256_KEY_SIZE		32					
#define ISC_ARIA256_IV_SIZE			ISC_ARIA_BLOCK_SIZE		
#define ISC_ARIA256_INIT			isc_Init_ARIA			
#define ISC_ARIA256_ECB_DO			isc_Do_ARIA_ECB			
#define ISC_ARIA256_CBC_DO			isc_Do_ARIA_CBC			
#define ISC_ARIA256_CFB_DO			isc_Do_ARIA_CFB	
#define ISC_ARIA256_CFB1_DO			isc_Do_ARIA_CFB1	
#define ISC_ARIA256_CFB8_DO			isc_Do_ARIA_CFB8	
#define ISC_ARIA256_CFB16_DO		isc_Do_ARIA_CFB16	
#define ISC_ARIA256_CFB32_DO		isc_Do_ARIA_CFB32	
#define ISC_ARIA256_CFB64_DO		isc_Do_ARIA_CFB64	
#define ISC_ARIA256_OFB_DO			isc_Do_ARIA_OFB			
#define ISC_ARIA256_CTR_DO			isc_Do_ARIA_CTR		
#define ISC_ARIA256_CCM_DO			isc_Do_ARIA_CCM		
#define ISC_ARIA256_GCM_DO			isc_Do_ARIA_GCM	
#define ISC_ARIA256_ST_SIZE			sizeof(ISC_ARIA_KEY)	
/*--------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * ARIA�� Ű�� ���̴� ������ �ٷ� ����ü
 * \remarks
 * rd_key1(��ȣȭŰ), rd_key2(��ȣȭŰ), rounds(�����)
 */
struct isc_aria_key_st {
	uint32 rd_key1[ISC_ARIA_WORD_SIZE * (ISC_ARIA_MAXNR + 1)];
	uint32 rd_key2[ISC_ARIA_WORD_SIZE * (ISC_ARIA_MAXNR + 1)];
	int rounds;
} ;

typedef struct isc_aria_key_st ISC_ARIA_KEY;
/*!
* \brief
* ARIA���� ���̴� �� �ܰ��� Ű�� ����� �Լ�
* \param KLR
* �ʱ� Ű��
* \param keysize
* Ű�� ������(bytes)
* \param key
* Ű�� ������ ��� �ִ� ����ü ����
* \returns
* -# INI_CRYPT_SUCCESS : Success
* -# INI_CRYPT_FAIL : Fail
* \remarks
* Key���� 128, 192, �׸��� 256��Ʈ�� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_ARIA_Key(const uint8 *KLR, const int keysize, ISC_ARIA_KEY *key);
/*!
* \brief
* ��ȣȭ�Ҷ� ���̴� �� �ܰ��� Ű�� ����� �Լ�
* \param KLR
* �ʱ� Ű��
* \param keysize
* Ű�� ������(bytes)
* \param key
* Ű�� ������ ��� �ִ� ����ü ����
* \returns
* -# INI_CRYPT_SUCCESS : Success
* -# INI_CRYPT_FAIL : Fail
* \remarks
* Key���� 128, 192, �׸��� 256��Ʈ�� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_Decrypt_ARIA_Key(const uint8 *KLR, const int keysize, ISC_ARIA_KEY *key);

/*!
* \brief
* ARIA �ʱ� Ű ���� �Լ�
* \param unit
* ISC_BLOCK_CIPHER_UNIT ����ü
* \param key
* �ʱ� Ű��
* \param enc
* 1�̸� encrypt���, 0�̸� decrypt���
* \returns
* -# ISC_SUCCESS : Success
* -# L_ARIA^ISC_F_INIT_ARIA_KEY^ISC_ERR_INIT_KEY_FAILURE : Ű ���� ����
* \remarks
* enc �������� ���� isc_Init_Encrypt_ARIA_Key�� isc_Init_Decrypt_ARIA_Key�� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_ARIA_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, int enc);
/*!
* \brief
* ARIA �ʱ� �Լ�
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
* -# isc_Init_ARIA_Key() ��� ����
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# L_ARIA^ISC_F_INIT_ARIA^ISC_ERR_INIT_FAILURE : �ʱ�ȭ ����
* \remarks
* iv���� key���� ���� �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_ARIA(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* �� �� 128bit�� ��ȣȭ�ϴ� ARIA �˰���
* \param in
* �� �� ��
* \param out
* ��ȣ�� �� ��
* \param key
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
* \remarks
* ISC_ARIA_KEY key�� ����Ǿ� �ִ� rounds ������ ���� 128, 192, 256��忡 ���� ��ȣȭ
*/
ISC_INTERNAL void isc_ARIA_Encrypt_Block(const uint8 *in, uint8 *out, const ISC_ARIA_KEY *key);
/*!
* \brief
* �� �� 128bit�� ��ȣȭ�ϴ� ARIA �˰���
* \param in
* ��ȣ�� �� ��
* \param out
* �� �� ��
* \param key
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
* \remarks
* ISC_ARIA_KEY key�� ����Ǿ� �ִ� rounds ������ ���� 128, 192, 256��忡 ���� ��ȣȭ
*/
ISC_INTERNAL void isc_ARIA_Decrypt_Block(const uint8 *in, uint8 *out, const ISC_ARIA_KEY *key);

/*!
* \brief
* ARIA ECB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CBC���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA OFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CBC^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CFBR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param nbits
* �Է±��� ��Ʈ��(ex:CFB1->1, CFB16->16)
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* ARIA CFB1���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����(bit ����)
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CFB8���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CFB16���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CFB32���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* ARIA CFB64���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CFB64(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* ARIA CTR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_ARIA^ISC_F_DO_ARIA_CTR^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

ISC_INTERNAL ISC_STATUS isc_Do_ARIA_CCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_ARIA_GCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_ARIA_H */

