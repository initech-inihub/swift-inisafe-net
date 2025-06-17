/*!
* \file lea.h
* \brief LEA �˰���

�� 128, ��ȣ�� 128bits, Ű 128,192,256 bits\n

* \author
* Copyright (c) 2013 by \<INITech\>
*/

#ifndef HEADER_LEA_H
#define HEADER_LEA_H

#include "foundation.h"
#include "mem.h"
#include "blockcipher_mac.h"

#ifdef NO_LEA
#error LEA is disabled.
#endif

#define ISC_LEA_ENCRYPT	1			/*!< LEA�� ��ȣȭ*/
#define ISC_LEA_DECRYPT	0			/*!< LEA�� ��ȣȭ*/

#define ISC_LEA_BLOCK_SIZE	16		/*!< LEA�� BLOCK_SIZE*/
#define ISC_LEA_WORD_SIZE	4

#define ISC_LEA128_RND		24
#define ISC_LEA192_RND		28
#define ISC_LEA256_RND		32

#define ISC_LEA_RND_128_KEY_BYTE_LEN ISC_LEA128_RND*6
#define ISC_LEA_RND_192_KEY_BYTE_LEN ISC_LEA192_RND*6
#define ISC_LEA_RND_256_KEY_BYTE_LEN ISC_LEA256_RND*6
#define ISC_LEA_RND_MAX_KEY_BYTE_LEN ISC_LEA_RND_256_KEY_BYTE_LEN

/*--------------------------------------------------*/
#define ISC_LEA128_NAME				"LEA_128"			
#define ISC_LEA128_BLOCK_SIZE		ISC_LEA_BLOCK_SIZE		
#define ISC_LEA128_KEY_SIZE			16					
#define ISC_LEA128_IV_SIZE			ISC_LEA_BLOCK_SIZE		
#define ISC_LEA128_INIT				isc_Init_LEA			
#define ISC_LEA128_ECB_DO			isc_Do_LEA_ECB			
#define ISC_LEA128_CBC_DO			isc_Do_LEA_CBC			
#define ISC_LEA128_CFB_DO			isc_Do_LEA_CFB		
#define ISC_LEA128_CFB1_DO			isc_Do_LEA_CFB1	
#define ISC_LEA128_CFB8_DO			isc_Do_LEA_CFB8	
#define ISC_LEA128_CFB16_DO			isc_Do_LEA_CFB16	
#define ISC_LEA128_CFB32_DO			isc_Do_LEA_CFB32	
#define ISC_LEA128_CFB64_DO			isc_Do_LEA_CFB64	
#define ISC_LEA128_OFB_DO			isc_Do_LEA_OFB			
#define ISC_LEA128_CTR_DO			isc_Do_LEA_CTR
#define ISC_LEA128_CCM_DO			isc_Do_LEA_CCM	
#define ISC_LEA128_GCM_DO			isc_Do_LEA_GCM	
#define ISC_LEA128_ST_SIZE			sizeof(ISC_LEA_KEY)	
/*--------------------------------------------------*/
/*--------------------------------------------------*/
#define ISC_LEA192_NAME				"LEA_192"			
#define ISC_LEA192_BLOCK_SIZE		ISC_LEA_BLOCK_SIZE		
#define ISC_LEA192_KEY_SIZE			24					
#define ISC_LEA192_IV_SIZE			ISC_LEA_BLOCK_SIZE		
#define ISC_LEA192_INIT				isc_Init_LEA			
#define ISC_LEA192_ECB_DO			isc_Do_LEA_ECB			
#define ISC_LEA192_CBC_DO			isc_Do_LEA_CBC			
#define ISC_LEA192_CFB_DO			isc_Do_LEA_CFB		
#define ISC_LEA192_CFB1_DO			isc_Do_LEA_CFB1	
#define ISC_LEA192_CFB8_DO			isc_Do_LEA_CFB8	
#define ISC_LEA192_CFB16_DO			isc_Do_LEA_CFB16	
#define ISC_LEA192_CFB32_DO			isc_Do_LEA_CFB32	
#define ISC_LEA192_CFB64_DO			isc_Do_LEA_CFB64	
#define ISC_LEA192_OFB_DO			isc_Do_LEA_OFB			
#define ISC_LEA192_CTR_DO			isc_Do_LEA_CTR		
#define ISC_LEA192_CCM_DO			isc_Do_LEA_CCM	
#define ISC_LEA192_GCM_DO			isc_Do_LEA_GCM	
#define ISC_LEA192_ST_SIZE			sizeof(ISC_LEA_KEY)	
/*--------------------------------------------------*/
/*--------------------------------------------------*/
#define ISC_LEA256_NAME				"LEA_256"			
#define ISC_LEA256_BLOCK_SIZE		ISC_LEA_BLOCK_SIZE		
#define ISC_LEA256_KEY_SIZE			32					
#define ISC_LEA256_IV_SIZE			ISC_LEA_BLOCK_SIZE		
#define ISC_LEA256_INIT				isc_Init_LEA			
#define ISC_LEA256_ECB_DO			isc_Do_LEA_ECB			
#define ISC_LEA256_CBC_DO			isc_Do_LEA_CBC			
#define ISC_LEA256_CFB_DO			isc_Do_LEA_CFB	
#define ISC_LEA256_CFB1_DO			isc_Do_LEA_CFB1	
#define ISC_LEA256_CFB8_DO			isc_Do_LEA_CFB8	
#define ISC_LEA256_CFB16_DO			isc_Do_LEA_CFB16	
#define ISC_LEA256_CFB32_DO			isc_Do_LEA_CFB32	
#define ISC_LEA256_CFB64_DO			isc_Do_LEA_CFB64	
#define ISC_LEA256_OFB_DO			isc_Do_LEA_OFB			
#define ISC_LEA256_CTR_DO			isc_Do_LEA_CTR		
#define ISC_LEA256_CCM_DO			isc_Do_LEA_CCM	
#define ISC_LEA256_GCM_DO			isc_Do_LEA_GCM	
#define ISC_LEA256_ST_SIZE			sizeof(ISC_LEA_KEY)	
/*--------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * LEA�� Ű�� ���̴� ������ �ٷ� ����ü
 * \remarks
 * rd_key(����Ű), rounds(�����)
 */
struct isc_lea_key_st {
	uint32 rd_key[ISC_LEA_RND_MAX_KEY_BYTE_LEN];
	int rounds;
};

typedef struct isc_lea_key_st ISC_LEA_KEY;
/*!
* \brief
* LEA���� ���̴� �� �ܰ��� Ű�� ����� �Լ�
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
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_LEA_Key(const uint8 *user_key, const int key_size, ISC_LEA_KEY *key);

/*!
* \brief
* LEA �ʱ� Ű ���� �Լ�
* \param unit
* ISC_BLOCK_CIPHER_UNIT ����ü
* \param key
* �ʱ� Ű��
* \param enc
* 1�̸� encrypt���, 0�̸� decrypt���
* \returns
* -# ISC_SUCCESS : Success
* -# L_LEA^ISC_F_INIT_LEA_KEY^ISC_ERR_INIT_KEY_FAILURE : Ű ���� ����
* \remarks
* enc �������� ���� isc_Init_Encrypt_LEA_Key�� isc_Init_decrypt_LEA_KEY�� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_LEA_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, int enc);

/*!
* \brief
* LEA �ʱ� �Լ�
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
* -# isc_Init_LEA_Key() ��� ����
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# L_LEA^ISC_F_INIT_LEA^ISC_ERR_INIT_FAILURE : �ʱ�ȭ ����
* \remarks
* iv���� key���� ���� �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_LEA(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* �� �� 128bit�� ��ȣȭ�ϴ� LEA �˰���
* \param in
* �� �� ��
* \param out
* ��ȣ�� �� ��
* \param key
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
* \remarks
* ISC_LEA_KEY key�� ����Ǿ� �ִ� rounds ������ ���� 128, 192, 256��忡 ���� ��ȣȭ
*/
ISC_INTERNAL void isc_LEA_Encrypt_Block(const uint8 *in, uint8 *out, const ISC_LEA_KEY *key);

/*!
* \brief
* �� �� 128bit�� ��ȣȭ�ϴ� LEA �˰���
* \param in
* ��ȣ�� �� ��
* \param out
* �� �� ��
* \param key
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
* \remarks
* ISC_LEA_KEY key�� ����Ǿ� �ִ� rounds ������ ���� 128, 192, 256��忡 ���� ��ȣȭ
*/
ISC_INTERNAL void isc_LEA_Decrypt_Block(const uint8 *in, uint8 *out, const ISC_LEA_KEY *key);

/*!
* \brief
* LEA ECB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_LEA^ISC_F_DO_LEA_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CBC���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_LEA^ISC_F_DO_LEA_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA OFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_LEA^ISC_F_DO_LEA_CBC^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CFBR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param nbits
* �Է±��� ��Ʈ��(ex:CFB1->1, CFB16->16)
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);

/*!
* \brief
* LEA CFB1���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����(bit ����)
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CFB8���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CFB16���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CFB32���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CFB64���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_LEA^ISC_F_DO_LEA_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CFB64(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

/*!
* \brief
* LEA CTR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ISC_BLOCK_CIPHER_UNIT����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_LEA^ISC_F_DO_LEA_CTR^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_LEA_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

ISC_INTERNAL ISC_STATUS isc_Do_LEA_CCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
ISC_INTERNAL ISC_STATUS isc_Do_LEA_GCM(ISC_BLOCK_CIPHER_MAC_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
#ifdef  __cplusplus
}
#endif
#endif /* HEADER_LEA_H */

