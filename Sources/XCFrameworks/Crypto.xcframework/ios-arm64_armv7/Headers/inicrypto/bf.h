/*!
 * \file bf.h
 * \brief BlowFish
 * BlowFish �� 64, ��ȣ�� 64bits, Ű 4 ~ 56bytes \n
 * \remarks
 * round���� 16�� �⺻����, Ű�� �⺻������ 16����Ʈ�� ����Ǹ�, \n
 * ����Ű ������ ���ؼ� isc_Init_Encrypt_BF_Key�� ����Ͽ��� ��
 * \author
 * Copyright (c) 2008 by \<INITech\>
 */
 
#ifndef HEADER_BF_H
#define HEADER_BF_H

#include "foundation.h"
#include "mem.h"

#ifdef ISC_NO_BF
#error ISC_BF is disabled.
#endif

#define ISC_BF_ENCRYPT	1			/*!< ISC_BF�� ��ȣȭ*/
#define ISC_BF_DECRYPT	0			/*!< ISC_BF�� ��ȣȭ*/

#define ISC_BF_ROUNDS	16          /*!< Round Ƚ��(16 or 20) */

/*--------------------------------------------------*/
#define ISC_BF_NAME					"BlowFish"				
#define ISC_BF_BLOCK_SIZE			8					
#define ISC_BF_KEY_SIZE				16					
#define ISC_BF_IV_SIZE				ISC_BF_BLOCK_SIZE		
#define ISC_BF_INIT					isc_Init_BF			
#define ISC_BF_ECB_DO				isc_Do_BF_ECB			
#define ISC_BF_CBC_DO				isc_Do_BF_CBC			
#define ISC_BF_CFB_DO				isc_Do_BF_CFB		
#define ISC_BF_CFB1_DO				isc_Do_BF_CFB1	
#define ISC_BF_CFB8_DO				isc_Do_BF_CFB8	
#define ISC_BF_CFB16_DO				isc_Do_BF_CFB16	
#define ISC_BF_CFB32_DO				isc_Do_BF_CFB32	
#define ISC_BF_OFB_DO				isc_Do_BF_OFB			
#define ISC_BF_CTR_DO				isc_Do_BF_CTR			
#define ISC_BF_ST_SIZE				sizeof(BF_KEY)	
/*--------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * ISC_BF���� ���̴� BF_KEY�� ����ü
 */
typedef struct isc_bf_key_st {
	uint32 P[ISC_BF_ROUNDS+2];
    uint32 S[4*256];
} BF_KEY;

/*!
* \brief
* �� �� 64bit�� ��ȣȭ�ϴ� BlowFish �˰���
* \param in
* �� �� ��, ��°��� �ٽ� ����.
* \param key
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
*/
ISC_INTERNAL void isc_BF_Encrypt_Block(uint32 *in, const BF_KEY *key);
/*!
* \brief
* �� �� 64bit�� ��ȣȭ�ϴ� BlowFish �˰���
* \param in
* �� �� ��, ��°��� �ٽ� ����.
* \param key
* ��ȣȭ �Ҷ� ���� Ű���� ����Ǿ� �ִ� ����ü ����
*/
ISC_INTERNAL void isc_BF_Decrypt_Block(uint32 *in, const BF_KEY *key);


/*!
* \brief
* BlowFish���� ���̴� �� �ܰ��� Ű�� ����� �Լ�
* \param userKey
* �ʱ� Ű��
* \param len
* Ű���� ����
* \param key
* Ű�� ������ ��� �ִ� ����ü ����
* \returns
* -# INI_CRYPT_SUCCESS : Success
* -# INI_CRYPT_FAIL : Fail
*/
ISC_INTERNAL ISC_STATUS isc_Init_Encrypt_BF_Key(const uint8 *userKey, int len, BF_KEY *key);
/*!
* \brief
* BlowFish �ʱ� Ű ���� �Լ�
* \param unit
* ISC_BLOCK_CIPHER_UNIT ����ü
* \param key
* �ʱ� Ű��
* \param enc
* 1�̸� encrypt���, 0�̸� decrypt���
* \returns
* -# ISC_SUCCESS : Success
* -# L_BF^ISC_F_INIT_BF_KEY^ISC_ERR_INIT_KEY_FAILURE : Key Init Fail
*/
ISC_INTERNAL ISC_STATUS isc_Init_BF_Key(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, int enc);
/*!
* \brief
* BlowFish �ʱ� �Լ�
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
* -# L_BF^ISC_F_INIT_BF_KEY^ISC_ERR_INIT_KEY_FAILURE : Key Init Fail
* \remarks
* iv���� key���� ���� �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Init_BF(ISC_BLOCK_CIPHER_UNIT *unit, const uint8 *key, const uint8 *iv, int enc);

/*!
* \brief
* BlowFish ECB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_BF^ISC_F_DO_BF_ECB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_ECB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CBC���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_BF^ISC_F_DO_BF_CBC^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CBC(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_BF^ISC_F_DO_BF_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CFBR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param nbits
* �Է±��� ��Ʈ��(ex:CFB1->1, CFB16->16)
* \returns
* -# L_BF^ISC_F_DO_BF_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CFBR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, const int nbits);
/*!
* \brief
* BlowFish CFB1���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����(bit ����)
* \returns
* -# L_BF^ISC_F_DO_BF_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CFB1(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CFB8���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_BF^ISC_F_DO_BF_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CFB8(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CFB16���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_BF^ISC_F_DO_BF_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CFB16(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CFB32���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_BF^ISC_F_DO_BF_CFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CFB32(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish OFB���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_BF^ISC_F_DO_BF_OFB^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_OFB(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);
/*!
* \brief
* BlowFish CTR���
* \param unit
* ��/��ȣȭ�� ���Ǵ� ���� ���� �Ű������� �����ϴ� ����ü
* \param out
* ��ȣ��
* \param in
* ��
* \param inl
* �Է� ����
* \returns
* -# L_BF^ISC_F_DO_BF_CTR^ISC_ERR_INVALID_INPUT : �ʱ� �Ķ���� ����
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Do_BF_CTR(ISC_BLOCK_CIPHER_UNIT *unit, uint8 *out, const uint8 *in, uint32 inl);

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_BF_H */

