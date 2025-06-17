#ifndef HEADER_GPKI_H
#define HEADER_GPKI_H

#include <inicrypto/foundation.h>

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* DER������ ISC_KCDSA �������� ���ڵ��ϴ� �Լ�
* \param buf
* ���ڵ��� ���̳ʸ� �������� ������
* \param r
* ISC_KCDSA�� R ��
* \param rLen
* ISC_KCDSA�� R ����
* \param s
* ISC_KCDSA�� S ��
* \param sLen
* ISC_KCDSA�� S ����
* \returns
* DER���� ���ڵ��� ���̳ʸ��� ����(Byte)
*/
ISC_API int encode_KCDSASignatureValue(uint8 **buf, uint8 *r, int rLen, uint8 *s, int sLen);

/*!
* \brief
* ISC_KCDSA ������ DER ���ڵ��ϴ� �Լ�
* \param r
* ISC_KCDSA�� R ��
* \param rLen
* ISC_KCDSA�� R ����
* \param s
* ISC_KCDSA�� S ��
* \param sLen
* ISC_KCDSA�� S ����
* \param buf
* ���ڵ��� ���̳ʸ� �������� ������
* \returns
* ISC_SUCCESS
*/
ISC_API ISC_STATUS decode_KCDSASignatureValue(uint8 *r, int *rLen, uint8 *s, int *sLen, uint8 *buf);

/*!
* \brief
* DER������ ISC_KCDSA �������� ���ڵ��ϴ� �Լ�(Deplecated) - �Լ� �̸� ��Ÿ
* \param buf
* ���ڵ��� ���̳ʸ� �������� ������
* \param r
* ISC_KCDSA�� R ��
* \param rLen
* ISC_KCDSA�� R ����
* \param s
* ISC_KCDSA�� S ��
* \param sLen
* ISC_KCDSA�� S ����
* \returns
* DER���� ���ڵ��� ���̳ʸ��� ����(Byte)
*/
ISC_API int encode_KCDSASignatrueValue(uint8 **buf, uint8 *r, int rLen, uint8 *s, int sLen);

/*!
* \brief
* ISC_KCDSA ������ DER ���ڵ��ϴ� �Լ�(Deplecated) - �Լ� �̸� ��Ÿ
* \param r
* ISC_KCDSA�� R ��
* \param rLen
* ISC_KCDSA�� R ����
* \param s
* ISC_KCDSA�� S ��
* \param sLen
* ISC_KCDSA�� S ����
* \param buf
* ���ڵ��� ���̳ʸ� �������� ������
* \returns
* ISC_SUCCESS
*/
ISC_API ISC_STATUS decode_KCDSASignatrueValue(uint8 *r, int *rLen, uint8 *s, int *sLen, uint8 *buf);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(int, encode_KCDSASignatureValue, (uint8 **buf, uint8 *r, int rLen, uint8 *s, int sLen), (buf,r,rLen,s,sLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decode_KCDSASignatureValue, (uint8 *r, int *rLen, uint8 *s, int *sLen, uint8 *buf), (r,rLen,s,sLen,buf), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, encode_KCDSASignatrueValue, (uint8 **buf, uint8 *r, int rLen, uint8 *s, int sLen), (buf,r,rLen,s,sLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decode_KCDSASignatrueValue, (uint8 *r, int *rLen, uint8 *s, int *sLen, uint8 *buf), (r,rLen,s,sLen,buf), ISC_FAIL);

#endif

#ifdef  __cplusplus
}
#endif

#endif
