#ifndef HEADER_GPKI_H
#define HEADER_GPKI_H

#include <inicrypto/foundation.h>

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* DER형식을 ISC_KCDSA 서명값으로 인코딩하는 함수
* \param buf
* 인코딩할 바이너리 데이터의 포인터
* \param r
* ISC_KCDSA의 R 값
* \param rLen
* ISC_KCDSA의 R 길이
* \param s
* ISC_KCDSA의 S 값
* \param sLen
* ISC_KCDSA의 S 길이
* \returns
* DER으로 인코딩된 바이너리의 길이(Byte)
*/
ISC_API int encode_KCDSASignatureValue(uint8 **buf, uint8 *r, int rLen, uint8 *s, int sLen);

/*!
* \brief
* ISC_KCDSA 서명값을 DER 디코딩하는 함수
* \param r
* ISC_KCDSA의 R 값
* \param rLen
* ISC_KCDSA의 R 길이
* \param s
* ISC_KCDSA의 S 값
* \param sLen
* ISC_KCDSA의 S 길이
* \param buf
* 디코딩된 바이너리 데이터의 포인터
* \returns
* ISC_SUCCESS
*/
ISC_API ISC_STATUS decode_KCDSASignatureValue(uint8 *r, int *rLen, uint8 *s, int *sLen, uint8 *buf);

/*!
* \brief
* DER형식을 ISC_KCDSA 서명값으로 인코딩하는 함수(Deplecated) - 함수 이름 오타
* \param buf
* 인코딩할 바이너리 데이터의 포인터
* \param r
* ISC_KCDSA의 R 값
* \param rLen
* ISC_KCDSA의 R 길이
* \param s
* ISC_KCDSA의 S 값
* \param sLen
* ISC_KCDSA의 S 길이
* \returns
* DER으로 인코딩된 바이너리의 길이(Byte)
*/
ISC_API int encode_KCDSASignatrueValue(uint8 **buf, uint8 *r, int rLen, uint8 *s, int sLen);

/*!
* \brief
* ISC_KCDSA 서명값을 DER 디코딩하는 함수(Deplecated) - 함수 이름 오타
* \param r
* ISC_KCDSA의 R 값
* \param rLen
* ISC_KCDSA의 R 길이
* \param s
* ISC_KCDSA의 S 값
* \param sLen
* ISC_KCDSA의 S 길이
* \param buf
* 디코딩된 바이너리 데이터의 포인터
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
