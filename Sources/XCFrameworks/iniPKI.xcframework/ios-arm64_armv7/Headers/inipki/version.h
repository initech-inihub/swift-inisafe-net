#ifndef __INIPKI_VERSION_H__
#define __INIPKI_VERSION_H__

#include <inicrypto/foundation.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* PKI모듈의 버전을 리턴하는 함수
*/
ISC_API char *get_PkiVersion();

#ifdef  __cplusplus
}
#endif

#endif

