#ifndef HEADER_KISA_ST_H
#define HEADER_KISA_ST_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1.h"
#include "asn1_objects.h"
#include "x509.h"

#ifdef  __cplusplus
extern "C" {
#endif


typedef struct KisaHashContent {
	PRINTABLE_STRING    *idn;
	BIT_STRING			*randomNum;
} ST_KISA_HASH_CONTENT;


#ifndef WIN_INI_LOADLIBRARY_PKI

ISC_API ST_KISA_HASH_CONTENT * new_ST_KISA_HASH_CONTENT(void);
ISC_API void free_ST_KISA_HASH_CONTENT(ST_KISA_HASH_CONTENT *unit);
ISC_API void clean_ST_KISA_HASH_CONTENT(ST_KISA_HASH_CONTENT *unit);
ISC_API ISC_STATUS Seq_to_ST_KISA_HASH_CONTENT(SEQUENCE *top, ST_KISA_HASH_CONTENT **hashct);
ISC_API int ST_KISA_HASH_CONTENT_to_Seq(ST_KISA_HASH_CONTENT *hashct,  SEQUENCE **ST_KISA_HASH_CONTENT_seq);
ISC_API ST_KISA_HASH_CONTENT *ST_KISA_HASH_CONTENT_new(void);
ISC_API void ST_KISA_HASH_CONTENT_content_free(ST_KISA_HASH_CONTENT *a);
ISC_API void ST_KISA_HASH_CONTENT_free(ST_KISA_HASH_CONTENT *a);
   
#else

#include "foundation_pki.h"


#endif

#ifdef  __cplusplus
}
#endif
#endif
