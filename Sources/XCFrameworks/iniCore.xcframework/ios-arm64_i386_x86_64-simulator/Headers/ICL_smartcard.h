/**
 *	file	: ICL_smartcard.h
 */

#ifndef ICL_SMARTCARD_H_
#define ICL_SMARTCARD_H_

#ifdef _INI_BADA
#include "ICL_bada.h"
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef INISAFECORE_API
#if defined(WIN32) || defined(_WIN32_WCE)
	#ifdef INISAFECORE_EXPORTS
	#define INISAFECORE_API __declspec(dllexport)
	#else
	#define INISAFECORE_API __declspec(dllimport)
	#endif
#else
	#define INISAFECORE_API
#endif
#endif


/* ---------------------------------------------------------------------*/
/* Card Type                                            */
/* ---------------------------------------------------------------------*/
#define F3_TYPE         0
#define EF_TYPE         1


#ifndef _WIN32_LOADLOBRARY_CORE_
INISAFECORE_API int ICL_Load_Smart_Key(int cardtype ,char *serialdev, char *pinNumber, char *passwd, int passwd_len, unsigned char **out_cert, int *out_cert_len, unsigned char **out_priv, int *out_priv_len);
#else
INI_RET_LOADLIB_CORE(int, ICL_Load_Smart_Key, (int cardtype ,char *serialdev, char *pinNumber, char *passwd, int passwd_len, unsigned char **out_cert, int *out_cert_len, unsigned char **out_priv, int *out_priv_len), (cardtype,serialdev,pinNumber,passwd,passwd_len,out_cert,out_cert_len,out_priv,out_priv_len), -10000);
#endif

#ifdef  __cplusplus
}
#endif


#endif /* ICL_SMARTCARD_H_ */
