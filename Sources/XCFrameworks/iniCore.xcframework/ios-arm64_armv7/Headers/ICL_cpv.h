/**
 *	@file	: ICL_cpv.h
 *	@brief	: Certificate Path Validataion API
 *	@section	CREATEINFO	Create
 *		- author	: Myungkyu Jung (myungkyu.jung@initech.com)
 *		- create	: 2009. 11. 4
 *  @section	MODIFYINFO	History
 *		- 2009. 11. 4/Myungkyu Jung : create file
 */

#ifndef ICL_INICRYPTO_CPV_H_
#define ICL_INICRYPTO_CPV_H_

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

#ifndef _WIN32_LOADLOBRARY_CORE_
/**
 * @brief	: validate certificate path (check sign+issuer+expire_date+crl)
 * @param	:(int) ca_keys_cnt: number of CA certificate list
 * @param	:(PKI_STR_INFO *) ca_keys		: CA certificates structure (malloced)
 * @param	:(unsigned char *) user_cert	: The certificate to verify (read string from file)
 * @param	:(int) user_cert_len			: length of user_cert
 * @param	:(int) check_crl				: check CRL flag (0: no check, 1:check CRL)
 * @return	:(int) success=ICL_OK, error=error code
 */
INISAFECORE_API int ICL_CPV_Cert_Path_Validation(int ca_keys_cnt, PKI_STR_INFO *ca_keys, unsigned char *user_cert, int user_cert_len, int check_crl);

/**
 * @brief	: get CRL from CA and check.
 * @param	:(unsigned char *) user_cert	: The certificate to verify (read string from file)
 * @param	:(int) user_cert_len			: length of user_cert
 * @param	:(unsigned char *) ca_cert		: CA certificate (signer of CRL)
 * @param	:(int) ca_cert_len				: length of ca_cert
 * @return	:(int) success=ICL_OK, error=error code
 */
INISAFECORE_API int ICL_CPV_Check_CRL(unsigned char *user_cert, int user_cert_len, unsigned char *ca_cert, int ca_cert_len);
#else
INI_RET_LOADLIB_CORE(int, ICL_CPV_Cert_Path_Validation, (int ca_keys_cnt, PKI_STR_INFO *ca_keys, unsigned char *user_cert, int user_cert_len, int check_crl), (ca_keys_cnt,ca_keys,user_cert,user_cert_len,check_crl), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CPV_Check_CRL, (unsigned char *user_cert, int user_cert_len, unsigned char *ca_cert, int ca_cert_len), (user_cert,user_cert_len,ca_cert,ca_cert_len), -10000);
#endif



#ifdef  __cplusplus
}
#endif

#endif /* ICL_INICRYPTO_CPV_H_ */
