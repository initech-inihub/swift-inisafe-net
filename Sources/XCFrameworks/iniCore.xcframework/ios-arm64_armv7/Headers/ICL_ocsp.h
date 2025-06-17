/**
 *	@file	: ICL_ocsp.h
 *	@brief	: API for OCSP
 *	@section	CREATEINFO	Create
 *		- author	: Yoonjeong Heo (yoonjeong.heo@initech.com)
 *		- create	: 2010. 6. 16 
 *  @section	MODIFYINFO	History
 */

#ifndef ICL_INICRYPTO_OCSP_H_
#define ICL_INICRYPTO_OCSP_H_

#ifdef _INI_BADA
#include "ICL_bada.h"
#endif

#include "inicrypto/dh.h"
#include "inipki/cid_dh.h"

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

/* response status */
#define ICL_OCSP_REP_STATUS_SUCCESS 			0
#define ICL_OCSP_REP_STATUS_MALFORMED_REQ 		1
#define ICL_OCSP_REP_STATUS_INTERNAL_ERROR		2 
#define ICL_OCSP_REP_STATUS_TRY_LATER			3
#define ICL_OCSP_REP_STATUS_UNKNOWN				4
#define ICL_OCSP_REP_STATUS_SIG_REQ				5
#define ICL_OCSP_REP_STATUS_UNAUTH				6



/* ocsp cert status */
#define ICL_OCSP_CERT_STATUS_GOOD				0
#define ICL_OCSP_CERT_STATUS_REVOKED			1
#define ICL_OCSP_CERT_STATUS_UNKNOWN			2

#define ICL_MAX_REASON_SIZE						100

#ifndef _WIN32_LOADLOBRARY_CORE_
/**
 * @brief	: 
 * @param	:(unsigned char*) req_cert : 
 * @param	:(unsigned char*) ocsp_cert : 
 * @param	:(unsigned char *) ocsp_pri : 
 * @param	:(int) user_cert_len		: 
 * @param	:(int) check_crl			: 
 * @return	:(int) success=ICL_OK, error=error code
 */

INISAFECORE_API int ICL_OCSP_Single_Request(unsigned char *req_cert, 
							unsigned char *ocsp_cert,
		                    unsigned char *ocsp_pri, 
							char *ocsp_pass, int ocsp_pass_len, 
							unsigned char *nonce, int nonce_len,
							unsigned char **ocsp_req, int *ocsp_req_len);



INISAFECORE_API int ICL_OCSP_Single_Request_Ex(unsigned char *req_cert, 
				unsigned char *ocsp_cert,
		                    unsigned char *ocsp_pri, 
							char *ocsp_pass, int ocsp_pass_len, 
							char *hash_alg, char pad_mode,
							unsigned char *nonce, int nonce_len,
							unsigned char **ocsp_req, int *ocsp_req_len);

INISAFECORE_API int ICL_OCSP_Single_Request_Ex_With_CI(unsigned char *req_cert, 
				unsigned char *ocsp_cert,
		                    unsigned char *ocsp_pri, 
							char *ocsp_pass, int ocsp_pass_len, 
							char *hash_alg, char pad_mode,
							unsigned char *nonce, int nonce_len,
							ISC_DH_UNIT* dh,
							unsigned char **ocsp_req, int *ocsp_req_len);


/**
 * @brief	: 
 * @param	:(unsigned char*) ocsp_req : ocsp request message
 * @param	:(unsigned char*) ocsp_ser_cert: ocsp server cert
 * @param	:(unsigned char*) req_nonce : request에 생성시 추가했던  nonce 
 * @param	:(int) req_nonce_len : nonce 길이
 * @param	:(int*) response_status : 응답 상태코드 
 * @param	:(int*) cert_status: 인증서 상태코드
 * @param	:(unsigned char*) recv_date: 폐기된 인증서 일 경우 폐기일자 
 * @param	:(unsigned char*) revoke_reason: 폐기된 인증서 일 경우 폐기이유
 * @return	:(int) success=ICL_OK, error=error code
 */

INISAFECORE_API int ICL_OCSP_Response(unsigned char *ocsp_rep, unsigned char *ocsp_ser_cert, 
					unsigned char *req_nonce, int req_nonce_len,
					int *response_status, int *cert_status, 
					char *revoked_date, char *revoked_reason);



INISAFECORE_API int ICL_OCSP_Response_Ex(unsigned char *ocsp_rep, unsigned char *ocsp_ser_cert, 
					int verify_flag, char pad_mode, 
					unsigned char *req_nonce, int req_nonce_len,
					int *response_status, int *cert_status, 
					char *revoked_date, char *revoked_reason);

INISAFECORE_API int ICL_OCSP_Response_Ex_With_CI(unsigned char *ocsp_rep, unsigned char *ocsp_ser_cert, 
					int verify_flag, char pad_mode, 
					unsigned char *req_nonce, int req_nonce_len,
					int *response_status, int *cert_status, 
					char *revoked_date, char *revoked_reason, ISC_DH_UNIT* dh, char** ci, int* ci_len);


/**
 * @brief	: revoked reason code 를 스트링형태로 변환한다.
 * @param	:(int) reason_code: 폐기이유 코드
 * @param	:(char*) reason_str : 폐기이유 스트링 [out]
 * @return	:(void)
 */

INISAFECORE_API void ICL_Get_Revoked_Reason(int reason_code, char *reason_str);




INISAFECORE_API int ICL_Parsing_OCSP_request(unsigned char* request,int request_len,
		                int* signature_flag,unsigned char** ocsp_client,int* ocsp_client_len,
				        unsigned char** nonce,int* nonce_len,int* single_count);

INISAFECORE_API int ICL_Parsing_OCSP_request_Ex(unsigned char* request,int request_len,
		                int* signature_flag,unsigned char** ocsp_client,int* ocsp_client_len,
				char pad_mode, unsigned char** nonce,int* nonce_len,int* single_count);

INISAFECORE_API int ICL_Priv_to_key_unit(unsigned char* priv,int priv_len,char* pwd,
		                unsigned char** der_priv_unit);

INISAFECORE_API int ICL_Cert_conv_DER_type(unsigned char* cert,int cert_len,
		                unsigned char** der_cert);

INISAFECORE_API int ICL_Get_infomation_from_cert(unsigned char* der_cert,
		                char** issuerkey,char** serial,int* sign_alg, char** out_issuer_dn, char** out_subject_dn);

INISAFECORE_API int ICL_Make_OCSP_response_init(unsigned char* cert,unsigned char* nonce,
		                int nonce_len,unsigned char** respone_data);

INISAFECORE_API int ICL_Get_OCSP_request_from_list(unsigned char* reqeust,int request_len,
		                int offset,unsigned char** single_request);

INISAFECORE_API int ICL_Get_single_requet_info(unsigned char* single_req,
		                char** serial,char** issuerkey);

INISAFECORE_API int ICL_Get_single_requet_info_ex(unsigned char* single_req,
		                char** serial,char** issuerkey, DHCIREQ** dhci_req);

INISAFECORE_API int ICL_Make_revoke_info(char* revoke_date,int revoke_reason,
		                unsigned char** der_revoke_info);

INISAFECORE_API int ICL_Make_OCSP_response_update(unsigned char* der_respdata,
		                unsigned char* der_singledata,unsigned char* der_revokeinfo,
						int cert_status,unsigned char** response_update);

INISAFECORE_API int ICL_Make_OCSP_response_update_ex(unsigned char* der_respdata,
						unsigned char* der_singledata,unsigned char* der_revokeinfo,
						int cert_status, unsigned char* dhci_res, int dhci_res_len, int add_extended_revoke, unsigned char** response_update);

INISAFECORE_API int ICL_Make_OCSP_response_final(unsigned char* der_respdata,
		                unsigned char* der_cert,unsigned char* der_priv_unit,
						int sign_alg,int ocsp_response_status,
						unsigned char** final_response,int* final_response_len);


INISAFECORE_API int ICL_Make_OCSP_response_final_Ex(unsigned char* der_respdata,
		                unsigned char* der_cert,unsigned char* der_priv_unit,
						int sign_alg,char pad_mode,int ocsp_response_status,
						unsigned char** final_response,int* final_response_len);


INISAFECORE_API int ICL_Make_OCSP_response_init_one(unsigned char* request,int request_len,
		                unsigned char* der_single_req,unsigned char* der_invokeinfo,
						unsigned char* cert,int cert_status,
						unsigned char* nonce,int nonce_len,unsigned char** response_data);

INISAFECORE_API int ICL_Make_OCSP_response_init_one_ex(unsigned char* request,int request_len,
		                unsigned char* der_single_req,unsigned char* der_invokeinfo,
						unsigned char* cert,int cert_status,
						unsigned char* nonce,int nonce_len, unsigned char* dhci_res, int dhci_res_len, int add_extended_revoke, unsigned char** response_data);


INISAFECORE_API int ICL_OCSP_Response_error (int errcode,unsigned char** resp, int* resp_len);

/**
 * @brief CI request와 ci 값을 인지로 CI response를 생성한다.
 *
 * @param res_bin CI response [out]
 * @param res_bin_length CI response length [out]
 * @param req CI request [in]
 * @param ci CI value [in]
 * @return INISAFECORE_API 0: success, others: fail
 */
INISAFECORE_API int ICL_Make_DHCI_Response(unsigned char** res_bin, int* res_bin_len, DHCIREQ* req, const char* ci, int ci_len);

#else

INI_RET_LOADLIB_CORE(int, ICL_OCSP_Single_Request, (unsigned char *req_cert,, (req_cert,), -10000);
INI_RET_LOADLIB_CORE(int, ICL_OCSP_Response, (unsigned char *ocsp_rep, unsigned char *ocsp_ser_cert,, (ocsp_rep,ocsp_ser_cert,), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_Get_Revoked_Reason, (int reason_code, char *reason_str), (reason_code,reason_str) );

#endif

#ifdef  __cplusplus
}
#endif

#endif /* ICL_INICRYPTO_CPV_H_ */
