/**
 *	@file	: ICL_license.h
 *	@brief	: Check file/cert license of INISAFE Product
 *	@section	CREATEINFO	Create
 *		- author	: Myungkyu Jung (myungkyu.jung@initech.com)
 *		- create	: 2009. 9. 21
 *  @section	MODIFYINFO	History
 *		- 2009. 9. 21/Myungkyu Jung : create file
 */

#ifndef ICL_LICENSE_H_
#define ICL_LICENSE_H_

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

#define MAX_LIST_COUNT 		20
#define MAX_LIST_SIZE           128 

typedef struct LICENSE_INFO_st
{
	char issue_date[128];				/* 라이센스 발급한 날짜 */
	char lastup_date[128];				/* 라이센스 수정한 날짜 */
	char grant_domain[128];			/* 계양사이트 영문명 (필수) */
	char grant_service[512];			/* 용도 (필수) */
	char grant_text[512];				/* 라이센스 식별 텍스트 */
	char grant_info[128];				/* 라이센스 식별 텍스트 */
	char check_period[16];				/* 확인주기 (once, everytime, hour:, momth:, prob:*/
	char check_ip_level[16];			/* IP 검증방법 (none, alrt, block) */
	char grant_ipaddress[100][20];		/* 허용 IP */
	int  grant_ipaddress_count;
	char check_validdate_level[16];		/* 만료일 검증 (none, alrt, block) */
	char validdate_begin[32];			/* 제품 허용시간 시작일 (필수)*/
	char validdate_end[32];			/* 제품 허용시간 시작일 (필수)*/
	char check_access_level[16];	/* (none, alrt, block)*/
	int  grant_access_count;                /* 허용 기능 리스트 개수 */
	int  grant_access_size;
	/*char grant_access[MAX_LIST_COUNT][MAX_LIST_SIZE];*/
	char **grant_access;
	char block_access_level[16];	/* (none, alrt, block)*/
	int  block_access_count;                /* 차단 기능 리스트 개수 */
	char block_access[MAX_LIST_COUNT][MAX_LIST_SIZE];

} LICENSE_INFO;

#define ISSUE_DATE			"issue.date"
#define GRANT_DOMAIN			"grant.domain"
#define GRANT_SERVICE			"grant.service"
#define GRANT_TEXT			"grant.text"
#define GRANT_INFO			"grant.info"
#define CHECK_PERIOD 			"check.period"
#define CHECK_IP_LEVEL		"check.ip.level"
#define GRANT_IPADDRESS		"grant.ipaddress"
#define CHECK_VALIDDATE_LEVEL	"check.validdate.level"
#define VALIDDATE_BEGIN		"validdate.begin"
#define VALIDDATE_END			"validdate.end"
#define CHECK_ACCESS_LEVEL		"check.access.level"
#define GRANT_ACCESS			"grant.access"
#define BLOCK_ACCESS_LEVEL		"block.access.level"
#define BLOCK_ACCESS			"block.access"

#define GRANT_FIX_KEY 		0x01
#define GRANT_HANDSHAKE 		0x02
#define GRANT_EXCHANGE_KEY		0x04
#define GRANT_ENCRYPT			0x08
#define GRANT_DECRYPT			0x10

#define LICENSE_CERT_TYPE  10001
#define LICENSE_FILE_TYPE  10002

/* license.c */
/**
 * @brief	: Check file/cert license of INISAFE Product
 * @param	: (char *)product_name		: name of product. sample)"[INISAFENet(C)]"
 * @param	: (char *)license_path		: absoulte full path of license file
 * @param	: (int *) grant_flag		: The grant_flag of product (return)
 * @return	: (int) success=0, error=error code
 */
#ifndef _WIN32_LOADLOBRARY_CORE_
INISAFECORE_API int ICL_Check_License(char *product_name, char *license_path, int *grant_flag);
INISAFECORE_API int ICL_Check_License_Renew(char *product_name, char *bundle_identifier, char *license_path, int *grant_flag);
INISAFECORE_API int ICL_Check_License_Ex(char *product_name, char *product_name_2 ,char *license_path, int *grant_flag, int *auth_2048_flag);

INISAFECORE_API int ICL_check_cert_license(char *lic_str, int lic_len, int *grant_flag);
INISAFECORE_API int ICL_check_file_license(char *product_name, char *license_path, int lic_len, int *grant_flag);
INISAFECORE_API int ICL_check_file_license_ex(char *product_name, char *product_name_2, char *license_path, int lic_len, int *grant_flag, int *auth_2048_flag);
INISAFECORE_API int ICL_get_section(FILE* fp, char* section_name, char** section_vaule);
INISAFECORE_API int ICL_get_licence_products(FILE* fp, char* productname, char* licensed_products, LICENSE_INFO* common, LICENSE_INFO* solusion);
INISAFECORE_API void ICL_set_st_info( LICENSE_INFO* pcommon, LICENSE_INFO* psolusion );
INISAFECORE_API int ICL_verify_signature(char* licensed_products, char* signature);
INISAFECORE_API int ICL_check_ip(char license_ip[][20], int ip_cnt);
INISAFECORE_API int ICL_get_token(char* line, LICENSE_INFO* lic_info_st, FILE *fp);

/* **************************************************************************
 * @brief : 기능 제한 라이센스 파일 체크
 * @param : [IN] char* product_name              [ 제품명 ]
 * @param : [IN] char* license_path              [ 라이센스 경로 ]
 * @param : [IN] int license_len                 [ 라이센스 파일 길이 ]
 * @param : [OUT]char** grant_list               [ 허용 리스트 ]
 * @param : [OUT]char** block_list               [ 차단 리스트 ]
 * *************************************************************************/
INISAFECORE_API int ICL_Check_file_License_with_functional_restricted(char *product_name, char *license_path, int license_len, char** grant_list,char** block_list);

/* **************************************************************************
 * @brief : 기능 제한 라이센스 체크
 * @param : [IN] char* product_name              [ 제품명 ]
 * @param : [IN] char* license_path              [ 라이센스 경로 ]
 * @param : [OUT]char** grant_list               [ 허용 리스트 ]
 * @param : [OUT]char** block_list               [ 차단 리스트 ]
 * *************************************************************************/
INISAFECORE_API int ICL_Check_License_with_functional_restricted(char *product_name, char *license_path, char** grant_list, char** block_list);


INISAFECORE_API int ICL_Get_Restricted_Filed(char *str, char *name, char **value);

/* license key 2048 bit 로 고도화 - license version 2.1.0 이상인 경우 적용 */
int ICL_verify_signature_ex(char* licensed_products, char* signature, char *version_string);

/* getip.c */
#if defined(WIN32) || defined(_WIN32_WCE)
INISAFECORE_API int ICL_GetIP(char *szInfoBuffer, unsigned int nBufferLen);
#else
int ICL_GetIP(char* infamily, int doaliases, char** outdata);
#endif

#else
INI_RET_LOADLIB_CORE(int, ICL_Check_License, (char *product_name, char *license_path, int *grant_flag), (product_name,license_path,grant_flag), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Check_License_Ex, (char *product_name, char *product_name_2 ,char *license_path, int *grant_flag, int *auth_2048_flag), (product_name,product_name_2,license_path,grant_flag,auth_2048_flag), -10000);
INI_RET_LOADLIB_CORE(int, ICL_check_cert_license, (char *lic_str, int lic_len, int *grant_flag), (lic_str,lic_len,grant_flag), -10000);
INI_RET_LOADLIB_CORE(int, ICL_check_file_license, (char *product_name, char *license_path, int lic_len, int *grant_flag), (product_name,license_path,lic_len,grant_flag), -10000);
INI_RET_LOADLIB_CORE(int, ICL_check_file_license_ex, (char *product_name, char *product_name_2, char *license_path, int lic_len, int *grant_flag, int *auth_2048_flag), (product_name,product_name_2,license_path,lic_len,grant_flag,auth_2048_flag), -10000);
INI_RET_LOADLIB_CORE(int, ICL_get_section, (FILE* fp, char* section_name, char** section_vaule), (fp,section_name,section_vaule), -10000);
INI_RET_LOADLIB_CORE(int, ICL_get_licence_products, (FILE* fp, char* productname, char* licensed_products, LICENSE_INFO* common, LICENSE_INFO* solusion), (fp,productname,licensed_products,common,solusion), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_set_st_info, ( LICENSE_INFO* pcommon, LICENSE_INFO* psolusion ), (pcommon,psolusion) );
INI_RET_LOADLIB_CORE(int, ICL_verify_signature, (char* licensed_products, char* signature), (licensed_products,signature), -10000);
INI_RET_LOADLIB_CORE(int, ICL_check_ip, (char license_ip[][20], int ip_cnt), (license_ip[][20],ip_cnt), -10000);
INI_RET_LOADLIB_CORE(int, ICL_get_token, (char* line, LICENSE_INFO* lic_info_st), (line,lic_info_st), -10000);

#if defined(WIN32) || defined(_WIN32_WCE)
INI_RET_LOADLIB_CORE(int, ICL_GetIP, (char *szInfoBuffer, unsigned int nBufferLen), (szInfoBuffer,nBufferLen), -10000);
#else
int ICL_GetIP(char* infamily, int doaliases, char** outdata);
#endif

#endif

#ifdef  __cplusplus
}
#endif


#endif /* ICL_LICENSE_H_ */
