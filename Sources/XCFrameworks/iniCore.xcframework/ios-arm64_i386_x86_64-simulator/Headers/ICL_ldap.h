#ifndef __LDAPSEARCH_H__
#define __LDAPSEARCH_H__

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

#define DEFAULT_LDAP_PORT			389

#ifndef _WIN32_LOADLOBRARY_CORE_
INISAFECORE_API int ICL_Ldap_Simple_Search(char* host, int port, char* user, char* pass, char* base, char* filter, char* attribute, char ** pRet);

INISAFECORE_API int ICL_Ldap_Get_Data(char *ldapurl, int ldapurl_len, unsigned char **ldap_data, int *ldap_data_len);

INISAFECORE_API char *ICL_Http_Get_file(char *URI, int *filesize);
#else
INI_RET_LOADLIB_CORE(int, ICL_Ldap_Simple_Search, (char* host, int port, char* user, char* pass, char* base, char* filter, char* attribute, char ** pRet), (host,port,user,pass,base,filter,attribute,pRet), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Ldap_Get_Data, (char *ldapurl, int ldapurl_len, unsigned char **ldap_data, int *ldap_data_len), (ldapurl,ldapurl_len,ldap_data,ldap_data_len), -10000);
INI_RET_LOADLIB_CORE(char*, ICL_Http_Get_file, (char *URI, int *filesize), (URI,filesize), NULL);
#endif

/*
#define Err_LDAP_connect 			-101
#define	Err_LDAP_bind 	 			-102
#define	Err_LDAP_search	 			-103
#define	Err_LDAP_notfoundEntry 		-104
#define	Err_LDAP_notfoundAttribute 	-105
*/

#ifdef  __cplusplus
}
#endif

#endif
