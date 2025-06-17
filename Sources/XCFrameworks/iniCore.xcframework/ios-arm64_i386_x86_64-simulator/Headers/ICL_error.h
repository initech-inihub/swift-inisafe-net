#ifndef __ICLERROR_H__
#define __ICLERROR_H__

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

#ifdef _WIN8STORE
extern static unsigned int ICLLastErrorCode;
#else
extern unsigned int ICLLastErrorCode;
#endif
#ifndef _WINDOWS
#include <pthread.h>
#endif

typedef struct{
	unsigned int code;
	char msg[255];
}ERR_LOC;

#ifndef _WIN32_LOADLOBRARY_CORE_
INISAFECORE_API int ICL_GetLastError();
INISAFECORE_API char *ICL_GetErrorString(int result);
INISAFECORE_API char *ICL_Get_Error_Msg(int error_code);
#else
INI_RET_LOADLIB_CORE(int, ICL_GetLastError, (), (), -10000);
INI_RET_LOADLIB_CORE(char*, ICL_GetErrorString, (int result), (result), NULL);
INI_RET_LOADLIB_CORE(char*, ICL_Get_Error_Msg, (int error_code), (error_code), NULL);
#endif
/* common error */
/*
#define FILE_NOT_EXIST                            1007006
#define FILE_IS_EMPTY                             1007007
#define Err_FileOpenErr                              -102
#define FILE_OPEN_ERROR                           1007008
*/

#define ICL_OK									0
#define ICL_BOOL_TRUE							1
#define ICL_BOOL_FALSE							0
/**********************ErrorCode**************************************/

/*구 INISFAE Core 모듈과 호환성을 위해 과거 사용한 에러 코드
신규로 추가되는 함수는 아래와 같이 에러코드를 하나의 값을 사용하지 않아야 함
*/
/* common error*/
#define UNKNOWN_ERROR                             1001000
#define MALLOC_ERROR                              1001001
#define BUFFER_MEM_NOT_ALLOCATED                  1001002
#define INVALID_ARGUMENT_ERROR                   1001003
#define DATA_PARSING_ERROR                        1001004
#define FILE_READ_ERROR                           1001005

/* log error */
#define LOGFILE_OPEN_ERROR                        1001100

/* urlenc error */
#define URL_ENOCDE_WRONG_PARAMETER                1002000
#define URL_DECODE_WRONG_PARAMETER                1002001

/*base encode error*/
#define BASE128_NOLINE_ENCODING_FAIL              1003001
#define BASE128_NOLINE_DECODING_FAIL              1003002
#define BASE128_NOLINE_ENCODE_WRONG_PARAMETER     1003003
#define BASE128_NOLINE_DECODE_WRONG_PARAMETER     1003004

#define BASE64_NOLINE_ENCODING_FAIL               1003005
#define BASE64_NOLINE_DECODING_FAIL               1003006
#define BASE64_NOLINE_ENCODE_WRONG_PARAMETER      1003007
#define BASE64_NOLINE_ENCODE_DESTLENGTH_SMALL     1003008
#define BASE64_NOLINE_DECODE_WRONG_PARAMETER      1003009
#define BASE64_NOLINE_DECODE_DESTLENGTH_SMALL     1003010

/*compress error*/
#define COMPRESS_WRONG_PARAMETER                  1004000
#define DECOMPRESS_WRONG_PARAMETER                1004001

/* unihan error */
#define DEST_BUFFER_EXHAUSTED                     1005001
#define SRC_BUFFER_EXHAUSTED                      1005002
#define SRC_HAS_UCS4                              1005003
#define PARAMETER_NOT_UCS2                        1005004

#define INITECH_LDAP_CONNECT_ERROR                1006004 /*-101*/
#define LDAP_BIND_ERROR                           1006005 /*-102*/
#define LDAP_SEARCH_ERROR                         1006006 /*-103*/
#define LDAP_NOTFOUNDENTRY_ERROR                  1006007 /*-104*/
#define LDAP_NOTFOUNDATTRIBUTE_ERROR              1006008 /*-105*/
#define LDAP_URL_PROTO_ERROR						1006009

/*openssl error*/

#define BASE64_ENCODE_ERROR                       1007000
#define BASE64_DECODE_ERROR                       1007001
#define BASE64_ENCODE_WRONG_PARAMETER             1007002
#define BASE64_DECODE_WRONG_PARAMETER             1007003
#define BASE64_ENCODE_MALLOC_ERROR                1007004
#define BASE64_DECODE_MALLOC_ERROR                1007005
#define BASE64_ENCODE_MALLOC_WRONG_PARAMETER      1007006
#define BASE64_DECODE_MALLOC_WRONG_PARAMETER      1007007

#define X509_D2I_ERROR                            1007010
#define X509_GET_PUBKEY_ERROR                     1007011
#define CERT_LOAD_ERROR                           1007012
#define BIO_NEW_ERROR                             1007013
#define INVALID_PASSWD                            1007014
#define RSAPUB_ENC_ERROR                          1007015
#define PRIVKEY_FOPEN_ERROR                       1007016
#define INVALID_PRIVKEY                           1007017
#define GET_NOTAFTER_ERROR						   1007018
#define EXPIRED_CERT							   1007019
#define RSA_GENERATEKEY_ERROR                     1007020
#define PEM_WRITE_BIO_RSAPRIVATEKEY_ERROR         1007021
#define PEM_WRITE_BIO_RSAPUBLICKEY_ERROR          1007022
#define PEM_READ_BIO_RSAPUBLICKEY_ERROR           1007023
#define RSAPRIV_DEC_ERROR                         1007024
#define RSAPUB_DEC_ERROR                          1007025
#define GETTIME_FROM_ASN1UTCTIME_ERROR            1007026
#define PUBKEYFILE_OPEN_ERROR                     1007027
#define PUBKEYFILE_IS_EMPTY                       1007028
#define EVP_GET_DIGESTBYNAME_ERROR                1007029
#define EVP_CHIPHER_ERROR                         1007030
#define EVP_PKCS82PKEY_ERROR                      1007031
#define M_PKCS8_DECRYPT_ERROR                     1007032
#define D2I_PKCS8_BIO_ERROR                       1007033
#define X509_STORE_NEW_ERROR                      1007034
#define X509_VERIFY_CERT                          1007035
#define PEM_READ_BIO_X509_ERROR                   1007036
#define PEM_READ_BIO_PRIVATEKEY_ERROR             1007037
#define X509_I2D_PEM_ERROR                        1007038
#define X509_GET_EXT_ERROR                        1007039
#define X509V3_GET_EXT_BY_NID_ERROR               1007040
#define OPENSSL_INIT_FIRST_ERROR                  1007041
#define EVP_GET_CIPHERBYNAME_ERROR                1007042
#define SERVER_PRIVATEKEY_FILE_OPEN_ERROR         1007043
#define SERVER_PRIVATEKEY_FILE_READ_ERROR         1007044
#define EVP_PKEY_GET_RSA_ERROR					   1007045
#define GET_ISSUERDN_ERROR					       1007046

#define CONFIG_FILE_ERROR                         1008001
#define CONFIG_SETTING_ERROR                      1008002
#define LICENSE_FILE_OPEN_ERROR                   1008003
#define LICENSE_GET_IP_ERROR                      1008004
#define SOCKET_OPEN_ERROR                         1008005
#define IOCTL_ERROR                               1008006
#define BN_NEW_ERROR                              1008006
#define CHECK_LICENSE_FILEVER_ERROR					1008007
#define GET_LICENSE_VER_ERROR						1008008
#define LICENSE_PRODUCT_CHECK_ERROR					1008009
#define GET_LICENSE_SIGN_ERROR						1008010
#define VERIFY_LICENSE_ERROR						1008011
#define ACCESS_IP_IS_INVALID						1008012
#define LICENSE_INVALID_DATE_ERROR					1008013
#define RSA_SIGN_VERIFY_ERROR						1008014
#define GET_LICENSE_SECTION_ERROR					1008015
#define RSA_MAKE_SIGN_ERROR							1008016

#define NOT_FOUND_SEED_ERROR                      1009001
#define INVAILED_EXTE2E_LENGTH_ERROR              1009002
#define INVAILED_EXTE2E_DECRYPT_ERROR             1009003


#define BIO_WRITE_ERROR                         1009100
#define PKCS7_SIGN_ERROR                        1009101
#define PKCS7_VERIFY_ERROR                      1009102
#define PKCS7_ENCRYPT_ERROR                     1009103
#define PKCS7_DECRYPT_ERROR                     1009104

#define FILE_NOT_EXIST                          1009110
#define FILE_IS_EMPTY                           1009111
#define FILE_OPEN_ERROR                         1009112

#define LOADP12FROMFILE_PARAM_ERROR             1009120
#define D2I_PKCS12_FP_ERROR                     1009122
#define GET_PKEY_ERROR                          1009123
#define I2D_PKCS12_FP_ERROR                     1009124
#define PKCS12_CREATE_ERROR                     1009125
#define SAVEP12TOFILE_PARAM_ERROR               1009126
#define LOADP8PKEYFROMFILE_PARAM_ERROR          1009127
#define SAVEP8PKEUTOFILE_PARAM_ERROR            1009128

#define GETHEXSERIALNUMBER_PARAM_ERROR          1009129
#define X509GETSERIALNUMBER_ERROR               1009130

/*pkcs7*/
#define PKCS7SIGNED_GET_DIGESTNAME_ERROR        1009131
#define PKCS7_SIGNED_PARAM_ERROR                1009132
#define PKCS7_SIGNED_VERIFY_ERROR               1009133
#define PKCS7_ENVELOPED_PARAM_ERROR             1009134
#define CONVERT_CIPHER_FROM_JAVA_ERROR          1009135
#define PKCS7_SIGNEDANDENVELOPED_PARAM_ERROR    1009136
#define PKCS7_ENVELOPED_DECRYPT_PARAM_ERROR     1009137
#define PKCS7_SIGNEDANDENVELOPEDDECRYPT_PARAM_ERROR     1009138
#define PKCS7_ENVELOPEDENCRYPT_WITHKEYIV_PARAM_ERROR    1009139
#define PKCS7_ENVELOPEDDECRYPT_WITHKEYIV_PARAM_ERROR    1009140
#define PKCS7_NEW_ERROR                                 1009141
#define PKCS7_ADD_SIGNATURE_ERROR                    	1009142
#define PKCS7_DATAINIT_ERROR							1009143
#define PKCS7_DATAFINAL_ERROR							1009144

#define GET_ATTR_X509_ERROR             1009200
#define GET_RAND_PKEY_FAIL              1009201
#define GET_RAND_PKEY_PARAM_ERROR           1009202
#define GET_ATTRIBUTE_X509_DATA_ERROR           1009203
#define M_ASN1_BIT_STRING_DUP_ERROR         1009204


/* OTP */
#define OTP_NOTSUPPORT_HASH             1009300
#define OTP_FOLDHASHTOOTP_PARAM_ERROR	1009301
#define OTP_GENOTPSEED_PARAM_ERROR		1009302

/* CONFIG */
#define CFG_FILE_OPEN_ERROR			1009400
#define CFG_FILE_EMPTY				1009401

/* 
에러코드 부여 방법
   기능분류, 함수명,  에러내용을 조합해서 하나의 에러코드를 생성함.
    형식 : 기능분류 ^ 함수명 ^ 에러내용
	  예) L_LICENSE ^ F_CHK_LICENSE ^ ERR_FAIL_MALLOC
*/
/* LICENSE */
#define L_LICENSE					0xC5000000
#define F_CHK_LICENSE				0x00010000
#define F_CHK_CERT_LIC			0x00020000
#define F_CHK_FILE_LIC			0x00030000
#define F_GET_SECTION				0x00040000
#define F_GET_PRODUCT				0x00050000
#define F_CHK_IP					0x00060000
#define F_GET_TOKEN					0x00070000

/* INICRYPTO */
#define L_SYMMETRIC					0xA0000000
#define F_ENCRYPT					0x00010000
#define F_DECRYPT					0x00020000
#define F_PARALLEL					0x00030000

#define L_HASH						0xA1000000
#define F_HASH                      0x00010000
#define F_HASH_FILE                 0x00020000

#define L_RANDOM					0xB0000000
#define F_GET_SEEDRAND				0x00010000

#define L_OTP						0xA3000000
#define F_FOLD_HASH_OTP				0x00010000
#define F_GEN_OTP_SEED				0x00020000
#define F_GEN_OTP_MSG					0x00030000

#define L_PKCS1_KEY					0xA4000000
#define F_GEN_KEY						0x00010000
#define F_PK1_SET_PKISTRINFO			0x00020000
#define F_PRIV_CONV_KEYUNIT			0x00030000
#define F_PUBK_CONV_KEYUNIT			0x00040000
#define F_PRIVATEKEY_TO_RSAINFO		0x00050000
#define F_CERT_TO_RSAINFO			0x00060000
#define F_GENRATE_ECDSA_KEY         0x00070000

#define L_PKCS1_CRYPTO				0xA5000000
#define F_PK1_RSAES					0x00010000
#define F_PK1_RSADS					0x00020000
#define F_PK1_RSASS					0x00030000
#define F_PK1_RSAVS					0x00040000
#define F_PK1_PRIV_ENC				0x00050000
#define F_PK1_PUBK_DEC				0x00060000
#define F_PK1_CERT_ENC				0x00050000
#define F_PK1_PK8_DEC					0x00060000
#define F_PK1_PK8_SIGN				0x00070000
#define F_PK1_PK8_ENC					0x00080000
#define F_PK1_CERT_DEC				0x00090000
#define F_PK1_CERT_VERI				0x000A0000
#define F_PK1_PUBK_ENC				0x000B0000
#define F_PK1_PRIV_DEC				0x000C0000
#define F_PK1_PRIV_SIGN				0x000D0000
#define F_PK1_PUBK_VERI				0x000E0000
#define F_PK1_CERT_TO_PUBK_PEM			0x000F0000
#define F_PK1_PK8_KCDSA_SIGN			0x00100000
#define F_PK1_PK8_KCDSA_VERIFY			0x00110000
#define F_PK1_HASH_SIGN				0x00120000
#define F_PK1_CERT_TO_PRIK_PEM		0x00130000
#define F_PK1_ASYMMETRICKEY_GET_TYPE	0x00140000

#define L_PKCS5_CRYPTO              0xA6000000
#define F_PK5_PBES1_KISA_ENC        0x00010000
#define F_PK5_PBES1_KISA_DEC        0x00020000
#define F_PK5_PBES1_ENC             0x00030000
#define F_PK5_PBES1_DEC             0x00040000
#define F_PK5_PBES2_ENC             0x00050000
#define F_PK5_PBES2_DEC             0x00060000
#define F_PK5_PBKDF1                0x00070000
#define F_PK5_PBKDF2                0x00080000

#define L_PKCS7_CMS					0xA7000000
#define F_PK7_NAME_TO_OID				0x00010000
#define F_PK7_ENCODE_PKCS7				0x00020000
#define F_PK7_DECODE_PKCS7				0x00030000
#define F_PK7_MAKE_SIGNED				0x00040000
#define F_PK7_VERIFY_SIGNED			0x00050000
#define F_PK7_GET_SIGNER_CERT			0x00060000
#define F_PK7_GET_SIGN_TIME			0x00070000
#define F_PK7_MAKE_ENVELOPED			0x00080000
#define F_PK7_VERIFY_ENVELOPED			0x00090000
#define F_PK7_MAKE_SIGNED_ENVELOPED		0x000A0000
#define F_PK7_VERIFY_SIGNED_ENVELOPED	0x000B0000
#define F_PK7_CHECK_FORMAT				0x000C0000
#define F_PK7_GET_PUBKEY				0x000D0000
#define F_PK7_GET_ENCDIGEST				0x000E0000


#define F_CMS_NAME_TO_OID				0x00110000
#define F_CMS_ENCODE_PKCS7				0x00120000
#define F_CMS_DECODE_PKCS7				0x00130000
#define F_CMS_MAKE_SIGNED				0x00140000
#define F_CMS_VERIFY_SIGNED			0x00150000
#define F_CMS_GET_SIGNER_CERT			0x00160000
#define F_CMS_GET_SIGN_TIME			0x00170000
#define F_CMS_MAKE_ENVELOPED			0x00180000
#define F_CMS_VERIFY_ENVELOPED			0x00190000
#define F_CMS_MAKE_SIGNED_ENVELOPED		0x001A0000
#define F_CMS_VERIFY_SIGNED_ENVELOPED	0x001B0000
#define F_CMS_CHECK_FORMAT				0x001C0000
#define F_CMS_GET_PUBKEY				0x001D0000
#define F_CMS_GET_ENCDIGEST				0x001E0000

#define F_PK7_ENCRYPT_INITECHRANDOM		0x00200000
#define F_PK7_DECRYPT_INITECHRANDOM		0x00210000
#define F_PK7_VERIFY_INITECHVID			0x00220000
#define F_PK7_ENCRYPT_INITECHMOREINFO	0x00300000
#define F_PK7_ENCRYPT_REPLAYATTACKDATA  0x00400000

#define F_PK7_KFTC_INITECH_RANDOM		0x00250000

#define F_PK7_MAKE_CTL				0x00260000
#define F_PK7_VERIFY_CTL			0x00270000


#define L_PKCS8_KEY					0xA8000000
#define F_DECODE_PKCS8				0x00010000
#define F_LOAD_STR_TO_RSA				0x00020000
#define F_GET_RANDOM					0x00030000
#define F_MAKE_PRIV_KEY				0x00040000
#define F_GET_ASYMM_KEY				0x00050000
#define F_DER_to_PK1_PEM			0x00060000
#define F_PK8_TO_PK1				0x00070000
#define F_REMOVE_RDATA				0x00080000
#define F_DUPLICATE_PK8				0x00090000
#define F_GET_EXTENDED_PK8			0x00100000
#define F_GET_EXTENDED_PK8_OID		0x00110000
#define F_GET_EXTENDED_PK8_OIDCOUNT	0x00120000
#define F_GET_EXTENDED_PK8_OIDLIST	0x00130000
#define F_MAKE_EXTENDED_PK8         0x00140000
#define F_ADD_EXTENDED_PK8_LIST     0x00150000
#define F_DELETE_EXTENDED_PK8_LIST  0x00160000
#define F_GET_PK8_OBJECTNAME        0x00170000
#define F_GET_PK8_KEYFACTOR         0x00180000
#define F_MAKE_NON_ENCRYPT_PRIVATEKEY	0x00190000	

    

#define L_X509_ICL					0xA9000000
#define F_CONV_CERT2PEM					0x00010000
#define F_CONV_CERT2DER					0x00020000
#define F_INIT_X509_INFO				0x00030000
#define F_FREE_X509_INFO				0x00040000
#define F_INFO_GET_CRLDP				0x00050000
#define F_INFO_GET_LICENSEIPS			0x00060000
#define F_ICL_CHECK_VID					0x00070000
#define F_CRL_VERIFY					0x00080000
#define F_IS_REVOKED					0x00090000
#define F_INFO_GET_ISSUERDN				0x000A0000
#define F_INFO_GET_SUBJECTDN			0x000B0000
#define F_INFO_GET_SERIAL				0x000C0000
#define F_INFO_GET_VALIDITYFROM			0x000D0000
#define F_INFO_GET_VALIDITYTO			0x000E0000
#define F_INFO_GET_PUBKEY				0x000F0000
#define F_INFO_GET_SIGNATURE			0x00100000
#define F_INFO_GET_PUBKEYALG			0x00110000
#define F_INFO_GET_SIGNATUREALG			0x00120000
#define F_CRL_VERIFY_X509_CERT			0x00130000
#define F_CRL_VERIFY_NEXTUPDATE			0x00140000
#define F_VERIFY						0x00150000
#define F_VERIFY_DN						0x00160000
#define F_VERIFY_SIGNATURE				0x00170000
#define F_VERIFY_VALIDITY				0x00180000
#define F_INFO_GET_DN_FIELD				0x00190000
#define F_EXIST_VID						0x001A0000
#define F_CONV_CERT2X509				0x00510000
#define F_GET_RSAUNIT					0x00520000
#define F_NEW_X509_INFO					0x00530000
#define F_X509_TO_X509INFO				0x00540000
#define F_BIGINT_TO_STR					0x00550000
#define F_OID_TO_STR					0x00560000
#define F_TIME_TO_STR					0x00570000
#define F_NAME_TO_STR					0x00580000
#define F_MK_EXTSTR						0x00590000
#define F_PARSE_EXTENSIONS				0x005A0000
#define F_GET_DATA_ATTRIBUTES			0x005B0000
#define F_GET_PUBKEYALGOID				0x005C0000
#define F_GET_PUBKEY					0x005D0000
#define F_MK_PUBKEY						0x005E0000
#define F_PARSE_STR_AT					0x005F0000
#define F_CRL_CONV_CRL2X509CRL			0x00600000
#define F_STR_TO_UTC_TIME				0x00610000
#define F_PUBKEY_TO_BINARY				0x00620000
#define F_BINARY_TO_PUBKEY				0x00630000
#define F_GENTIME_TO_LOCALTIME			0x00640000
#define F_X509_GET_SUBJECTKEYIDENTIFIER			0x00650000
#define F_STR_TO_ASN1_TIME				0x00660000

/* add by sjyang 2010.01.06 */
#define F_X509_SIGN_TO_BINARY			0x00640000

#define L_X509_CPV					0xAA000000
#define F_CERT_PATH_VALID				0x00010000
#define F_VERIFY_CERT_PATH				0x00020000
#define F_VERIFY_CERT					0x00030000
#define F_CHECK_CRL					0x00040000

#define L_COMMON					0xB1000000
#define F_IS_PEM					0x00010000
#define F_ENC_PWD					0x00020000
#define F_DEC_PWD					0x00030000
#define F_GEN_RAND				0x00040000
#define F_DER_TO_PEM				0x00050000
#define F_PEM_TO_DER				0x00060000
#define F_CONV_CIPHER_NAME			0x00070000
#define F_CONV_HASH_NAME			0x00080000
#define F_GET_PEMFILE_TYPE			0x00090000
#define F_GET_DERFILE_TYPE			0x000A0000
#define F_CHANGE_PASSWORD			0x000B0000
#define F_WEB_SCRIPT_VERIFIER		0x000C0000
#define F_CONV_HASH_ID  			0x000D0000


#define L_PKCS12_ICL				0xB3000000
#define F_MAKE_PFX				0x00010000
#define F_VERIFY_PFX				0x00020000

#define L_PKCS11_ICL				0xB4000000
#define F_GET_HSM_SIGNER_ISSUERDN	0x00010000
#define F_HSM_DRIVER_COUNT			0x00020000
#define F_VERIFY_HSM_DRIVER		0x00030000
#define F_HSM_DRIVER_SIGN_COUNT	0x00040000
#define F_VERIFY_HSM_DRIVER_SIGN	0x00050000
#define F_LOAD_LIB				0x00060000
#define F_INIT					0x00070000
#define F_FINAL					0x00080000
#define F_GET_SLOT_COUNT			0x00090000
#define F_OPEN_SESSION			0x000A0000
#define F_CLOSE_SESSION			0x000B0000
#define F_CONV_ALGO_TYPE			0x000C0000
#define F_FIND_OBJECT				0x000D0000
#define F_SYM_ENCRYPT				0x000E0000
#define F_SYM_DECRYPT				0x000F0000
#define F_RSA_ENCRYPT				0x00100000
#define F_RSA_DECRYPT				0x00110000
#define F_RSA_SIGN				0x00120000
#define F_RSA_VERIFY				0x00130000
#define F_KEY_GENERATE			0x00140000
#define F_P11_HASH				0x00150000
#define F_DEL_OBJECT				0x00160000
#define F_SET_RSAKEY				0x00170000
#define F_GET_CERT				0x00180000
#define F_DEL_RSAKEY				0x00190000
#define F_SET_PUBK				0x001A0000
#define F_SET_PRIK				0x001B0000
#define F_SET_VID_RAND			0x001C0000
#define F_GET_VID_RAND			0x001D0000
#define F_GET_TOKEN_SERIAL			0x001E0000
#define F_GET_TOKEN_MEMORY			0x001F0000
#define F_SET_SYMKEY				0x00200000
#define F_DEL_SYMKEY				0x00210000
#define F_CONV_HASH_TYPE			0x00220000
#define F_GET_ALL_CERTS_COUNT		0x00230000
#define F_GET_ALL_CERTS			0x00240000
#define F_SET_CERT				0x00250000
#define F_DEL_CERT              0x00260000
#define F_GET_PUBK              0x00270000
#define F_GET_TOKENINFO 		0x00280000
#define F_ECDSA_SIGN 			0x00290000
#define F_ECDSA_VERIFY			0x002A0000

/* STRING */
#define L_STRING					0xC9000000
#define F_READ_FILE				0x00010000
#define F_WRITE_FILE				0x00020000
#define F_CHECK_VERSION 			0x00030000
#define F_PARSE_STRING_NAME			0x00040000



/* OCSP */
#define L_OCSP_CORE				0xD0000000
#define F_OCSP_SINGLE_REQUEST	0x00010000
#define F_OCSP_RESPONSE			0x00020000

/* Add manwoo.cho 2012.04.30 */
#define F_OCSP_REQUEST_PARSING          0x00030000
#define F_OCSP_GET_INFO_FROM_CERT       0x00040000
#define F_OCSP_MAKE_REVOKE_INFO         0x00050000
#define F_OCSP_RESPONSE_INIT            0x00060000
#define F_OCSP_RESPONSE_UPDATE          0x00070000
#define F_OCSP_RESPONSE_FINAL           0x00080000
#define F_OCSP_GET_REQUEST_FROM_LIST    0x00090000
#define F_OCSP_GET_SINGLE_REQUEST_INFO  0x000A0000
#define F_OCSP_RESPONSE_ERROR           0x000B0000
#define F_MAKE_DHCI_RESPONSE			0x000C0000

/* NTP */
#define L_NTP						0xD1000000
#define F_GET_CURRENT_TIME			0x00010000
#define F_GET_CURRENT_GM_TIME		0x00020000
#define F_GET_CURRENT_LOCAL_TIME	0x00030000

/* SMARTCARD */
#define L_SMART_CARD 				0xD2000000
#define F_LOAD_SMART_KEY			0x00010000
    
/* UCPID */
#define L_UCPID                     0xD3000000
#define F_GENERATE_DI               0x00010000
#define F_GENERATE_CI               0x00020000
    

/* Detail ERROR_CODE (0~999) */
#define ERR_FAIL_MALLOC				0x00000001
#define ERR_INPUT_NULL				0x00000002
#define ERR_INVLAID_INPUT				0x00000003
#define ERR_FAIL_OPEN_FILE				0x00000004
#define ERR_INPUT_LENGTH_ZERO			0x00000005
#define ERR_INVALID_HASH_ID			0x00000006
#define ERR_NOT_FOUND_DATA				0x00000007
#define ERR_REQLEN_GREATER_THAN_RESULT	0x00000008
#define ERR_MALLOC_SIZE_FULL			0x00000009
#define ERR_INVALID_INPUT_LENGTH		0x0000000A
#define ERR_FAIL_HASH					0x0000000B
#define ERR_READ_FILE					0x0000000C
#define ERR_WRITE_FILE				0x0000000D
#define ERR_NOT_SUPPORT_NAME			0x00000010
#define ERR_NOT_SUPPORT_MODE			0x00000011
#define ERR_NOT_SUPPORT_VERSION		0x00000012
#define ERR_NOT_SUPPORT_PADDING		0x00000013
#define ERR_INVALID_IP				0x00000014
#define ERR_INVALID_LIC_DATE			0x00000015
#define ERR_NOT_SUPPORT_ENCODE_TYPE		0x00000016
#define ERR_PLAINDATA_LENGTH_ZERO		0x00000017
#define ERR_CONVERT_PRIVKEY_UNIT		0x00000018
#define ERR_CONVERT_PUBKEY_UNIT		0x00000019

#define ERR_FAIL_NEW_DIGEST_UNIT		0x00000020
#define ERR_FAIL_GET_DIGESTALG_NAME		0x00000021
#define ERR_FAIL_GET_DIGESTLENGTH		0x00000022
#define ERR_FAIL_ENCODE_BASE64			0x00000023
#define ERR_FAIL_DECODE_BASE64			0x00000024
#define ERR_FAIL_GEN_RANDOM			0x00000025
#define ERR_FAIL_GET_SECTION			0x00000026
#define ERR_FAIL_GET_PRODUCT			0x00000027
#define ERR_FAIL_GET_IP				0x00000028
#define ERR_FAIL_GET_SIGNERINFO		0x00000029
#define ERR_FAIL_UTCTIME_TO_ASNT1IME	0x0000002A
#define ERR_FAIL_READ_PKCS1_KEY		0x0000002B
#define ERR_FAIL_PUBK_TO_BINARY		0x0000002C
#define ERR_FAIL_GET_SIGNER_CERT		0x0000002D
#define ERR_FAIL_CONV_CERT_TO_SEQ		0x0000002E
#define ERR_NO_MATCH_PRIVKEY			0x0000002F

#define ERR_FAIL_NEW_PKCS8				0x00000030
#define ERR_FAIL_NEW_PBE_PARAM			0x00000031
#define ERR_FAIL_NEW_PRIV_KEY_INFO		0x00000032
#define ERR_FAIL_SET_CONTENT_TYPE		0x00000033
#define ERR_FAIL_SET_CONTENT_DATA		0x00000034
#define ERR_FAIL_MAKE_SIGNER_INFO		0x00000035
#define ERR_FAIL_SET_CERT				0x00000036
#define ERR_FAIL_SET_ATTR_TYPE			0x00000037
#define ERR_FAIL_SET_ATTR_SIGNTIME		0x00000038
#define ERR_FAIL_SET_ATTR_MD			0x00000039
#define ERR_FAIL_PKCS7_SIGN			0x0000003A
#define ERR_FAIL_PKCS7_CONV_SEQ		0x0000003B
#define ERR_FAIL_ASN1_TO_BIN			0x0000003C
#define ERR_FAIL_DER_TO_ASN1			0x0000003D
#define ERR_FAIL_SEQ_TO_PKCS7			0x0000003E
#define ERR_FAIL_VERIFY_SIGN			0x0000003F
#define ERR_UNKNOWN_KEY_MODE 			0x00000040
#define ERR_ENCODE_PEM_FAIL 			0x00000041
#define ERR_NOT_DER_FORMAT  			0x00000042
#define ERR_NOT_PEM_FORMAT  			0x00000043
#define ERR_FAIL_CONV_DER_TO_PEM		0x00000044
#define ERR_FAIL_CONV_PEM_TO_DER		0x00000045
#define ERR_GET_OID					0x00000046
#define ERR_SET_OID_TO_ALGOID			0x00000047
#define ERR_SET_CERT_TO_RECIPI_INFO		0x00000048
#define ERR_PKCS7_ENC_ENVELOPED		0x00000049
#define ERR_GET_CEK_ENVELOPED			0x0000004A
#define ERR_DEC_ENVELOPED_DATA			0x0000004B
#define ERR_RSA_KEY_COUNT_NOT_ONE		0x0000004C
#define ERR_MAKE_SIGN_ENVELOP_FUNC		0x0000004D
#define ERR_VERIFY_SIGN_ENVELOP_FUNC	0x0000004E
#define ERR_NO_VID					0x0000004F

#define ERR_FAIL_ENC_RSAES				0x00000050
#define ERR_FAIL_DEC_RSAES				0x00000051
#define ERR_FAIL_SIGN					0x00000052
#define ERR_FAIL_VERIFY				0x00000053
#define ERR_VERIFY_CERT_SIGN			0x00000054
#define ERR_CERT_EXPIRED_DATE			0x00000055
#define ERR_NO_VALID_ISSUER_CERT		0x00000056
#define ERR_INVALID_CRL_PATH			0x00000057
#define ERR_REVOKED_CERT				0x00000058

#define ERR_DER_TO_SEQ				0x00000059
#define ERR_VERIFY_P12_MAC				0x0000005A
#define ERR_CHECK_KEY_PAIR				0x0000005B
#define ERR_MAKE_EM					0x0000005C
#define ERR_GET_STACK_VALUE			0x0000005D
#define ERR_ADD_AUTHSAFE_TO_PFX		0x0000005E
#define ERR_SEQ_TO_DER				0x0000005F
#define ERR_ADD_SAFEBAG_TO_AUTHSAFE		0x00000060
#define ERR_OUTPUT_NULL				0x00000061
#define ERR_NOT_HAVE_PUBKEY			0x00000062
#define ERR_FAIL_AKEY2RSAKEY			0x00000063
#define ERR_FAIL_WRITEPEMBIN			0x00000064
#define ERR_FAIL_READDERBIN			0x00000065
#define ERR_FAIL_WRITEDERBIN			0x00000066
#define ERR_FAIL_READPEMBIN			0x00000067
#define ERR_FAIL_READDERBIN_INPUTPARAM	0x00000068
#define ERR_FAIL_READPEMBIN_INPUTPARAM	0x00000069
#define ERR_CNT_FIELD					0x0000006A
#define	ERR_NOT_FOUND_SERIAL			0x0000006B
#define	ERR_UNKNOWN_ALGTYPE			0x0000006C
#define	ERR_FAIL_GET_NCHILD			0x0000006D
#define	ERR_PUBSEQ_TO_BIN				0x0000006E
#define ERR_GEN_RSA_PARAM				0x0000006F
#define ERR_GEN_PK1_PUBK_PEM			0x00000070
#define ERR_GEN_PK1_PRIK_PEM			0x00000071
#define ERR_FAIL_KCDSA_SIGN			0x00000072
#define ERR_ADD_CERT_TO_SAFEBAG		0x00000073
#define ERR_ADD_PRIV_TO_SAFEBAG		0x00000074
#define ERR_ADD_KEYID_TO_SAFEBAG		0x00000075
#define ERR_ADD_FRIENDLYNAME_TO_SAFEBAG	0x00000076
#define ERR_NOT_SUPPORT_LDAP			0x00000077
#define ERR_NOT_TOKEN_DIST_URL_TYPE		0x00000078

#define ERR_NOT_SUPPORT_CRYPTO_VERSION	0x00000079
#define ERR_NOT_SUPPORT_PKI_VERSION		0x0000007A
#define ERR_NOT_SUPPORT_CORE_VERSION	0x0000007B

#define ERR_FAIL_HSM_INIT				0x0000007C
#define ERR_FAIL_HSM_FINAL				0x0000007D
#define ERR_GET_SLOT_COUNT				0x0000007E
#define ERR_OPEN_SESSION				0x0000007F
#define ERR_LOGIN						0x00000080
#define ERR_CLOSE_SESSION				0x00000081
#define ERR_FIND_OBJECT				0x00000082
#define ERR_ENCRYPT_INIT				0x00000083
#define ERR_ENCRYPT					0x00000084
#define ERR_DECRYPT_INIT				0x00000085
#define ERR_DECRYPT					0x00000086
#define ERR_LOAD_LIB					0x00000087
#define ERR_GET_ATTR_VALUE				0x00000088
#define ERR_DELETE_OBJECT				0x00000089
#define ERR_CREATE_OBJECT				0x0000008A
#define ERR_DELETE_CERT				0x0000008B
#define ERR_DELETE_PUBK				0x0000008C
#define ERR_DELETE_PRIK				0x0000008D
#define ERR_DELETE_VIDRAND				0x0000008E
#define ERR_GET_TOKEN_INFO				0x0000008F

#define ERR_NOT_FOUND_PEM_FORMAT		0x00000090

#define ERR_NOT_SIGNED_DATA				0x00000091
#define ERR_INDEX_OVERFLOW				0x00000092
#define ERR_FAIL_GET_PUBKEY				0x00000093
#define ERR_FAIL_PKCS7_SET_VERSION		0x00000094
#define ERR_DATA_OVERFLOW				0x00000095
#define ERR_NOT_IP						0x00000096
#define ERR_NOT_SUPPORT_FORMAT			0x00000097

/* 2016-12-08 PKI DEV ADD */
#define ERR_SEQ_TO_GENERAL_NAMES        0x0000009A


#define ERR_NEW_OCSP_REQUEST		0x00000100
#define ERR_LOAD_USER_CERT			0x00000101
#define ERR_GEN_OCSP_REQUEST		0x00000102
#define ERR_LOAD_OCSP_CLIENT_CERT	0x00000103
#define ERR_LOAD_OCSP_CLIENT_PRI	0x00000104
#define ERR_PKCS5_DECRYPT			0x00000105
#define ERR_SIGN_OCSP_REQUEST		0x00000106
#define ERR_OCSPREQ_TO_SEQ			0x00000107
#define ERR_OCSPSEQ_TO_BIN			0x00000108
#define ERR_LOAD_OCSP_RESPONSE		0x00000109
#define ERR_OCSP_RESPONSE_STATUS	0x00000110
#define ERR_GET_BASIC_RESPONSE		0x00000111
#define ERR_VERIFY_BASIC_RESPONSE	0x00000112
#define ERR_OCSP_CERT_STATUS		0x00000113
#define ERR_GET_OCSP_SINGLE_RESPONSE	0x00000114
#define ERR_GET_REVOKED_DATE		0x00000115
#define ERR_GET_OCSP_REQ_NONCE		0x00000116
#define ERR_NEW_OCSP_RESPONSE		0x00000117	
#define	ERR_MKTIME					0x00000118
#define ERR_LOAD_OCSP_SERVER_CERT	0x00000119

#define ERR_SOCK_RECVTIMEOUT		0x0000011A
#define ERR_LICENSE_PRODUCT			0x0000011B

#define ERR_FAIL_SET_ATTR_RANDOM	0x0000011C

#define ERR_FAIL_NAME_STRTOKEN	0x0000011D
#define ERR_FAIL_MODE_STRTOKEN	0x0000011E

#define ERR_MAX_ACCESS_COUNT	        0x0000011F

#define ERR_FAIL_SET_ATTR_MOREINFO	0x00000120

#define ERR_NOT_FOUND			0x00000121
    
#define ERR_FAIL_SET_ATTR_REPLAY_ATTACK_DATA	0x00000130    

/* Add manwoo.cho  2012.04.30 */
#define ERR_GET_SIGN_OCSP_REQUEST       0x0000012D
#define ERR_GET_SINGLE_REQUEST_COUNT    0x0000012E
#define ERR_GET_OCSP_CLIENT             0x0000012F
#define ERR_AUTHORITY_KEY_NULL          0x00000130
#define ERR_COMPARE_DATA                0x00000131
#define ERR_GEN_OCSP_RESPONSE_DATA      0x00000132
#define ERR_SIGN_OCSP_REQUEST_COUNT     0x00000133
#define ERR_SIGN_OCSP_REQUEST_LIST      0x00000134
#define ERR_STR_TO_ASN1_TIME            0x00000135
#define ERR_LOAD_RESPONSE_DATA          0x00000136
#define ERR_LOAD_SINGLE_REQUEST         0x00000137
#define ERR_ADD_SINGLE_RESPONSE         0x00000138
#define ERR_REVOKE_INFO_WRITE           0x00000139
#define ERR_OCSP_RESPONSE_UPDATE_WRITE  0x0000013A
#define ERR_GEN_BASIC_OCSP_RESPONSE     0x0000013B
#define ERR_GEN_OCSP_RESPONSE           0x0000013C
#define ERR_LOAD_REVOKE_INFO            0x0000013D
#define ERR_GEN_RESPONSE_BYTES          0x0000013E
#define ERR_READ_DHCI_RES               0x0000013F

/* Add yoonjeong.heo 2012.10.24 */
#define ERR_INITIALIZE_DEVICE			0x00000150
#define ERR_START_SMARTCARD_READER		0x00000151
#define ERR_PIN_SIZE					0x00000152
#define ERR_VERIFY_PIN					0x00000153
#define ERR_F3_READ_PRIVKEY				0x00000154
#define ERR_EF_READ_PRIVKEY				0x00000155
#define ERR_NOT_SUPPORT_CARD			0X00000156
#define ERR_PRIVKEY_NOT_PROPERLY_STORED 0x00000157
#define ERR_F3_READ_CERT				0x00000158
#define ERR_EF_READ_CERT				0x00000159

#define ERR_FAIL_CREATE_THREAD		0x0000015A
#define ERR_FAIL_CALC_BLK_COUNT		0x0000015B
#define ERR_KEY_LENGTH_INVALID		0x0000015C
#define ERR_FAIL_CALC_BLK_SIZE		0x0000015D
#define ERR_INVALID_THREAD_COUNT	0x0000015E
    
/* Add sangheon.lee 2016.03.03 */
#define ERR_FAIL_SEQ_TO_PKCS8		0x0000015F
 
#define ERR_FAIL_GENERATE_CI        0x00000160
#define ERR_FAIL_GENERATE_DI        0x00000161
#define ERR_GEN_ECDSA_KEY           0x00000162
#define ERR_INVALID_CURVE_ID        0x00000163

#define ERR_PKCS7_GET_RAND			0x00000164

#define ERR_FAIL_SET_DH_PARAMS		0x00000165
#define ERR_FAIL_INIT_DH			0x00000166
#define ERR_FAIL_GENERATE_DH		0x00000167
#define ERR_FAIL_COMPUTE_KEY		0x00000168
#define ERR_FAIL_ENCRYPT_CI         0x00000169
#define ERR_FAIL_CREATE_DH_RESPONSE 0x00000170
#define ERR_FAIL_DHCIRES_TO_SEQ     0x00000171

#define ERR_DH_COMPUTE_KEY 			0x00000172

#define ERR_INVALID_CTL 		0x00000301
#define ERR_INVALID_SIGNER_CHAIN	0x00000302
#define ERR_INVALID_SIGNER_CERT		0x00000303
#define ERR_INVALID_TARGET_CHAIN	0x00000304
#define ERR_INVALID_TARGET_CERT		0x00000305
#define ERR_INVALID_CTL_TYPE		0x00000306
#define ERR_INVALID_CTL_VERSION		0x00000307
#define ERR_FAIL_VERIFY_VALIDITY 	0x00000308
#define ERR_FAIL_TO_FIND_ROOTCA		0x00000309
#define ERR_FAIL_TO_FIND_HASH_IN_CTL    0x00000310
#define ERR_FAIL_VERIFY_SIGNER_CHAIN	0x00000311



/***********************************ErrorMsg*****************************************/
#define MSG_UNKNOWN_ERROR                          "정의되지 않은 에러입니다."
#define MSG_MALLOC_ERROR                           "메모리를 할당하지 못했습니다."
#define MSG_BUFFER_MEM_NOT_ALLOCATED               "메모리가 할당되지 않은 버퍼를 사용하였습니다"
#define MSG_DATA_PARSING_ERROR                     "데이타 형식이 맞지 않습니다"
#define MSG_FILE_READ_ERROR                        "파일 읽기를 실패했습니다."
#define MSG_INVALID_ARGUMENT_ERROR                "함수 호출시 전달한 파라미터가 잘못되었습니다."

#define MSG_LOGFILE_OPEN_ERROR                     "LOG파일을 열수 없습니다."
#define MSG_OPENSSL_INIT_FIRST_ERROR               "라이브러리 초기화에 실패했습니다."

/*url encode*/
#define MSG_URL_ENOCDE_WRONG_PARAMETER             "url encoding 실패.잘못된 파라미터입니다."
#define MSG_URL_DECODE_WRONG_PARAMETER             "url decoding 실패.잘못된 파라미터 입니다."

/*base encode error*/
#define MSG_BASE128_NOLINE_ENCODING_FAIL           "Base128Encoding(전송형태)실패하였습니다."
#define MSG_BASE128_NOLINE_DECODING_FAIL           "Base128Decoding(전송형태)실패하였습니다."
#define MSG_BASE128_NOLINE_ENCODE_WRONG_PARAMETER  "Base128Encoding(전송형태)실패.잘못된 파라미터입니다."
#define MSG_BASE128_NOLINE_DECODE_WRONG_PARAMETER  "Base128Decoding(전송평태)실패.잘못된 파라미터입니다."
#define MSG_BASE64_NOLINE_ENCODING_FAIL            "Base64Encoding(전송형태)실패하였습니다."
#define MSG_BASE64_NOLINE_DECODING_FAIL            "Base64Decoding(전송형태)실패하였습니다."
#define MSG_BASE64_NOLINE_ENCODE_WRONG_PARAMETER   "Base64Encoding(전송형태)실패.잘못된 파라미터입니다."
#define MSG_BASE64_NOLINE_ENCODE_DESTLENGTH_SMALL  "Base64Encoding(전송형태)실패.dest buffer 사이즈가 작습니다."

#define MSG_BASE64_NOLINE_DECODE_WRONG_PARAMETER   "Base64Decoding(전송형태)실패.잘못된 파라미터입니다."
#define MSG_BASE64_NOLINE_DECODE_DESTLENGTH_SMALL  "Base64Decoding(전송형태)실패.dest buffer 사이즈가 작습니다."

/*compress error*/
#define MSG_COMPRESS_WRONG_PARAMETER               "압축 실패.잘못된 파라미터 입니다."
#define MSG_DECOMPRESS_WRONG_PARAMETER             "압축해제 실패.잘못된 파라미터 입니다."

/* unihan error */
#define MSG_DEST_BUFFER_EXHAUSTED                  "유니코드 매핑 실패.dest buffer 에 공간이 없습니다."
#define MSG_SRC_BUFFER_EXHAUSTED                   "유니코드 매핑 실패.src buffer에 공간이 없습니다."
#define MSG_SRC_HAS_UCS4                           "utf8에서 ucs2로 변환 실패.데이터가 UCS4 입니다."
#define MSG_PARAMETER_NOT_UCS2                     "ucs2에서 euckr로 변환 실패.데이터가 ucs2 가 아닙니다."

#define MSG_LDAP_CONNECT_ERROR                     "ldap connect error " /*-101*/
#define MSG_LDAP_BIND_ERROR                        "ldap bind error" /*-102*/
#define MSG_LDAP_SEARCH_ERROR                      "ldap search error" /*-103*/
#define MSG_LDAP_NOTFOUNDENTRY_ERROR               "ldap not found entry error" /*-104*/
#define MSG_LDAP_NOTFOUNDATTRIBUTE_ERROR           "ldap not found attribute error" /*-105*/

#define MSG_BASE64_ENCODE_ERROR                    "base64 encode 실패 했습니다."
#define MSG_BASE64_DECODE_ERROR                    "base64 decode 실패 했습니다."
#define MSG_BASE64_ENCODE_WRONG_PARAMETER          "base64 encode 실패. 잘못된 파라미터입니다."
#define MSG_BASE64_DECODE_WRONG_PARAMETER          "base64 decode 실패. 잘못된 파라미터입니다."
#define MSG_BASE64_ENCODE_MALLOC_ERROR             "base64 malloc encode 실패."
#define MSG_BASE64_DECODE_MALLOC_ERROR             "base64 malloc decode 실패."
#define MSG_BASE64_ENCODE_MALLOC_WRONG_PARAMETER   "base64 malloc encode 실패. 잘못된 파라미터입니다."
#define MSG_BASE64_DECODE_MALLOC_WRONG_PARAMETER   "base64 malloc decode 실패. 잘못된 파라미터입니다."

#define MSG_X509_D2I_ERROR                         "X509인증서 형식이 아닙니다"
#define MSG_X509_GET_PUBKEY_ERROR                  "X509구조체에서 공개키를 가져올수 없습니다."
#define MSG_CERT_LOAD_ERROR                        "인증서를 로드할 수 없습니다."
#define MSG_BIO_NEW_ERROR                          "I/O 버퍼 객체를 생성할 수 없습니다."
#define MSG_INVALID_PASSWD                         "개인키의 패스워드가 적당하지 않습니다."
#define MSG_PEM_WRITE_BIO_RSAPRIVATEKEY_ERROR      "개인키를 PEM 구조체로 변환하지 못하였습니다."
#define MSG_PEM_WRITE_BIO_RSAPUBLICKEY_ERROR       "공개키를 PEM 구조체로 변환하지 못하였습니다."
#define MSG_PEM_READ_BIO_RSAPUBLICKEY_ERROR        "PEM구조체에서 공개키 읽기를 실패했습니다."

#define MSG_RSAPUB_ENC_ERROR                       "공개키로 암호화 하는 중에 에러가 발생했습니다."
#define MSG_PRIVKEY_FOPEN_ERROR                    "개인키를 읽을 수 없습니다."
#define MSG_INVALID_PRIVKEY                        "개인키가 적당하지 않습니다."
#define MSG_RSA_GENERATEKEY_ERROR                  "키를 생성할 수가 없습니다."
#define MSG_RSAPRIV_DEC_ERROR                      "개인키로 복호화 하는 중에 에러가 발생했습니다."
#define MSG_RSAPUB_DEC_ERROR                       "공개키로 복호화 하는 중에 에러가 발생했습니다."
#define MSG_GETTIME_FROM_ASN1UTCTIME_ERROR         "ASN1_UTCTIME에서 localtime 얻기를 실패했습니다."
#define MSG_PUBKEYFILE_OPEN_ERROR                  "공개키를 읽을 수 없습니다."
#define MSG_PUBKEYFILE_IS_EMPTY                    "공개키 파일이 비어있습니다."
#define MSG_EVP_GET_DIGESTBYNAME_ERROR             "알수없는 DIGEST 메시지 입니다."
#define MSG_EVP_CHIPHER_ERROR                      "대칭키 암/복호화에 실패하였습니다."
#define MSG_EVP_PKCS82PKEY_ERROR                   "PKCS8구조체에서 개인키 추출에 실패하였습니다"
#define MSG_M_PKCS8_DECRYPT_ERROR                  "개인키 복호화에 실패하였습니다."
#define MSG_D2I_PKCS8_BIO_ERROR                    "개인키를 I/O버퍼에 쓸수 없습니다."
#define MSG_X509_STORE_NEW_ERROR                   "X509_STORE 생성에 실패 하였습니다."
#define MSG_X509_VERIFY_CERT                       "인증서 유효성 검증에 실패 하였습니다."
#define MSG_PEM_READ_BIO_X509_ERROR                "인증서를 X509형태로 변환하는데 실패 하였습니다."
#define MSG_X509_I2D_PEM_ERROR                     "인증서를 PEM 형태로 변환하는데 실패 하였습니다."
#define MSG_PEM_READ_BIO_PRIVATEKEY_ERROR          "PEM구조체에서 개인키 읽기를 실패했습니다."
#define MSG_X509V3_GET_EXT_BY_NID_ERROR            "X509V3에서 EXT를 가져오는데 실패 하였습니다."
#define MSG_X509_GET_EXT_ERROR                     "X509에서 EXT를 가져오는데 실패 하였습니다."
#define MSG_EVP_GET_CIPHERBYNAME_ERROR             "알수없는 알고리즘명입니다."
#define MSG_ERR_DATA_OVERFLOW					   "Data 가 Buffer 를 초과합니다. "
#define MSG_ERR_NOT_IP								"IP 주소가 아닙니다. "


#define MSG_CONFIG_FILE_ERROR                      "Config 파일을 찾을 수 없습니다."
#define MSG_CONFIG_SETTING_ERROR                   "config 파일에 설정이 올바르지 않습니다."

#define MSG_NOT_FOUND_SEED_ERROR                   "seed 데이타가 없습니다"
#define MSG_INVAILED_EXTE2E_LENGTH_ERROR           "확장E2E 데이타의 길이가 올바르지 않습니다."
#define MSG_INVAILED_EXTE2E_DECRYPT_ERROR          "확장E2E 데이타가 올바르게 복호화되지 않았습니다."

/*pkcs7*/
#define MSG_PKCS7SIGNED_GET_DIGESTNAME_ERROR            "PKCS7 Signed 하던 중 다이제스트네임 가져오는데 실패하였습니다"
#define MSG_PKCS7_SIGNED_VERIFY_ERROR               "PKCS7 Signed Verify 파라미터 에러. pkcs7 데이터가 NULL입니다."

/* OTP */
#define MSG_OTP_NOTSUPPORT_HASH "지원하지 않는 OTP Hash 알고리즘입니다."
#define MSG_OTP_FOLDHASHTOOTP_PARAM_ERROR "해쉬테이블을 생성시 파라미터가 적당하지 않습니다"
#define MSG_OTP_GENOTPSEED_PARAM_ERROR "OTP Seed를 전달받을 메모리가 할당되지 않았습니다."

/* CONFIG */
#define MSG_CFG_FILE_OPEN_ERROR			"Config 파일을 열기 실패했습니다."
#define MSG_CFG_FILE_EMPTY				"Config파일에 내용이 없습니다."
#define MSG_LIC_VER_CHECK_ERROR			" "

/* License */
#define MSG_LICENSE_PRODUCT				"라이센스파일에서 [licensed-products] 를 가져오는데 실패했습니다,"


/* SmartCard */
#define MSG_ERR_INITIALIZE_DEVICE           "디바이스 초기화에 실패했습니다"
#define MSG_ERR_START_SMARTCARD_READER      "스마크카드 리더 구동에 실패했습니다"
#define MSG_ERR_PIN_SIZE                    "잘못된 PIN사이즈 입니다. (0이하)"
#define MSG_ERR_VERIFY_PIN                  "PIN 검증에 실패했습니다."
#define MSG_ERR_F3_READ_PRIVKEY             "F3 개인키 로딩에 실패했습니다"
#define MSG_ERR_EF_READ_PRIVKEY             "EF 개인키 로딩에 실패했습니다"
#define MSG_ERR_NOT_SUPPORT_CARD            "지원하지않는 스마트카드 타입 입니다"
#define MSG_ERR_PRIVKEY_NOT_PROPERLY_STORED "개인키가 제대로 저장되지 않았습니다."
#define MSG_ERR_F3_READ_CERT                "F3 인증서 로딩에 실패했습니다"
#define MSG_ERR_EF_READ_CERT                "EF 인증서 로딩에 실패했습니다"

#define MSG_ERR_FAIL_GENERATE_CI            "CI 생성을 실패했습니다"
#define MSG_ERR_FAIL_GENERATE_DI            "DI 생성을 실패했습니다"

#define MSG_ERR_GEN_ECDSA_KEY               "ECDSA 키 생성에 실패했습니다"
#define MSG_ERR_INVALID_CURVE_ID            "EC CURVE ID가 유효하지 않습니다"

#ifdef  __cplusplus
}
#endif

#endif

