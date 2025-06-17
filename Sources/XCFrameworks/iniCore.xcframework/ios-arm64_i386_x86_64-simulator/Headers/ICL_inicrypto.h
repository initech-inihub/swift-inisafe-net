/**
 *	@file	: ICL_inicrypto.h
 *	@brief	: INICrypto v5 API header file
 *	@section	CREATEINFO	Create
 *		- author	: Myungkyu Jung (myungkyu.jung@initech.com)
 *		- create	: 2009. 9. 22
 *  @section	MODIFYINFO	History
 *		- 2009. 9. 22/Myungkyu Jung : create file
 *      - 2021. 02.01/kwangho.jung : add some functions for ca,ra,ocsp
 */

#ifndef ICL_INICRYPTO_H_
#define ICL_INICRYPTO_H_

#ifdef _INI_BADA
#include "ICL_bada.h"
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#include <time.h>		/* to use 'struct tm' in PKCS#7 */

#include "inipki/asn1.h"
#include "inipki/x509.h"
//sykim 2023.06.14 윈도우일 경우 해당 include 제거 cryptoutil.h 내 함수명 중복으로 선언 제거
#if defined(WIN32) || defined(WIN64) || defined(_WIN32_WCE)
#else
#include <inipki/pkcs7.h>
#include <inipki/pkcs8.h>
#include <inipki/pkcs11.h>
#endif

#define DISABLE_CCM_GCM 1
#define DISABLE_BLOCKCIPHER_MAC 1

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


/* win & unix 호환을 위해 */
#if defined(WIN32) || defined(WIN64) || defined(_WIN32_WCE)
#ifndef _INI_BADA
#define strcasecmp(x,y) _stricmp((x),(y))
#define strncasecmp(x,y,z) _strnicmp((x),(y),(z))
#endif /* _INI_BADA */
#else

#ifdef CYGWIN
#undef tolower
#undef toupper
#define tolower(c)       ((c>='A' && c<='Z') ? (c+('a'-'A')) : c)
#define toupper(c)       ((c>='a' && c<='z') ? (c-('a'-'A')) : c)
#else
#define stricmp(x,y) strcasecmp((x),(y))
#define strnicmp(x,y,z) strncasecmp((x),(y),(z))
#endif
#endif

#if defined(WIN32) || defined(WIN64) || defined(_WIN32_WCE)
#define snprintf _snprintf
#define pipe(h) _pipe(h,4096,O_BINARY)
#define popen _popen
#define pclose _pclose
#else
#define _snprintf snprintf
#define _pipe(h,s,m) pipe(h)
#define _popen popen
#define _pclose pclose
#endif

#if defined(WIN32) || defined(WIN64) || defined(_WIN32_WCE)
#define sleep(x) Sleep((x)*1000)
#else
#define Sleep(x) \ do{ \ struct timespec interval, remainder; \ interval.tv_sec = (unsigned int)((x)/1000); \ interval.tv_nsec = (((x)-(interval.tv_sec*1000))*1000000); \ nanosleep(&interval, &remainder); \ }while(0)
#endif


/* these define values have to same with inicrypto's define value */
#define ICL_RSA					1	/*!< PKI RSA type */
#define ICL_KCDSA					2	/*!< PKI KCDSA type */
#define	ICL_SIGNCERT				3	/*!< PKI Certificate type for sign */
#define ICL_KMCERT				4	/*!< PKI Certificate type for encrypt */
#define ICL_ECDSA               5   /* PKI ECDSA type */

#define ICL_NO_PAD				0x00
#define ICL_RSAES_PKCS1_15			0x20	/*!< RSA encryption PKCS1 v1.5 ENCODE*/
#define ICL_RSAES_OAEP_20			0x08	/*!< RSA encryption OAEP v2.0 ENCODE*/
#define ICL_RSAES_OAEP_21			0x10	/*!< RSA encryption OAEP v2.1 ENCODE*/
#define ICL_RSASSA_PKCS1_15		0x01	/*!< RSA signature PKCS1 v1.5 ENCODE*/
#define ICL_RSASSA_PSS			0x02	/*!< RSA signature PSS ENCODE*/
#define ICL_PKCS5_PAD				0x01


#define ICL_NO_ENCODE				0x10	/*!< No encoding flag */
#define ICL_B64_ENCODE			0x00	/*!< Base64 encoding flag */
#define ICL_B64_LF_ENCODE			0x01	/*!< Base64 encoding with 'insert linefeed' flag */


#define ICL_CKM_SHA_1           0x00000220
#define ICL_CKM_SHA224          0x00000255
#define ICL_CKM_SHA256          0x00000250
#define ICL_CKM_SHA384          0x00000260
#define ICL_CKM_SHA512          0x00000270

#define ICL_CKG_MGF1_SHA1       0x00000001
#define ICL_CKG_MGF1_SHA224     0x00000005
#define ICL_CKG_MGF1_SHA256     0x00000002
#define ICL_CKG_MGF1_SHA384     0x00000003
#define ICL_CKG_MGF1_SHA512     0x00000004

#define ICL_DER			0x30			/*!< DER format */
#define ICL_PEM			0x31			/*!< PEM format */
#define ICL_PUBK			0x32			/*!< public-key */
#define ICL_PRIV			0x33			/*!< private-key */
#define ICL_P1_PUBK		0x34			/*!< public-key for PKCS#1 format */
#define ICL_P1_PRIV		0x35			/*!< private-key for PKCS#1 format */
#define ICL_P8_PRIV		0x36			/*!< private-key for PKCS#8 format */
#define ICL_CERT			0x37			/*!< certificate format */
#define ICL_PKCS7			0x38			/*!< PKCS#7 format */
#define ICL_KEYLABLE		0x39			/*!< Key_Lable format in PKCS#11 */
#define ICL_KEYID			0x3A			/*!< Key_Lable format in PKCS#11 */

#define ICL_NO_PWD		0x40			/*!< no password */
#define ICL_PLAIN_PWD		0x41			/*!< plain password */
#define ICL_ENC_PWD		0x42			/*!< ecnrypted password */

#define ICL_ENC_P1_PRIV	0x43			/*!< private-key for encrypted PKCS#1 format */

/* EC CURVE */
#define ICL_ECC_P_224                0x00000001 /*!< secp224r1 */
#define ICL_ECC_P_256                0x00000002 /*!< secp256r1 | prime256v1 */
#define ICL_ECC_K_233                0x00000100 /*!< sect233k1 */
#define ICL_ECC_K_283                0x00000200 /*!< sect283k1 */

/* pkcs5 */
#define ICL_IV_DEFALUT      0       	/*!< PKCS5 KISA_PBES의 초기벡터: 정해진 벡터값 */
#define ICL_IV_GENERATE     1       	/*!< PKCS5 KISA_PBES의 초기벡터: 기본값(SHA1이용)  */

#define ICL_PBE_MD5_DES_CBC		10
#define ICL_PBE_SHA1_3DES_CBC		146
#define ICL_PBE_SHA1_DES_CBC		170
#define ICL_PBE_SHA1_SEED_CBC		780
#define ICL_PBE_SHA1_ARIA_CBC		828
#define ICL_PBE_SHA256_ARIA_CBC	829
#define ICL_PBE_HAS160_ARIA_CBC	830

/* pkcs7 */
#define ICL_PK7_VER_14     0       	/*!< PKCS#7 1.4 : 0   */
#define ICL_PK7_VER_15     1       	/*!< PKCS#7 1.5 : 1   */

#define ICL_OID_P7_DATA                     21
#define ICL_OID_P7_SIGNED_DATA              22
#define ICL_OID_P7_ENVELOPEDDATA            23
#define ICL_OID_P7_SIGNEDANDENVELOPEDDATA   24
#define ICL_OID_P7_DIGESTDATA               25
#define ICL_OID_P7_ENCRYPTEDDATA            26

#define ICL_PK7_INSERT_CERT                 1
#define ICL_PK7_NOT_INSERT_CERT             0
#define ICL_PK7_INSERT_PLAINTEXT            1
#define ICL_PK7_NOT_INSERT_PLAINTEXT        0
#define ICL_PK7_INSERT_RANDOM				1
#define ICL_PK7_NOT_INSERT_RANDOM			0
#define ICL_PK7_REMOVE_TIMESTAMP			1
#define ICL_PK7_NOT_REMOVE_TIMESTAMP		0

#define ICL_CMS_ADD_ATTR					1
#define ICL_CMS_NOT_ADD_ATTR				0

/* cms */
#define ICL_CMS_VER_1     1       	/*!< CMS v1  */
#define ICL_CMS_VER_3     3       	/*!< CMS v3  */


/* MAC */
#define ICL_HMAC_SHA1				0x15000100	/*!< HMAC_SHA1 알고리즘 ID*/
#define ICL_HMAC_SHA224			0x15000200	/*!< HMAC_SHA224 알고리즘 ID*/
#define ICL_HMAC_SHA256			0x15000300	/*!< HMAC_SHA256 알고리즘 ID*/
#define ICL_HMAC_SHA384			0x15000400	/*!< HMAC_SHA384 알고리즘 ID*/
#define ICL_HMAC_SHA512			0x15000500	/*!< HMAC_SHA512 알고리즘 ID*/
#define ICL_HMAC_MD5				0x16000100	/*!< HMAC_MD5 알고리즘 ID*/
#define ICL_HMAC_HAS160			0x17000100	/*!< HMAC_HAS160 알고리즘 ID*/
#define ICL_HMAC_MDC2				0x18000100	/*!< HMAC_MDC2 알고리즘 ID*/


/* x509 */
#define ICL_DFAULT_SEPARATOR		0x7C		/*!<	'|'  <-- pipeline */
#define ICL_RET_VALID				0		/*!< ICL_X509_check_VID 의 return : PEM type */
#define ICL_RET_UPDATE				1		/*!< X509 인증서 갱신 기간 */
#define ICL_RET_INVALID			-1		/*!< ICL_X509_check_VID 의 return : DER type */

#define ICL_X509_NOTREVOKED	0		/*!< valid 하다. revoke 되지 않았다. */
#define ICL_X509_REVOKED	-1		/*!< valid 하다. revoke 되었다. . */

#define ICL_DEC_STR		1		/*!< BIGINT to String 시 DEC type 플래그 */
#define ICL_HEX_STR		2		/*!< BIGINT to String 시 DEC type 플래그 */

#define ICL_ALGTYPE_OID			0	/*!< 알고리즘 string 의 첫번째 필드 OID 형태 */
#define ICL_ALGTYPE_SN			1	/*!< 알고리즘 string 의 두번째 필드 short name 형태 */
#define ICL_ALGTYPE_LN			2	/*!< 알고리즘 string 의 세번째 필드 long nae 형태 */

#define ICL_X509_VERIFY_SIGNATURE	0x00000001	/*!< ICL_X509_VERIFY에서 X509 인증서 서명 검증 */
#define ICL_X509_VERIFY_VALIDITY	0x00000010	/*!< ICL_X509_VERIFY에서 X509 인증서 유효기간 검증 */
#define ICL_X509_VERIFY_DN			0x00000100	/*!< ICL_X509_VERIFY에서 X509 인증서 DN 검증 */

#define	ICL_RET_VERIFY_CERT_NOT_BEFORE	0x80000001	/*!< ICL_X509_VERIFY에서 X509 인증서 유효기간 이전인 경우 */
#define	ICL_RET_VERIFY_CERT_NOT_AFTER	0x80000002	/*!< ICL_X509_VERIFY에서 X509 인증서 유효기간 이 지난 경우 */
#define	ICL_RET_VERIFY_CERT_FAIL_SIG	0x80000003	/*!< ICL_X509_VERIFY에서 X509 인증서 서명검증 실패 */
#define	ICL_RET_VERIFY_CERT_FAIL_DN		0x80000004	/*!< ICL_X509_VERIFY에서 X509 인증서 DN 검증 실패 */

/* Structure ***************************************************************/
typedef unsigned long int CK_HANDLE;		/*!< pkcs11에서 세션과 키의 handler */

/* x509 */
typedef char IPADDR[16];					/**< 인증서 라이센스에 등록된 IP리스트 데이터 타입 */

/**
 * @brief	X.509형식의 인증서를 파싱하여 담고 있는 구조체
 */
typedef struct x509_info_st {
	int		info_version;			/*!< core 의 x509 st 버젼 이다. 추후에 구조체 바뀌면 버젼 반드시 올려주고 체크하자. */
	char	sep;					/*!< 구분자 : default = | */
	int		version;				/*!< x509 version */
	char	*serial;				/*!< 시리얼번호 문자열 "81" */
	char	*hexaserial;			/*!< 시리얼번호 문자열 hexa "51" */
	char	*signatureAlg;			/*!< 서명알고리즘 "1.2.840.113549.1.1.5|RSA-SHA1|sha1WithRSAEncryption" */
	char	*issuerDN;				/*!< "emailAddress=support@initech.com,CN=Product-License-CA,OU=PKI,O=Initech,L=SEOUL" */
	char	*validityFrom;			/*!< YYYYMMDDHHmmss "20080707020215" */
	char	*validityTo;			/*!< YYYYMMDDHHmmss "20090708020215" */
	char	*subjectDN;				/*!< cn=김대현()008104220090320181000498,ou=HNB,ou=personal4IB,o=yessign,c=kr */
	char	*subjectDN_DER;			/*!< subjectDN 의 DER 값 / 사설인증서 CA 파일명 생성시 사용 / 추후 삭제 대상.  */
	int		subjectDN_DERLen;		/*!< */
	char	*pubkeyAlg;				/*!< OID_|_sn_|_ln "1.2.840.113549.1.1.1|rsaEncryption|rsaEncryption" */
	unsigned char	*pubkey;		/*!< 공개키 */
	int		pubkeyLen;
	int		pubkeyBit;				/*!< 공개키 비트 */
	unsigned char *pubkey_n;		/*!< RSA 공개키 n 값 / 사설인증서 파일명 생성시 사용 / 추후 삭제 대상. */
	int		pubkey_nLen;			/*!< RSA 공개키 n의 길이 */
	unsigned char	*pubkeyseq;		/*!< 공개키 der sequence */
	char	*issuerUniqueID;		/*!< crypto 에 현재 구현안됨 */
	char	*subjectUniqueID;		/*!< crypto 에 현재 구현안됨 */
	char	*authoritykeyid;		/*!< 기관키 식별자 "KeyID=41:4A:0B:87:51:B1:D6:D0:F4:E4:26:72:CD:1E:D1:80:AB:23:22:A7|Serial=0xD2B0725206F2AAC97FFA2E446A3195628DB8ECF4emailAddress=support@initech.com,CN=Product-License-CA,OU=PKI,O=Initech,L=SEOUL" */
	char	*subjectkeyid;			/*!< 주체키 식별자 "72:B3:46:ED:B1:CD:0D:5C:75:95:61:BA:14:E0:E6:CA:73:FD:75:E5" */
	char	*subjectAltName;		/*!< 주체 대체 이름 "type|value|value|.. " "URI|172.20.24.142|172.20.24.143|172.20.24.144" */
	char	*crlDP;					/*!< "DP=http://www.initech.com/shttp/server.crl" */
	char	*authorityInfoAcc;		/*!< 기관 정보 액세스 : [1]Authority Info Access: Access Method=온라인 인증서 상태 프로토콜 (1.3.6.1.5.5.7.48.1/2),Alternative Name:URL=http://ocsp.yessign.org:4612 */
	char	*aiaurl;				/*!< 기관정보 액세스 URL */
	char	*subjectInfoAcc;		/*!< 주체 정보 액세스 : [1]Subject Info Access: Access Method=,Alternative Name:URL=http://ocsp.yessign.org:4612 */
	char	*siaurl;				/*!< 주체정보 액세스 URL */
	char	*keyusage;				/*!< 키사용: "A0" */
	char	*certpolicy;			/*!< "PI=1.3.6.1.4.1.7150.2.1,USER_NOTICE=,O=Initech's customer group.,Text=Un-Supported Type (1A),CPS=http://www.initech.com/" */
	char	*certpolicyOID;			/*!< "1.2.410.200005.1.1.1" */
	char	*extkeyuse;				/*!< "1.3.6.1.5.5.7.3.1|1.3.6.1.5.5.7.3.2|1.3.6.1.5.5.7.3.3|1.3.6.1.5.5.7.3.8" */
	unsigned char	*signature;				/*!< ... */
	int		signatureLen;
}X509_INFO;

/**
 * @brief	X.509형식의 서명값을 담고 있는 구조체
 */
typedef struct {
	char			*algorithm;					/*!< "1.2.410.200005.1.1.1" */
	char			*parameters;					/*!< ... default(NULL)" */
	unsigned char	*hashedData;					/*!< ... */
	int				hashedData_len;				/*!< ... */
}X509_SIGNED_INFO;

/**
 * @brief	공개키,개인키 정보 담는 구조체
 */
typedef struct{
	unsigned char *cert;			/*!< certificate: read string from file */
	int cert_len;					/*!< length of cert */
	unsigned char *priv;			/*!< private-key: read string from file */
	int priv_len;					/*!< length of priv */
	char priv_pwd[256];			/*!< password for private-key */
	int pwd_len;					/*!< length of priv_pwd */
	int key_type;					/*!< ICL_RSA | ICL_KCDSA (use only in PKCS11, PKCS12) */
	int key_usage;				/*!< ICL_SIGNCERT | ICL_KMCERT (use only in PKCS11, PKCS12) */
}PKI_STR_INFO;


/**
 * @brief	보안토큰 드라이버 정보 담는 구조체
 */
typedef struct{
	char token_id[256];			/*!< vendor ID & product ID */
	char os_version[256];			/*!< supported OS version. separate with ',' */
	char version[256];			/*!< driver version */
	char name[256];				/*!< driver download path */
	int type;					/*!< 0=HSM, 1=smartcard */
	char cp[256];				/*!< company ID of HSM */
	char info[256];				/*!< product info of HSM */
}DRIVER_INFO;

/**
 * @brief	보안토큰 드라이버의 인증정보 담는 구조체
 */
typedef struct{
        char modulename[256];		/*!< module_name */
        char algorithm[256];		/*!< algorithm ',' */
        unsigned char hash[256];			/*!< hash */
        int hash_len;				/*!< length of hash */
}DRIVER_SIGNATURE_INFO;

/* INISAFE Web client를 위한 RSA구조체
 * 임시용으로 곧 삭제될 예정이므로 사용 금지!
 */
typedef struct{
	unsigned char n[512];
	int n_len;
	unsigned char e[16];
	int e_len;
	unsigned char d[512];
	int d_len;
	unsigned char p[256];
	int p_len;
	unsigned char q[256];
	int q_len;
	unsigned char dmp1[256];
	int dmp1_len;
	unsigned char dmq1[256];
	int dmq1_len;
	unsigned char iqmp[256];
	int iqmp_len;
}RSA_INFO;

/**
* @brief	WebContent Script 서명 검증용 구조체
*/
typedef struct {
	int		nWebContentAlgorithmType;
	union
	{
		char *ptr;
		struct {
			unsigned char *key;
			unsigned int keylen;
		} hmac;
		void *rsa;
	} key;
}SCRIPT_VERIFY_CORE;




/**
* @brief    원문 정보를 가진 구조체
*/
typedef struct{
    unsigned char *msg;
    int msglen;
}ICL_MSG_INFO;

/**
* @brief    서명 데이터를 가진 구조체
*/
typedef struct{
    unsigned char *signed_data;
    int signed_data_len;
}ICL_SIGNED_DATA_INFO;

/* for NTP */
#define ICL_NTP_GM_TIME	0
#define ICL_NTP_LOCAL_TIME 1


#ifndef _WIN32_LOADLOBRARY_CORE_
/* Functions ***************************************************************/
/* symmetric.c */

#ifndef _WINDOWS

/**
 * @brief	:Encrypt data with given symmectric algorithm(parallel)
 * @param	:(int) th_cnt: thread count
 * @param	:(unsigned char *) key: the KEY value
 * @param	:(int) keylen: length of the KEY value
 * @param	:(unsigned char *) iv: the IV value
 * @param	:(int) ivlen: length of the IV value
 * @param	:(char *) alg: algorithm name
 * 			algorithm-list (use only these)
 * 			"SEED-CTR" "ARIA128-CTR" "ARIA192-CTR" "ARIA256-CTR" "DES-CTR" "DES_EDE-CTR"
			"AES128-CTR" "AES192-CTR" "AES256-CTR" "RC5-CTR" "BF-CTR"
 * @param	:(int) pad_mode	: ICL_NO_PAD | ICL_PKCS5_PAD
 * @param	:(unsigned char *) in: plaintext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: ciphertext (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @return	:(int) success=0, error=error code
 */
int ICL_SYM_Parallel_Encrypt(int th_cnt, unsigned char *key, int keylen, unsigned char *iv, int ivlen, char *alg, int pad_mode, unsigned char *in, int inl, unsigned char **out, int *outl, char encode);

/**
 * @brief	:Decrypt data with given symmectric algorithm(parallel)
 * @param	:(int) th_cnt: thread count
 * @param	:(unsigned char *) key: the KEY value
 * @param	:(int) keylen: length of the KEY value
 * @param	:(unsigned char *) iv: the IV value
 * @param	:(int) ivlen: length of the IV value
 * @param	:(char *) alg: algorithm name
 * 			algorithm-list (use only these)
 * 			"SEED-CTR" "ARIA128-CTR" "ARIA192-CTR" "ARIA256-CTR" "DES-CTR" "DES_EDE-CTR"
			"AES128-CTR" "AES192-CTR" "AES256-CTR" "RC5-CTR" "BF-CTR"
 * @param	:(int) pad_mode	: ICL_NO_PAD | ICL_PKCS5_PAD
 * @param	:(unsigned char *) in: ciphertext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: plaintext (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @return	:(int) success=0, error=error code
 */
int ICL_SYM_Parallel_Decrypt(int th_cnt, unsigned char *key, int keylen, unsigned char *iv, int ivlen, char *alg, int pad_mode, unsigned char *in, int inl, unsigned char **out, int *outl, char encode);

/**
 * @brief	:Encrypt/Decrypt data with given symmectric algorithm(parallel)
 * @param	:(int) enc: cipher mode select (0:decrypt, 1:encrypt)
 * @param	:(int) th_cnt: thread count
 * @param	:(unsigned char *) key: the KEY value
 * @param	:(int) keylen: length of the KEY value
 * @param	:(unsigned char *) iv: the IV value
 * @param	:(int) ivlen: length of the IV value
 * @param	:(char *) alg: algorithm name
 * 			algorithm-list (use only these)
 * 			"SEED-CTR" "ARIA128-CTR" "ARIA192-CTR" "ARIA256-CTR" "DES-CTR" "DES_EDE-CTR"
			"AES128-CTR" "AES192-CTR" "AES256-CTR" "RC5-CTR" "BF-CTR"
 * @param	:(int) pad_mode	: ICL_NO_PAD | ICL_PKCS5_PAD
 * @param	:(unsigned char *) in: plaintext/ciphertext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: plaintext/ciphertext (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @return	:(int) success=0, error=error code
 */
int ICL_SYM_Parallel_Cipher(int enc, int th_cnt, unsigned char *key, int keylen, unsigned char *iv, int ivlen, char *alg, int pad_mode, unsigned char *in, int inl, unsigned char **out, int *outl, char encode);

#endif

/**
 * @brief   : Get key length of symmetric algorithm
 * @param   :(char *) alg: algorithm name and mode
 *           algorithm-list (use only these)
 *          "SEED-ECB"  | "SEED-CBC"        | "SEED-CFB"        | "SEED-OFB"        | "SEED-CTR"
 *          "ARIA128-ECB"   | "ARIA128-CBC" | "ARIA128-CFB" | "ARIA128-OFB" | "ARIA128-CTR"
 *          "ARIA192-ECB"   | "ARIA192-CBC" | "ARIA192-CFB" | "ARIA192-OFB" | "ARIA192-CTR"
 *          "ARIA256-ECB"   | "ARIA256-CBC" | "ARIA256-CFB" | "ARIA256-OFB" | "ARIA256-CTR"
 *          "DES-ECB"   | "DES-CBC"     | "DES-CFB"     | "DES-OFB"     | "DES-CTR"
 *          "DES_EDE-ECB"   | "DES_EDE-CBC" | "DES_EDE-CFB" | "DES_EDE-OFB" | "DES_EDE-CTR"
 *          "AES128-ECB"    | "AES128-CBC"  | "AES128-CFB"  | "AES128-OFB"  | "AES128-CTR"
 *          "AES192-ECB"    | "AES192-CBC"  | "AES192-CFB"  | "AES192-OFB"  | "AES192-CTR"
 *          "AES256-ECB"    | "AES256-CBC"  | "AES256-CFB"  | "AES256-OFB"  | "AES256-CTR"
 *          "RC5-ECB"       | "RC5-CBC"     | "RC5-CFB"     | "RC5-OFB"     | "RC5-CTR"
 *          "BF-ECB"        | "BF-CBC"      | "BF-CFB"      | "BF-OFB"      | "BF-CTR"
 * @param   :(int*)olen : key length of algorithm
 * @return  :(int) 0:success ,  fail= ERROR CODE (return)
 */
INISAFECORE_API int ICL_SYM_Get_Key_Length(char *alg, int *olen);

/**
 * @brief	: Get block length of symmetric algorithm
 * @param	:(char *) alg: algorithm name and mode
 * 			 algorithm-list (use only these)
 * 			"SEED-ECB"	| "SEED-CBC"		| "SEED-CFB"		| "SEED-OFB"		| "SEED-CTR"
 * 			"ARIA128-ECB"	| "ARIA128-CBC"	| "ARIA128-CFB"	| "ARIA128-OFB"	| "ARIA128-CTR"
 * 			"ARIA192-ECB"	| "ARIA192-CBC"	| "ARIA192-CFB"	| "ARIA192-OFB"	| "ARIA192-CTR"
 * 			"ARIA256-ECB"	| "ARIA256-CBC"	| "ARIA256-CFB"	| "ARIA256-OFB"	| "ARIA256-CTR"
 * 			"DES-ECB" 	| "DES-CBC"		| "DES-CFB"		| "DES-OFB"		| "DES-CTR"
 * 			"DES_EDE-ECB"	| "DES_EDE-CBC"	| "DES_EDE-CFB"	| "DES_EDE-OFB"	| "DES_EDE-CTR"
 * 			"AES128-ECB"	| "AES128-CBC"	| "AES128-CFB"	| "AES128-OFB"	| "AES128-CTR"
 * 			"AES192-ECB"	| "AES192-CBC"	| "AES192-CFB"	| "AES192-OFB"	| "AES192-CTR"
 * 			"AES256-ECB"	| "AES256-CBC"	| "AES256-CFB"	| "AES256-OFB"	| "AES256-CTR"
 * 			"RC5-ECB"		| "RC5-CBC"		| "RC5-CFB"		| "RC5-OFB"		| "RC5-CTR"
 * 			"BF-ECB"		| "BF-CBC"		| "BF-CFB"		| "BF-OFB"		| "BF-CTR"
 * @return	:(int) block_size: block length of algorithm, fail=0 (return)
 */
INISAFECORE_API int ICL_SYM_Get_Block_Length(char *alg);

/**
 * @brief	: Encrypt data with given symmectric algorithm
 * @param	:(unsigned char *) key: the KEY value
 * @param	:(unsigned char *) iv: the IV value
 * @param	:(char *) alg: algorithm name and mode
 * 			 algorithm-list (use only these)
 * 			"SEED-ECB"	| "SEED-CBC"		| "SEED-CFB"		| "SEED-OFB"		| "SEED-CTR"
 * 			"ARIA128-ECB"	| "ARIA128-CBC"	| "ARIA128-CFB"	| "ARIA128-OFB"	| "ARIA128-CTR"
 * 			"ARIA192-ECB"	| "ARIA192-CBC"	| "ARIA192-CFB"	| "ARIA192-OFB"	| "ARIA192-CTR"
 * 			"ARIA256-ECB"	| "ARIA256-CBC"	| "ARIA256-CFB"	| "ARIA256-OFB"	| "ARIA256-CTR"
 * 			"DES-ECB" 	| "DES-CBC"		| "DES-CFB"		| "DES-OFB"		| "DES-CTR"
 * 			"DES_EDE-ECB"	| "DES_EDE-CBC"	| "DES_EDE-CFB"	| "DES_EDE-OFB"	| "DES_EDE-CTR"
 * 			"AES128-ECB"	| "AES128-CBC"	| "AES128-CFB"	| "AES128-OFB"	| "AES128-CTR"
 * 			"AES192-ECB"	| "AES192-CBC"	| "AES192-CFB"	| "AES192-OFB"	| "AES192-CTR"
 * 			"AES256-ECB"	| "AES256-CBC"	| "AES256-CFB"	| "AES256-OFB"	| "AES256-CTR"
 * 			"RC5-ECB"		| "RC5-CBC"		| "RC5-CFB"		| "RC5-OFB"		| "RC5-CTR"
 * 			"BF-ECB"		| "BF-CBC"		| "BF-CFB"		| "BF-OFB"		| "BF-CTR"
 * @param	:(int) pad_mode	: ICL_NO_PAD | ICL_PKCS5_PAD
 * @param	:(unsigned char *) in: plaintext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: ciphertext (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_SYM_Encrypt(unsigned char *key, unsigned char *iv, char *alg, int pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode);



INISAFECORE_API int ICL_SYM_Encrypt_F(unsigned char *key, unsigned char *iv, char *alg, int pad_mode, unsigned char *in, int in_len, unsigned char *out, int *out_len);


INISAFECORE_API int ICL_SYM_Encrypt_init_Adv(unsigned char *key, unsigned char *iv, char *alg, int pad_mode, unsigned char *initd_enc_key, int *initd_enc_keylen);
INISAFECORE_API int ICL_SYM_Encrypt_doFinal_Adv(unsigned char *initd_enc_key, int initd_enc_keylen, unsigned char *in, int in_len, unsigned char *out, int *out_len);

/**
 * @brief	: Decrypt data with given symmectric algorithm
 * @param	:(unsigned char *) key: the KEY value
 * @param	:(unsigned char *) iv: the IV value
 * @param	:(char *) alg: algorithm name and mode
 * @param	:(int) pad_mode	: ICL_NO_PAD | ICL_PKCS5_PAD
 * @param	:(unsigned char *) in: ciphertext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: plaintext (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_SYM_Decrypt(unsigned char *key, unsigned char *iv, char *alg, int pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode);


INISAFECORE_API int ICL_SYM_Decrypt_F(unsigned char *key, unsigned char *iv, char *alg, int pad_mode, unsigned char *in, int in_len, unsigned char *out, int *out_len);


INISAFECORE_API int ICL_SYM_Decrypt_init_Adv(unsigned char *key, unsigned char *iv, char *alg, int pad_mode, unsigned char *initd_dec_key, int *initd_dec_keylen);
INISAFECORE_API int ICL_SYM_Decrypt_doFinal_Adv(unsigned char *initd_dec_key, int initd_dec_keylen, unsigned char *in, int in_len, unsigned char *out, int *out_len);

/* pkcs_key.c */
/**
 * @brief	: create new structure about PKI_STR_INFO  (malloc)
 * @param	:(void)
 * @return	:(PKI_STR_INFO *) success=structure pointer, error=NULL
 */
INISAFECORE_API PKI_STR_INFO *ICL_PK1_New_PKISTRINFO(void);

/**
 * @brief	: set data to PKI_STR_INFO  (malloc)
 * @param	:(PKI_STR_INFO *) pki_st: pki structur to set
 * @param	:(unsigned char *) cert		: read cert-string from file. (PEM|DER)
 * @param	:(int) cert_len				: length of cert
 * @param	:(unsigned char *) priv		: read pkcs8_privkey-string from file. (PEM|DER)
 * @param	:(int) priv_len				: length of priv
 * @param	:(char *) passwd				: private-key password
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Set_PKISTRINFO(PKI_STR_INFO *pki_st, unsigned char *cert, int cert_len, unsigned char *priv, int priv_len, char *passwd);

/**
 * @brief	: free malloc structure at ICL_PK1_New_PKISTRINFO()
 * @param	:(PKI_STR_INFO *) pki_st: pki structure to free
 * @return	:(void)
 */
INISAFECORE_API void ICL_PK1_Free_PKISTRINFO(PKI_STR_INFO *pki_st);

/**
 * @brief	: free allocated memory of PKI_STR_INFO.cert, PKI_STR_INFO.priv (PKI_STR_INFO구조체를 여러개 malloc잡아 사용한 경우 호출)
 * @param	:(PKI_STR_INFO *) pki_st: pki structure to free
 * @param	:(int) count: number of malloced structures
 * @return	:(void)
 */
INISAFECORE_API void ICL_PK1_Free_PKISTRINFOS(PKI_STR_INFO *pki_st, int count);

/**
 * @brief	: generate RSA Key pair string (format PKCS#1) (Not support function)
 * @param	:(int) version: 1=PKCS#1_v1.5, 2=PKCS#1_v2.0(Not support yet)
 * @param	:(int) len_bit: bit-length of modulus n (1024|2048|...)
 * @param	:(char) format: ICL_DER | ICL_PEM
 * @param	:(unsigned char **) pubk_str: generated RSA public-key string (return)
 * @param	:(int) pubk_len : length of pubk_str
 * @param	:(unsigned char **) prik_str: generated RSA private-key string (return)
 * @param	:(int) pubk_len : length of prik_str
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Generate_RSA_Key(int version, int len_bit, char out_type, unsigned char **pubk_str, int *pubk_len, unsigned char **prik_str, int *prik_len);

/**
 * @brief    : generate RSA Key pair string (format PKCS#1) (Not support function)
 * @param    :(int) version: 1=PKCS#1_v1.5, 2=PKCS#1_v2.0(Not support yet)
 * @param    :(int) len_bit: bit-length of modulus n (1024|2048|...)
 * @param    :(char) format: ICL_DER | ICL_PEM
 * @param    :(unsigned char **) pubk_str: generated RSA public-key string (return)
 * @param    :(int) pubk_len : length of pubk_str
 * @param    :(unsigned char **) prik_str: generated RSA private-key string (return)
 * @param    :(int) pubk_len : length of prik_str
 * @param    :(int) object_index : index of oid
 * @return   : (int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Generate_RSA_Key_With_Oid(int version, int len_bit, char out_type,
                                  unsigned char **pubk_str, int *pubk_len, unsigned char **prik_str, int *prik_len, int object_index);

/**
 * @brief	: convert certificate to public-key PEM string (format PKCS#1)
 * @param	:(unsigned char *) cert_str: read cert-string from file. (PEM|DER)
 * @param	:(int) cert_len: length of cert_str
 * @param	:(unsigned char **) out: PKCS#1 public-key pem string without OID (return)
 * @param	:(int *) out_len: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Cert_To_Publickey_Pemfile(unsigned char *cert_str, int cert_len, char **out, int *out_len);

/**
* @brief	: convert certificate to private-key PEM string (format PKCS#1)
* @param	:(unsigned char *) cert_str: read cert-string from file. (PEM|DER)
* @param	:(int) cert_len: length of cert_str
* @param	:(unsigned char *) priv_str:  privkey-string
* @param	:(int) priv_len: length of priv_str
* @param	:(unsigned char **) out: PKCS#1 public-key pem string without OID (return)
* @param	:(int *) out_len: length of out (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK1_Cert_To_Privatekey_Pemfile(unsigned char *cert_str, int cert_len, unsigned char *priv_str, int priv_len, unsigned char *password, int passwordLen,  char **out, int *out_len);


/*임시 사용 함수 , 곧 삭제될 예정 */
INISAFECORE_API int ICL_PK1_Privatekey_To_RSAINFO(unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, RSA_INFO **rsa_info);


/* pkcs_crypto.c */
/**
 * @brief	: get private-key from priv_str and encrypt data with it. (Only RSA)
 * @param	:(unsigned char *) priv_str: read privkey-string from file. (PKCS#1 or PKCS#8, PEM or DER)
 * @param	:(int) priv_len: length of priv_str
 * @param	:(char *) passwd: private-key password	(if not encrypted file, input NULL)
 * @param	:(int) passwd_len: length of passwd		(if not encrypted file, input 0)
 * @param	:(unsigned char *) pad_mode: padding-mode
 *			ICL_NO_PAD     		: no padding (in_len = length of RSA key)
 *          ICL_RSAES_PKCS1_15  : RSAES_PKCS1_v1.5 padding
 *          ICL_RSAES_OAEP_20   : RSAES_OAEP_v2.0 padding
 *          ICL_RSAES_OAEP_21   : RSAES_OAEP_v2.1 padding
 * @param	:(unsigned char *) in: plaintext
 * @param	:(int) in_len: length of in (in_len < rsa_key_length)
 * @param	:(unsigned char **) out: ciphertext. (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Private_Encrypt(unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode);

/* pkcs_crypto.c */
/**
 * @brief	: get private-key from priv_str and encrypt data with it. (Only RSA)
 * @param	:(unsigned char *) priv_str: read privkey-string from file. (PKCS#1 or PKCS#8, PEM or DER)
 * @param	:(int) priv_len: length of priv_str
 * @param	:(char *) passwd: private-key password	(if not encrypted file, input NULL)
 * @param	:(int) passwd_len: length of passwd		(if not encrypted file, input 0)
 * @param	:(unsigned char *) pad_mode: padding-mode
 *			ICL_NO_PAD     		: no padding (in_len = length of RSA key)
 *          ICL_RSAES_PKCS1_15  : RSAES_PKCS1_v1.5 padding
 *          ICL_RSAES_OAEP_20   : RSAES_OAEP_v2.0 padding
 *          ICL_RSAES_OAEP_21   : RSAES_OAEP_v2.1 padding
 * @param	:(unsigned char *) in: plaintext
 * @param	:(int) in_len: length of in (in_len < rsa_key_length)
 * @param	:(unsigned char **) out: ciphertext. (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @param	:(char) hash_algo: hash algorithm. (SHA1 | SHA256 | SHA512 | HAS160)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Private_Encrypt_ex(unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode, char *hash_algo);

/**
 * @brief	: get public-key from pubk_str and decrypt data with it. (Only RSA)
 * @param	:(unsigned char *) pubk_str: read key-string from file. (PKCS#1 or CERT, PEM or DER)
 * @param	:(int) pubk_len: length of pubk_str
 * @param	:(unsigned char *) pad_mode: padding-mode
 *			ICL_NO_PAD		: no padding (in_len = length of RSA key)
 *          ICL_RSAES_PKCS1_15  : RSAES_PKCS1_v1.5 padding
 *          ICL_RSAES_OAEP_20   : RSAES_OAEP_v2.0 padding
 *          ICL_RSAES_OAEP_21   : RSAES_OAEP_v2.1 padding
 * @param	:(unsigned char *) in: ciphertext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: plaintext. (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Public_Decrypt(unsigned char *pubk_str, int pubk_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode);

/**
 * @brief	: get public-key from pubk_str and decrypt data with it. (Only RSA)
 * @param	:(unsigned char *) pubk_str: read key-string from file. (PKCS#1 or CERT, PEM or DER)
 * @param	:(int) pubk_len: length of pubk_str
 * @param	:(unsigned char *) pad_mode: padding-mode
 *			ICL_NO_PAD		: no padding (in_len = length of RSA key)
 *          ICL_RSAES_PKCS1_15  : RSAES_PKCS1_v1.5 padding
 *          ICL_RSAES_OAEP_20   : RSAES_OAEP_v2.0 padding
 *          ICL_RSAES_OAEP_21   : RSAES_OAEP_v2.1 padding
 * @param	:(unsigned char *) in: ciphertext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: plaintext. (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @param	:(char) hash_algo: hash algorithm. (SHA1 | SHA256 | SHA512 | HAS160)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Public_Decrypt_ex(unsigned char *pubk_str, int pubk_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode, char *hash_algo);

/**
 * @brief	: get public-key from pubk_str and decrypt data with it. (Only RSA)
 * @param	:(unsigned char *) pubk_str: read key-string from file. (PKCS#1 or CERT, PEM or DER)
 * @param	:(int) pubk_len: length of pubk_str
 * @param	:(unsigned char *) in: ciphertext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: plaintext. (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @param	:(unsigned char *) pad_mode: padding-mode (return)
 *			ICL_NO_PAD		: no padding (in_len = length of RSA key)
 *          ICL_RSAES_PKCS1_15  : RSAES_PKCS1_v1.5 padding
 *          ICL_RSAES_OAEP_20   : RSAES_OAEP_v2.0 padding
 *          ICL_RSAES_OAEP_21   : RSAES_OAEP_v2.1 padding
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Public_Decrypt_all(unsigned char *pubk_str, int pubk_len, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode, char *outmode);

/**
 * @brief	: get public-key from pubk_str and encrypt data with it. (Only RSA)
 * @param	:(unsigned char *) pubk_str: read PKCS#1 public-key string from file. (PKCS#1 or CERT, PEM or DER)
 * @param	:(int) pubk_len: length of pubk_str
 * @param	:(unsigned char *) pad_mode: padding-mode
 *			ICL_NO_PAD		: no padding (in_len = length of RSA key)
 *			ICL_RSAES_PKCS1_15	: RSAES_PKCS1_v1.5 padding
 *			ICL_RSAES_OAEP_20	: RSAES_OAEP_v2.0 padding
 *			ICL_RSAES_OAEP_21	: RSAES_OAEP_v2.1 padding
 * @param	:(unsigned char *) in: plaintext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: ciphertext. buffer size must greater than RSA key-length (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Public_Encrypt(unsigned char *pubk_str, int pubk_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode);

INISAFECORE_API int ICL_PK1_Public_Encrypt_With_Param(unsigned char *pubk_str, int pubk_len, char pad_mode, char *param_hashAlg, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode);

/**
 * @brief	: get public-key from pubk_str and encrypt data with it. (Only RSA)
 * @param	:(unsigned char *) pubk_str: read PKCS#1 public-key string from file. (PKCS#1 or CERT, PEM or DER)
 * @param	:(int) pubk_len: length of pubk_str
 * @param	:(unsigned char *) pad_mode: padding-mode
 *			ICL_NO_PAD		: no padding (in_len = length of RSA key)
 *			ICL_RSAES_PKCS1_15	: RSAES_PKCS1_v1.5 padding
 *			ICL_RSAES_OAEP_20	: RSAES_OAEP_v2.0 padding
 *			ICL_RSAES_OAEP_21	: RSAES_OAEP_v2.1 padding
 * @param	:(unsigned char *) in: plaintext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: ciphertext. buffer size must greater than RSA key-length (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @param	:(char) hash_algo: hash algorithm. (SHA1 | SHA256 | SHA512 | HAS160)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Public_Encrypt_ex(unsigned char *pubk_str, int pubk_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode, char *hash_algo);

/**
 * @brief	: get private-key from pk8_str and decrypt data with it. (Only RSA)
 * @param	:(unsigned char *) priv_str: read privkey-string from file. (PKCS#1 or PKCS#8, PEM or DER)
 * @param	:(int) priv_len: length of priv_str
 * @param	:(char *) passwd: private-key password	(if not encrypted file, input NULL)
 * @param	:(int) passwd_len: length of passwd		(if not encrypted file, input 0)
 * @param	:(unsigned char *) pad_mode: padding-mode
 *			ICL_NO_PAD		: no padding (in_len = length of RSA key)
 *			ICL_RSAES_PKCS1_15	: RSAES_PKCS1_v1.5 padding
 *			ICL_RSAES_OAEP_20	: RSAES_OAEP_v2.0 padding
 *			ICL_RSAES_OAEP_21	: RSAES_OAEP_v2.1 padding
 * @param	:(unsigned char *) in: ciphertext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char *) out: plaintext. buffer size must greater than RSA key-length (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Private_Decrypt(unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode);

/**
 * @brief	: get private-key from pk8_str and decrypt data with it. (Only RSA)
 * @param	:(unsigned char *) priv_str: read privkey-string from file. (PKCS#1 or PKCS#8, PEM or DER)
 * @param	:(int) priv_len: length of priv_str
 * @param	:(char *) passwd: private-key password	(if not encrypted file, input NULL)
 * @param	:(int) passwd_len: length of passwd		(if not encrypted file, input 0)
 * @param	:(unsigned char *) pad_mode: padding-mode
 *			ICL_NO_PAD		: no padding (in_len = length of RSA key)
 *			ICL_RSAES_PKCS1_15	: RSAES_PKCS1_v1.5 padding
 *			ICL_RSAES_OAEP_20	: RSAES_OAEP_v2.0 padding
 *			ICL_RSAES_OAEP_21	: RSAES_OAEP_v2.1 padding
 * @param	:(unsigned char *) in: ciphertext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char *) out: plaintext. buffer size must greater than RSA key-length (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @param	:(char) hash_algo: hash algorithm. (SHA1 | SHA256 | SHA512 | HAS160)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Private_Decrypt_ex(unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode, char *hash_algo);

/**
 * @brief	: get private-key from pk8_str and decrypt data with it. (Only RSA)
 * @param	:(unsigned char *) priv_str: read privkey-string from file. (PKCS#1 or PKCS#8, PEM or DER)
 * @param	:(int) priv_len: length of priv_str
 * @param	:(char *) passwd: private-key password	(if not encrypted file, input NULL)
 * @param	:(int) passwd_len: length of passwd		(if not encrypted file, input 0)
 * @param	:(unsigned char *) in: ciphertext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char *) out: plaintext. buffer size must greater than RSA key-length (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @param	:(unsigned char *) pad_mode: padding-mode (return)
 *			ICL_NO_PAD		: no padding (in_len = length of RSA key)
 *          ICL_RSAES_PKCS1_15  : RSAES_PKCS1_v1.5 padding
 *          ICL_RSAES_OAEP_20   : RSAES_OAEP_v2.0 padding
 *          ICL_RSAES_OAEP_21   : RSAES_OAEP_v2.1 padding
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Private_Decrypt_all(unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode, char *outmode);


/**
 * @brief	: get private-key from priv_str and make signature with it. (RSA | KCDSA)
 * @param	:(unsigned char *) priv_str: read pkcs8_privkey-string from file. (PKCS#1 or PKCS#8, PEM or DER)
 * @param	:(int) priv_len: length of priv_str
 * @param	:(char *) passwd: private-key password	(if not encrypted file, input NULL)
 * @param	:(int) passwd_len: length of passwd		(if not encrypted file, input 0)
 * @param	:(unsigned char *) pad_mode: padding-mode
 *			ICL_NO_PAD		: no padding (in_len = length of RSA key)
 *			ICL_RSASSA_PKCS1_15: RSASSA_PKCS1_v1.5 padding
 *			ICL_RSASSA_PSS	: RSASSA_PSS padding
 * @param	:(char *) hash_alg: hash algorithm name	("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(unsigned char *) in: plaintext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: signature. (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Private_Sign(unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, char pad_mode, char *hash_alg, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode);

/**
 * @brief	: get public-key from pubk_str and verify signature with it.	(RSA | KCDSA)
 * @param	:(unsigned char *) pubk_str: read PKCS#1 public-key string from file. (PKCS#1 or CERT, PEM or DER)
 * @param	:(int) pubk_len: length of pubk_str
 * @param	:(unsigned char *) pad_mode: padding-mode
 *			ICL_NO_PAD		: no padding (in_len = length of RSA key)
 *			ICL_RSASSA_PKCS1_15: RSASSA_PKCS1_v1.5 padding
 *			ICL_RSASSA_PSS	: RSASSA_PSS padding
 * @param	:(char *) hash_alg: hash algorithm name	("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(unsigned char *) msg: plaintext
 * @param	:(int) msg_len: length of msg
 * @param	:(unsigned char *) sign: signature
 * @param	:(int *) sign_len: length of sign
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Public_Verify(unsigned char *pubk_str, int pubk_len, char pad_mode, char *hash_alg, unsigned char *msg, int msg_len, unsigned char *sign, int sign_len, char encode);

/**
 * @brief	: make signature as PKCS1_RSASSA. input data must be hash value. (only RSA)
 * @param	:(unsigned char *) pk8_str: read pkcs8_privkey-string from file. (PEM|DER)
 * @param	:(int) pk8_len: length of pk8_str
 * @param	:(char *) passwd: private-key password
 * @param	:(unsigned char *) pad_mode: padding-mode
 *			ICL_RSASSA_PKCS1_15: RSASSA_PKCS1_v1.5 padding
 *			ICL_RSASSA_PSS	: RSASSA_PSS padding
 * @param	:(char *) hash_alg: hash algorithm name	("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(unsigned char *) in: hash value
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: signature. (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_PK8file_Hashvalue_Sign(unsigned char *pk8_str, int pk8_len, char *passwd, int passwd_len, char pad_mode, char *hash_alg, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode);

/**
 * @brief	: make signature as PKCS1_RSASSA. input data must be hash value. (only RSA)
 * @param	:(unsigned char *) pk8_str: read pkcs8_privkey-string from file. (PEM|DER)
 * @param	:(int) pk8_len: length of pk8_str
 * @param	:(char *) passwd: private-key password
 * @param	:(unsigned char *) pad_mode: padding-mode(ISC_NO_PADDING,PKCS1 1_15) or padding-mode(PSS)| MGF Algorithm | PSS Salt Length
 *			ICL_RSASSA_PKCS1_15: RSASSA_PKCS1_v1.5 padding
 *			ICL_RSASSA_PSS	: RSASSA_PSS padding
 *			MGF Algorithm
 *			ISC_RSA_MGF_SHA1 | ISC_RSA_MGF_SHA256 | ISC_RSA_MGF_SHA384 | ISC_RSA_MGF_SHA512 | ISC_RSA_MGF_MD5
 *			PSS Salt Length
 *			ISC_RSASSA_PSS_SALT_16 | ISC_RSASSA_PSS_SALT_20 | ISC_RSASSA_PSS_SALT_32 | ISC_RSASSA_PSS_SALT_48 | ISC_RSASSA_PSS_SALT_64
 * @param	:(char *) hash_alg: hash algorithm name	("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(unsigned char *) in: hash value
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: signature. (return)
 * @param	:(int *) out_len: length of out (return)
 * @param	:(char) encode: encoding mode. (ICL_NO_ENCODE | ICL_B64_ENCODE | ICL_B64_LF_ENCODE)
 * @return	:(int) success=0, error=error code
 */

INISAFECORE_API int ICL_PK1_PK8file_Hashvalue_Sign_ex(unsigned char *pk8_str, int pk8_len, char *passwd, int passwd_len, int pad_mode, char *hash_alg, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode);

/* pkcs5 */
/**
 * @brief	: PBES_KISA Encrypt
 * @param	:(const unsigned char *) in_msg: 암호화 할 메시지
 * @param	:(int) in_msg_len: 암호화 할 메시지 길이
 * @param	:(unsigned char *) in_passwd: 패스워드
 * @param	:(int) in_passwd_len: 패스워드 길이
 * @param	:(unsigned char*) in_salt: salt (8octet string)
 * @param	:(int) in_salt_len: salt 길이
 * @param	:(int) in_iter: iteration (1000이상 권고)
 * @param	:(unsigned char*) out: 암호화된 메시지 (return)
 * @param	:(int *) out_len: 암호화된 메시지 길이 (return)
 * @param	:(char *) in_cipher_alg: 대칭키 알고리즘
 * 			 [Available list]
 * 			"SEED-ECB"	| "SEED-CBC"		| "SEED-CFB"		| "SEED-OFB"		| "SEED-CTR"
 * 			"ARIA128-ECB"	| "ARIA128-CBC"	| "ARIA128-CFB"	| "ARIA128-OFB"	| "ARIA128-CTR"
 * 			"ARIA192-ECB"	| "ARIA192-CBC"	| "ARIA192-CFB"	| "ARIA192-OFB"	| "ARIA192-CTR"
 * 			"ARIA256-ECB"	| "ARIA256-CBC"	| "ARIA256-CFB"	| "ARIA256-OFB"	| "ARIA256-CTR"
 * 			"DES-ECB" 	| "DES-CBC"		| "DES-CFB"		| "DES-OFB"		| "DES-CTR"
 * 			"DES_EDE-ECB"	| "DES_EDE-CBC"	| "DES_EDE-CFB"	| "DES_EDE-OFB"	| "DES_EDE-CTR"
 * 			"AES128-ECB"	| "AES128-CBC"	| "AES128-CFB"	| "AES128-OFB"	| "AES128-CTR"
 * 			"AES192-ECB"	| "AES192-CBC"	| "AES192-CFB"	| "AES192-OFB"	| "AES192-CTR"
 * 			"AES256-ECB"	| "AES256-CBC"	| "AES256-CFB"	| "AES256-OFB"	| "AES256-CTR"
 * 			"RC5-ECB"		| "RC5-CBC"		| "RC5-CFB"		| "RC5-OFB"		| "RC5-CTR"
 * 			"BF-ECB"		| "BF-CBC"		| "BF-CFB"		| "BF-OFB"		| "BF-CTR"
 *
 * @param	:(char *) in_hash_alg: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 *
 * @param	:(int) in_iv_opt: 초기 벡터 ID
 *           [Available list]
 *			ICL_IV_DEFALUT (PKCS5 KISA_PBES의 초기벡터: 정해진 벡터값)
 *		    ICL_IV_GENERATE (PKCS5 KISA_PBES의 초기벡터: 기본값(SHA1이용)
 *
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK5_Encrypt_PBES1_KISA(const unsigned char *in_msg, int in_msg_len, unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, unsigned char *out, int *out_len, char *in_cipher_alg, char *in_hash_alg, int in_iv_opt);

/**
 * @brief	: PBES_KISA Decrypt
 * @param	:(const unsigned char *) in_cipher: 복호화 할 메시지
 * @param	:(int) in_cipher_len: 복호화 할 메시지 길이
 * @param	:(unsigned char *) in_passwd: 패스워드
 * @param	:(int) in_passwd_len: 패스워드 길이
 * @param	:(unsigned char*) in_salt: salt (8octet string)
 * @param	:(int) in_salt_len: salt 길이
 * @param	:(int) in_iter: iteration (1000이상 권고)
 * @param	:(unsigned char*) out: 복호화된 메시지 (return)
 * @param	:(int *) out_len: 복호화된 메시지 길이 (return)
 * @param	:(char *) in_cipher_alg: 대칭키 알고리즘
 * 			 [Available list]
 * 			"SEED-ECB"	| "SEED-CBC"		| "SEED-CFB"		| "SEED-OFB"		| "SEED-CTR"
 * 			"ARIA128-ECB"	| "ARIA128-CBC"	| "ARIA128-CFB"	| "ARIA128-OFB"	| "ARIA128-CTR"
 * 			"ARIA192-ECB"	| "ARIA192-CBC"	| "ARIA192-CFB"	| "ARIA192-OFB"	| "ARIA192-CTR"
 * 			"ARIA256-ECB"	| "ARIA256-CBC"	| "ARIA256-CFB"	| "ARIA256-OFB"	| "ARIA256-CTR"
 * 			"DES-ECB" 	| "DES-CBC"		| "DES-CFB"		| "DES-OFB"		| "DES-CTR"
 * 			"DES_EDE-ECB"	| "DES_EDE-CBC"	| "DES_EDE-CFB"	| "DES_EDE-OFB"	| "DES_EDE-CTR"
 * 			"AES128-ECB"	| "AES128-CBC"	| "AES128-CFB"	| "AES128-OFB"	| "AES128-CTR"
 * 			"AES192-ECB"	| "AES192-CBC"	| "AES192-CFB"	| "AES192-OFB"	| "AES192-CTR"
 * 			"AES256-ECB"	| "AES256-CBC"	| "AES256-CFB"	| "AES256-OFB"	| "AES256-CTR"
 * 			"RC5-ECB"		| "RC5-CBC"		| "RC5-CFB"		| "RC5-OFB"		| "RC5-CTR"
 * 			"BF-ECB"		| "BF-CBC"		| "BF-CFB"		| "BF-OFB"		| "BF-CTR"
 *
 * @param	:(char *) in_hash_alg: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 *
 * @param	:(int) in_iv_opt: 초기 벡터 ID
 *           [Available list]
 *			ICL_IV_DEFALUT (PKCS5 KISA_PBES의 초기벡터: 정해진 벡터값)
 *		    ICL_IV_GENERATE (PKCS5 KISA_PBES의 초기벡터: 기본값(SHA1이용)
 *
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK5_Decrypt_PBES1_KISA(const unsigned char *in_cipher, int in_cipher_len, unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, unsigned char *out, int *out_len, char *in_cipher_alg, char *in_hash_alg, int in_iv_opt );

/**
 * @brief	: PBES1 Encrypt
 * @param	:(const unsigned char *) in_msg: 암호화 할 메시지
 * @param	:(int) in_msg_len: 암호화 할 메시지 길이
 * @param	:(unsigned char *) in_passwd: 패스워드
 * @param	:(int) in_passwd_len: 패스워드 길이
 * @param	:(unsigned char*) in_salt: salt (8octet string)
 * @param	:(int) in_salt_len: salt 길이
 * @param	:(int) in_iter: iteration (1000이상 권고)
 * @param	:(unsigned char*) out: 암호화된 메시지 (return)
 * @param	:(int *) out_len: 암호화된 메시지 길이 (return)
 * @param	:(char *) in_cipher_alg: 대칭키 알고리즘
 * 			 [Available list]
 * 			"SEED-ECB"	| "SEED-CBC"		| "SEED-CFB"		| "SEED-OFB"		| "SEED-CTR"
 * 			"ARIA128-ECB"	| "ARIA128-CBC"	| "ARIA128-CFB"	| "ARIA128-OFB"	| "ARIA128-CTR"
 * 			"ARIA192-ECB"	| "ARIA192-CBC"	| "ARIA192-CFB"	| "ARIA192-OFB"	| "ARIA192-CTR"
 * 			"ARIA256-ECB"	| "ARIA256-CBC"	| "ARIA256-CFB"	| "ARIA256-OFB"	| "ARIA256-CTR"
 * 			"DES-ECB" 	| "DES-CBC"		| "DES-CFB"		| "DES-OFB"		| "DES-CTR"
 * 			"DES_EDE-ECB"	| "DES_EDE-CBC"	| "DES_EDE-CFB"	| "DES_EDE-OFB"	| "DES_EDE-CTR"
 * 			"AES128-ECB"	| "AES128-CBC"	| "AES128-CFB"	| "AES128-OFB"	| "AES128-CTR"
 * 			"AES192-ECB"	| "AES192-CBC"	| "AES192-CFB"	| "AES192-OFB"	| "AES192-CTR"
 * 			"AES256-ECB"	| "AES256-CBC"	| "AES256-CFB"	| "AES256-OFB"	| "AES256-CTR"
 * 			"RC5-ECB"		| "RC5-CBC"		| "RC5-CFB"		| "RC5-OFB"		| "RC5-CTR"
 * 			"BF-ECB"		| "BF-CBC"		| "BF-CFB"		| "BF-OFB"		| "BF-CTR"
 *
 * @param	:(char *) in_hash_alg: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 *
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK5_Encrypt_PBES1(const unsigned char *in_msg, int in_msg_len, unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, unsigned char *out, int *out_len, char *in_cipher_alg, char *in_hash_alg);

/**
 * @brief	: PBES1 Decrypt
 * @param	:(const unsigned char *) in_cipher: 복호화 할 메시지
 * @param	:(int) in_cipher_len: 복호화 할 메시지 길이
 * @param	:(unsigned char *) in_passwd: 패스워드
 * @param	:(int) in_passwd_len: 패스워드 길이
 * @param	:(unsigned char*) in_salt: salt (8octet string)
 * @param	:(int) in_salt_len: salt 길이
 * @param	:(int) in_iter: iteration (1000이상 권고)
 * @param	:(unsigned char*) out: 복호화된 메시지
 * @param	:(int *) out_len: 복호화된 메시지 길이
 * @param	:(char *) in_cipher_alg: 대칭키 알고리즘
 * 			 [Available list]
 * 			"SEED-ECB"	| "SEED-CBC"		| "SEED-CFB"		| "SEED-OFB"		| "SEED-CTR"
 * 			"ARIA128-ECB"	| "ARIA128-CBC"	| "ARIA128-CFB"	| "ARIA128-OFB"	| "ARIA128-CTR"
 * 			"ARIA192-ECB"	| "ARIA192-CBC"	| "ARIA192-CFB"	| "ARIA192-OFB"	| "ARIA192-CTR"
 * 			"ARIA256-ECB"	| "ARIA256-CBC"	| "ARIA256-CFB"	| "ARIA256-OFB"	| "ARIA256-CTR"
 * 			"DES-ECB" 	| "DES-CBC"		| "DES-CFB"		| "DES-OFB"		| "DES-CTR"
 * 			"DES_EDE-ECB"	| "DES_EDE-CBC"	| "DES_EDE-CFB"	| "DES_EDE-OFB"	| "DES_EDE-CTR"
 * 			"AES128-ECB"	| "AES128-CBC"	| "AES128-CFB"	| "AES128-OFB"	| "AES128-CTR"
 * 			"AES192-ECB"	| "AES192-CBC"	| "AES192-CFB"	| "AES192-OFB"	| "AES192-CTR"
 * 			"AES256-ECB"	| "AES256-CBC"	| "AES256-CFB"	| "AES256-OFB"	| "AES256-CTR"
 * 			"RC5-ECB"		| "RC5-CBC"		| "RC5-CFB"		| "RC5-OFB"		| "RC5-CTR"
 * 			"BF-ECB"		| "BF-CBC"		| "BF-CFB"		| "BF-OFB"		| "BF-CTR"
 *
 * @param	:(char *) in_hash_alg: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 *
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK5_Decrypt_PBES1(const unsigned char *in_cipher, int in_cipher_len, unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, unsigned char *out, int *out_len, char *in_cipher_alg, char *in_hash_alg);

/**
 * @brief	: PBES2 Encrypt
 * @param	:(const unsigned char *) in_msg: 암호화 할 메시지
 * @param	:(int) in_msg_len: 암호화 할 메시지 길이
 * @param	:(unsigned char *) in_passwd: 패스워드
 * @param	:(int) in_passwd_len: 패스워드 길이
 * @param	:(unsigned char*) in_salt: salt (8octet string)
 * @param	:(int) in_salt_len: salt 길이
 * @param	:(int) in_iter: iteration (1000이상 권고)
 * @param	:(unsigned char *) out: 암호화된 메시지 (return)
 * @param	:(int *) out_len: 암호화된 메시지 길이  (return)
 * @param	:(unsigned char **) out_iv: 초기벡터 	(return)
 * @param	:(int *) out_iv_len: 초기벡터 길이  	(return)
 * @param	:(char *) in_cipher_alg: 대칭키 알고리즘
 * 			 [Available list]
 * 			"SEED-ECB"	| "SEED-CBC"		| "SEED-CFB"		| "SEED-OFB"		| "SEED-CTR"
 * 			"ARIA128-ECB"	| "ARIA128-CBC"	| "ARIA128-CFB"	| "ARIA128-OFB"	| "ARIA128-CTR"
 * 			"ARIA192-ECB"	| "ARIA192-CBC"	| "ARIA192-CFB"	| "ARIA192-OFB"	| "ARIA192-CTR"
 * 			"ARIA256-ECB"	| "ARIA256-CBC"	| "ARIA256-CFB"	| "ARIA256-OFB"	| "ARIA256-CTR"
 * 			"DES-ECB" 	| "DES-CBC"		| "DES-CFB"		| "DES-OFB"		| "DES-CTR"
 * 			"DES_EDE-ECB"	| "DES_EDE-CBC"	| "DES_EDE-CFB"	| "DES_EDE-OFB"	| "DES_EDE-CTR"
 * 			"AES128-ECB"	| "AES128-CBC"	| "AES128-CFB"	| "AES128-OFB"	| "AES128-CTR"
 * 			"AES192-ECB"	| "AES192-CBC"	| "AES192-CFB"	| "AES192-OFB"	| "AES192-CTR"
 * 			"AES256-ECB"	| "AES256-CBC"	| "AES256-CFB"	| "AES256-OFB"	| "AES256-CTR"
 * 			"RC5-ECB"		| "RC5-CBC"		| "RC5-CFB"		| "RC5-OFB"		| "RC5-CTR"
 * 			"BF-ECB"		| "BF-CBC"		| "BF-CFB"		| "BF-OFB"		| "BF-CTR"
 * @param	:(char *) in_hash_alg: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 *
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK5_Encrypt_PBES2(const unsigned char *in_msg, int in_msg_len, unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, unsigned char *out, int *out_len, unsigned char **out_iv, int *out_iv_len, char *in_cipher_alg, char *in_hash_alg);

/**
 * @brief	: PBES2 Decrypt
 * @param	:(const unsigned char *) in_cipher: 복호화 할 메시지
 * @param	:(int) in_cipher_len: 복호화 할 메시지 길이
 * @param	:(unsigned char *) in_passwd: 패스워드
 * @param	:(int) in_passwd_len: 패스워드 길이
 * @param	:(unsigned char *) in_salt: salt (8octet string)
 * @param	:(int) in_salt_len: salt 길이
 * @param	:(int) in_iter: iteration (1000이상 권고)
 * @param	:(unsigned char *) out: 복호화된 메시지  (return)
 * @param	:(int *) out_len: 복호화된 메시지 길이   (return)
 * @param	:(unsigned char *) in_iv : 초기 벡터
 * @param	:(char *) in_cipher_alg: 대칭키 알고리즘
 * 			 [Available list]
 * 			"SEED-ECB"	| "SEED-CBC"		| "SEED-CFB"		| "SEED-OFB"		| "SEED-CTR"
 * 			"ARIA128-ECB"	| "ARIA128-CBC"	| "ARIA128-CFB"	| "ARIA128-OFB"	| "ARIA128-CTR"
 * 			"ARIA192-ECB"	| "ARIA192-CBC"	| "ARIA192-CFB"	| "ARIA192-OFB"	| "ARIA192-CTR"
 * 			"ARIA256-ECB"	| "ARIA256-CBC"	| "ARIA256-CFB"	| "ARIA256-OFB"	| "ARIA256-CTR"
 * 			"DES-ECB" 	| "DES-CBC"		| "DES-CFB"		| "DES-OFB"		| "DES-CTR"
 * 			"DES_EDE-ECB"	| "DES_EDE-CBC"	| "DES_EDE-CFB"	| "DES_EDE-OFB"	| "DES_EDE-CTR"
 * 			"AES128-ECB"	| "AES128-CBC"	| "AES128-CFB"	| "AES128-OFB"	| "AES128-CTR"
 * 			"AES192-ECB"	| "AES192-CBC"	| "AES192-CFB"	| "AES192-OFB"	| "AES192-CTR"
 * 			"AES256-ECB"	| "AES256-CBC"	| "AES256-CFB"	| "AES256-OFB"	| "AES256-CTR"
 * 			"RC5-ECB"		| "RC5-CBC"		| "RC5-CFB"		| "RC5-OFB"		| "RC5-CTR"
 * 			"BF-ECB"		| "BF-CBC"		| "BF-CFB"		| "BF-OFB"		| "BF-CTR"
 * @param	:(char *) in_hash_alg: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 *
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK5_Decrypt_PBES2(const unsigned char *in_cipher, int in_cipher_len, unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, unsigned char *out, int *out_len, unsigned char *in_iv, char *in_cipher_alg, char *in_hash_alg);

/**
 * @brief	: PBKDF1
 * @param	:(unsigned char *) in_passwd: 패스워드
 * @param	:(int) in_passwd_len: 패스워드 길이
 * @param	:(unsigned char *) in_salt: salt (8octet string)
 * @param	:(int) in_salt_len: salt 길이
 * @param	:(int) in_iter: iteration (1000이상 권고)
 * @param	:(char *) in_hash_alg: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(int) req_key_len: 요청하는 키 길이 (해시함수결과값의 길이보다 같거나 작아야 함)
 * @param	:(unsigned char *) out_key: PBKDF1을 통해 생성된 키 (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK5_PBKDF1(unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, char *in_hash_alg, int req_key_len, unsigned char *out_key);

/**
 * @brief	: PBKDF2
 * @param	:(unsigned char *) in_passwd: 패스워드
 * @param	:(int) in_passwd_len: 패스워드 길이
 * @param	:(unsigned char *) in_salt: salt (8octet string)
 * @param	:(int) in_salt_len: salt 길이
 * @param	:(int) in_iter: iteration (1000이상 권고)
 * @param	:(char *) in_hash_alg: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(unsigned char *) out_key: PBKDF1을 통해 생성된 키(return)
 * @param	:(int) in_key_len: out_key 버퍼 사이즈
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK5_PBKDF2(unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, char *in_hash_alg, unsigned char *out_key, int in_key_len);

#ifndef WIN32
/* pkcs7.c */
/**
 * @brief	: PKCS#7 generate cert trust list
 * @param	:(int) version				: version of certificates trust list (fixed to 1)
 * @param	:(unsigned long) seq			: sequence number for CTL
 * @param	:(X509_TIME) this_update		: creation date of CTL
 * @param	:(unsigned long) valid_days		: next creation date of CTL = this_update + valid_days
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(PKI_STR_INFO *) trusted_certs		: trusted certificate list
 * @param	:(int) trusted_certs_cnt 		: trusted certificates count
 * @param	:(PKI_STR_INFO *) sign cert key		: cert, privkey, priv_passwd structure of signer
 * @param	:(unsigned char **) out			: signed_data (return)
 * @param	:(int *) out_len			: length of signed_data (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Make_Cert_Trust_List(int version, unsigned long seq, X509_TIME *this_update, unsigned long valid_days, char *hash_alg, PKI_STR_INFO **trusted_certs, int trusted_certs_cnt, PKI_STR_INFO* sign_cert_key, unsigned char** out, int *out_len);
#endif

#ifndef WIN32
/**
 * @brief	: PKCS#7 generate cert trust list
 * @param	:(int) version				: version of certificates trust list (fixed to 1)
 * @param	:(unsigned long) seq			: sequence number for CTL
 * @param	:(X509_TIME) this_update		: creation date of CTL
 * @param	:(X509_TIME) next_update		: next creation date of CTL
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(PKI_STR_INFO *) trusted_certs		: trusted certificate list
 * @param	:(int) trusted_certs_cnt 		: trusted certificates count
 * @param	:(PKI_STR_INFO *) sign cert key		: cert, privkey, priv_passwd structure of signer
 * @param	:(unsigned char **) out			: signed_data (return)
 * @param	:(int *) out_len			: length of signed_data (return)
 * @param	:(PF_SIGN_CB) pf_sign_cb                : for external PKCS#11 HSM or PACCEL
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Make_Cert_Trust_List2(int version, unsigned long seq, X509_TIME *this_update, X509_TIME *next_update, char *hash_alg, PKI_STR_INFO **trusted_certs, int trusted_certs_cnt, PKI_STR_INFO* sign_cert_key, unsigned char** out, int *out_len, PF_SIGN_CB pf_sign_cb);
#endif
#ifndef WIN32
/**
* @brief	: PKCS#7 verify cert trust list
* @param	:(int) version				: version of certificates trust list (fixed to 1)
* @param	:(unsigned char*) ctl_der               : A DER formed CTL for verify target cert
* @param	:(int) ctl_der_len                      : length of CTL in bytes
* @param	:(PKI_STR_INFO *) signer_issuer_chain   : root ca certs, ca cert chain for verify signer cert
* @param	:(int) signer_issuer_cnt                : count of certs in signer_issuer_chain
* @param	:(PKI_STR_INFO *) signer_cert           : signer's cert for verify signature of CTL
* @param	:(PKI_STR_INFO *) target_issuer_chain   : root ca certs, ca cert chain for verify target cert
* @param	:(int) target_issuer_cnt                : count of certs in target_issuer_chain
* @param	:(PKI_STR_INFO *) target_cert           : target cert for verification ( check if target is in CTL, check if target is in valid CPV)
* @return	:(int) successfully verified=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Verify_Cert_Trust_List(int version, unsigned char* ctl_der, int ctl_der_len, PKI_STR_INFO** signer_issuer_chain, int signer_issuer_cnt, PKI_STR_INFO* signer_cert, PKI_STR_INFO** target_issuer_chain, int target_issuer_cnt, PKI_STR_INFO* target_cert );
#endif
#ifndef WIN32
/**
* @brief	: PKCS#7 verify cert trust list
* @param	:(int) version				: version of certificates trust list (fixed to 1)
* @param	:(unsigned char*) ctl_der               : A DER formed CTL for verify target cert
* @param	:(int) ctl_der_len                      : length of CTL in bytes
* @param	:(PKI_STR_INFO *) signer_issuer_chain   : root ca certs, ca cert chain for verify signer cert
* @param	:(int) signer_issuer_cnt                : count of certs in signer_issuer_chain
* @param	:(PKI_STR_INFO *) signer_cert           : signer's cert for verify signature of CTL
* @param	:(PKI_STR_INFO *) target_issuer_chain   : root ca certs, ca cert chain for verify target cert
* @param	:(int) target_issuer_cnt                : count of certs in target_issuer_chain
* @param	:(PKI_STR_INFO *) target_cert           : target cert for verification ( check if target is in CTL, check if target is in valid CPV)
* @param	:(PF_VERIFY_CB) pf_verify_cb            : for PKCS#11 or PACCEL
* @return	:(int) successfully verified=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Verify_Cert_Trust_List2(int version, unsigned char* ctl_der, int ctl_der_len, PKI_STR_INFO** signer_issuer_chain, int signer_issuer_cnt, PKI_STR_INFO* signer_cert, PKI_STR_INFO** target_issuer_chain, int target_issuer_cnt, PKI_STR_INFO* target_cert, PF_VERIFY_CB pf_verify_cb );
#endif
/* pkcs7.c */
/**
 * @brief	: PKCS#7 generate signed-data
 * @param	:(unsigned char *) msg			: plain message for sign
 * @param	:(int) msg_len				: length of msg
 * @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
 * @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
 * @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char **) out		: signed_data (return)
 * @param	:(int *) out_len				: length of signed_data (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Make_Signed_Data(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int out_type, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 generate signed-data 2
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Make_Signed_Data_With_Option(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int ins_cert, int ins_contentinfo, int out_type, unsigned char **out, int *out_len);


/**
* @brief	: PKCS#7 generate signed-data 3 - random insert
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) ins_random			: 0 - no add, 1 - add random.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/

INISAFECORE_API int ICL_PK7_Make_Signed_Data_With_Random(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char **out, int *out_len);

/**
* @brief    : PKCS#7 generate signed-data 4 - multi sign
* @param    :(ICL_MSG_INFO*) multi_msg            : plain message for sign ( ICL_MSG_INFO[]  )
* @param    :(int) multi_msg_count                : message of count ( ICL_MSG_INFO[] - array count )
* @param    :(PKI_STR_INFO *) rsa_keys        : cert, privkey, priv_passwd structure of signer
* @param    :(char *) hash_alg            : hash algorithm name
*             ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param    :(struct tm *) recv_time        : received sign time (if this is NULL, generate system time)
* @param    :(int) version                : ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param    :(int) ins_cert                : 0 - no add, 1 - add cert.
* @param    :(int) ins_contentinfo        : 0 - no add, 1 - add contentinfo.
* @param    :(int) ins_random            : 0 - no add, 1 - add random.
* @param    :(int) out_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param    :(ICL_SIGNED_DATA_INFO **) multi_signed_data        : signed_data array  (return ICL_SIGNED_DATA_INFO[] )
* @param    :(int *) multi_signed_data_cout                : count of signed_data (return ICL_SIGNED_DATA_INFO[] - count)
* @return    :(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Make_Multi_Signed_Data_With_Random(ICL_MSG_INFO *multi_msg, int multi_msg_count, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int ins_cert, int ins_contentinfo, int ins_random, int out_type, ICL_SIGNED_DATA_INFO **multi_signed_data, int* multi_signed_data_cout);

/**
* @brief    : PKCS#7 generate signed-data 4 - multi sign
* @param    :(ICL_MSG_INFO*) multi_msg            : plain message for sign ( ICL_MSG_INFO[]  )
* @param    :(int) multi_msg_count                : message of count ( ICL_MSG_INFO[] - array count )
* @param    :(PKI_STR_INFO *) rsa_keys        : cert, privkey, priv_passwd structure of signer
* @param    :(char *) hash_alg            : hash algorithm name
*             ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param    :(struct tm *) recv_time        : received sign time (if this is NULL, generate system time)
* @param    :(int) version                : ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param    :(int) ins_cert                : 0 - no add, 1 - add cert.
* @param    :(int) ins_contentinfo        : 0 - no add, 1 - add contentinfo.
* @param    :(int) ins_random            : 0 - no add, 1 - add random.
* @param    :(int) out_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param    :(int) enc_alg                : SignerInfo DigestEncryptionAlgorithm (ICL_RSASSA_PKCS1_15 | ICL_RSASSA_PSS)
* @param    :(ICL_SIGNED_DATA_INFO **) multi_signed_data        : signed_data array  (return ICL_SIGNED_DATA_INFO[] )
* @param    :(int *) multi_signed_data_cout                : count of signed_data (return ICL_SIGNED_DATA_INFO[] - count)
* @return    :(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Make_Multi_Signed_Data_With_Random_EncAlg(ICL_MSG_INFO *multi_msg, int multi_msg_count, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int ins_cert, int ins_contentinfo, int ins_random, int out_type, int enc_alg, ICL_SIGNED_DATA_INFO **multi_signed_data, int* multi_signed_data_cout);


/**
* @brief	: PKCS#7 generate signed-data 3 - random insert
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) ins_random			: 0 - no add, 1 - add random.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(int) remove_timestamp		: ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
* @param	:(unsigned char *)unauthmsg : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.3.2  - initech more info)
* @param	:(int) unauthmsg_len        : length of unauthmsg
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/

INISAFECORE_API int ICL_PK7_Make_Signed_Data_With_Unauth_Attr(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int ins_cert, int ins_contentinfo, int ins_random, int out_type, int remove_timestamp, unsigned char *unauthmsg, int unauthmsg_len, unsigned char **out, int *out_len);


/**
 * @brief	: PKCS#7 generate signed-data - replay attack
 * @param	:(unsigned char *) msg			: plain message for sign
 * @param	:(int) msg_len				: length of msg
 * @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
 * @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
 * @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
 * @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
 * @param	:(int) ins_random			: 0 - no add, 1 - add random.
 * @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(int) remove_timestamp		: ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
 * @param	:(unsigned char *)unauthmsg : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.3.2  - initech more info)
 * @param	:(int) unauthmsg_len        : length of unauthmsg
 * @param	:(unsigned char *)replay_attack_check_data : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.4.2  - replay_attack_check_data)
 * @param	:(int) replay_attack_check_data_len        : length of replayattackdata
 * @param	:(unsigned char **) out		: signed_data (return)
 * @param	:(int *) out_len				: length of signed_data (return)
 * @return	:(int) success=0, error=error code
 */

INISAFECORE_API int ICL_PK7_Make_Signed_Data_With_Unauth_Attr_ReplayAttack(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int ins_cert, int ins_contentinfo, int ins_random, int out_type, int remove_timestamp, unsigned char *unauthmsg, int unauthmsg_len, unsigned char *replay_attack_check_data, int replay_attack_check_data_len, unsigned char **out, int *out_len);

/**
 * @brief    : PKCS#7 generate signed-data - replay attack
 * @param    :(unsigned char *) msg            : plain message for sign
 * @param    :(int) msg_len                : length of msg
 * @param    :(PKI_STR_INFO *) rsa_keys        : cert, privkey, priv_passwd structure of signer
 * @param    :(char *) hash_alg            : hash algorithm name
 *             ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param    :(struct tm *) recv_time        : received sign time (if this is NULL, generate system time)
 * @param    :(int) version                : ICL_PK7_VER_14 | ICL_PK7_VER_15
 * @param    :(int) ins_cert                : 0 - no add, 1 - add cert.
 * @param    :(int) ins_contentinfo        : 0 - no add, 1 - add contentinfo.
 * @param    :(int) ins_random            : 0 - no add, 1 - add random.
 * @param    :(int) out_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(int) remove_timestamp        : ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
 * @param    :(unsigned char *)unauthmsg : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.3.2  - initech more info)
 * @param    :(int) unauthmsg_len        : length of unauthmsg
 * @param    :(unsigned char *)replay_attack_check_data : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.4.2  - replay_attack_check_data)
 * @param    :(int) replay_attack_check_data_len        : length of replayattackdata
 * @param    :(int) enc_alg                : SignerInfo DigestEncryptionAlgorithm (ICL_RSASSA_PKCS1_15 | ICL_RSASSA_PSS)
 * @param    :(unsigned char **) out        : signed_data (return)
 * @param    :(int *) out_len                : length of signed_data (return)
 * @return    :(int) success=0, error=error code
 */

INISAFECORE_API int ICL_PK7_Make_Signed_Data_With_Unauth_Attr_ReplayAttack_EncAlg(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int ins_cert, int ins_contentinfo, int ins_random, int out_type, int remove_timestamp, unsigned char *unauthmsg, int unauthmsg_len, unsigned char *replay_attack_check_data, int replay_attack_check_data_len, int enc_alg, unsigned char **out, int *out_len);



/**
* @brief	: PKCS#7 generate signed-data 4 - no plain, only messageDigest
* @param	:(unsigned char *) md			: message digest
* @param	:(int) md_len				: length of md
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(int) remove_timestamp		: ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/


INISAFECORE_API int ICL_PK7_Make_Signed_Data_WithOut_Plain_With_MD(unsigned char *md, int md_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int out_type, int remove_timestamp, unsigned char **out, int *out_len);

/**
* @brief    : PKCS#7 generate signed-data 4 - no plain, only messageDigest
* @param    :(unsigned char *) md            : message digest
* @param    :(int) md_len                : length of md
* @param    :(PKI_STR_INFO *) rsa_keys        : cert, privkey, priv_passwd structure of signer
* @param    :(char *) hash_alg            : hash algorithm name
*             ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param    :(struct tm *) recv_time        : received sign time (if this is NULL, generate system time)
* @param    :(int) ins_cert                : 0 - no add, 1 - add cert.
* @param    :(int) out_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param    :(int) remove_timestamp        : ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
* @param    :(unsigned char **) out        : signed_data (return)
* @param    :(int *) out_len                : length of signed_data (return)
* @return    :(int) success=0, error=error code
*/


INISAFECORE_API int ICL_PK7_Make_Signed_Data_WithOut_Plain_With_MD_Option(unsigned char *md, int md_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int ins_cert, int out_type, int remove_timestamp, unsigned char **out, int *out_len);


/**
 * @brief	: PKCS#7 generate signed-data 4 - no plain, only messageDigest
 * @param	:(unsigned char *) md			: message digest
 * @param	:(int) md_len				: length of md
 * @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
 * @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(int) remove_timestamp		: ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
 * @param	:(unsigned char *)replay_attack_check_data : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.4.2  - replay_attack_check_data)
 * @param	:(int) replay_attack_check_data_len        : length of replayattackdata
 * @param	:(unsigned char **) out		: signed_data (return)
 * @param	:(int *) out_len				: length of signed_data (return)
 * @return	:(int) success=0, error=error code
 */


INISAFECORE_API int ICL_PK7_Make_Signed_Data_WithOut_Plain_With_MD_ReplayAttack(unsigned char *md, int md_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int out_type, int remove_timestamp, unsigned char *replay_attack_check_data, int replay_attack_check_data_len, unsigned char **out, int *out_len);


/**
 * @brief    : PKCS#7 generate signed-data 4 - no plain, only messageDigest
 * @param    :(unsigned char *) md            : message digest
 * @param    :(int) md_len                : length of md
 * @param    :(PKI_STR_INFO *) rsa_keys        : cert, privkey, priv_passwd structure of signer
 * @param    :(char *) hash_alg            : hash algorithm name
 *             ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param    :(struct tm *) recv_time        : received sign time (if this is NULL, generate system time)
 * @param    :(int) ins_cert : 0 - no add, 1 - add cert.
 * @param    :(int) out_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(int) remove_timestamp        : ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
 * @param    :(unsigned char *)replay_attack_check_data : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.4.2  - replay_attack_check_data)
 * @param    :(int) replay_attack_check_data_len        : length of replayattackdata
 * @param    :(int) enc_alg : SignerInfo DigestEncryptionAlgorithm (ICL_RSASSA_PKCS1_15 | ICL_RSASSA_PSS)
 * @param    :(unsigned char **) out        : signed_data (return)
 * @param    :(int *) out_len                : length of signed_data (return)
 * @return    :(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Make_Signed_Data_WithOut_Plain_With_MD_ReplayAttack_Option_EncAlg(unsigned char *md, int md_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int ins_cert, int out_type, int remove_timestamp, unsigned char *replay_attack_check_data, int replay_attack_check_data_len, int enc_alg, unsigned char **out, int *out_len);


/**
* @brief	: PKCS#7 generate signed-data 3 - random insert
* @param	:(unsigned char *) sign			: plain message for sign
* @param	:(int) sign_len				: length of msg
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) ins_random			: 0 - no add, 1 - add random.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Make_Signed_Data_With_OutSign(unsigned char *sign, int sign_len, unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int ins_cert, int ins_contentinfo, int out_type,  unsigned char **out, int *out_len);


/**
 * @brief	: PKCS#7 generate signed-data 3 - random insert
 * @param	:(unsigned char *) sign			: plain message for sign
 * @param	:(int) sign_len				: length of msg
 * @param	:(unsigned char *) msg			: plain message for sign
 * @param	:(int) msg_len				: length of msg
 * @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
 * @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
 * @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
 * @param	:(unsigned char *)replay_attack_check_data : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.4.2  - replay_attack_check_data)
 * @param	:(int) replay_attack_check_data_len        : length of replayattackdata
 * @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char **) out		: signed_data (return)
 * @param	:(int *) out_len				: length of signed_data (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Make_Signed_Data_With_OutSign_ReplayAttack(unsigned char *sign, int sign_len, unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int ins_cert, int ins_contentinfo, unsigned char *replay_attack_check_data, int replay_attack_check_data_len, int out_type,  unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 generate signed-data
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) sign		: encryptedDigest
* @param	:(int) signLen				: encryptedDigest Length
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Make_Signed_Data_HSM(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int out_type, unsigned char* sign, int signLen, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 generate signed-data
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) sign		: encryptedDigest
* @param	:(int) signLen				: encryptedDigest Length
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Make_Signed_Data_HSM_With_Option(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time,int version, int ins_cert, int ins_contentinfo,int out_type, unsigned char* sign, int signLen, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 generate signed-data
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) ins_random			: 0 - no add, 1 - add random.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) sign		: encryptedDigest
* @param	:(int) signLen				: encryptedDigest Length
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Make_Signed_Data_HSM_With_Random(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time,int version, int ins_cert, int ins_contentinfo,int ins_random, int out_type, unsigned char* sign, int signLen, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 generate signed-data
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) ins_random			: 0 - no add, 1 - add random.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) sign		: encryptedDigest
* @param	:(int) signLen				: encryptedDigest Length
* @param	:(unsigned char *)unauthmsg : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.3.2  - initech more info)
* @param	:(int) unauthmsg_len        : length of unauthmsg
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/


INISAFECORE_API int ICL_PK7_Make_Signed_Data_HSM_With_Unauth_Attr(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys,
												  char *hash_alg, struct tm *recv_time,int version, int ins_cert, int ins_contentinfo, int ins_random, int out_type,
												  unsigned char* sign, int signLen, unsigned char *unauthmsg, int unauthmsg_len, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 generate signed-data_hsm_init
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char **) sign	: signner data
* @param	:(int *) signLen			: signner data length
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Make_Signed_Data_Init_HSM(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys,char *hash_alg, struct tm *recv_time, int out_type,unsigned char **signinfo, int *signinfo_len, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 generate signed-data_hsm_init
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char **) sign	: signner data
* @param	:(int *) signLen			: signner data length
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Make_Signed_Data_Init_HSM_With_Option(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time,int version, int ins_cert, int ins_contentinfo, int out_type,unsigned char **signinfo, int *signinfo_len, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 generate signed-data_hsm_init
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(int) remove_timestamp		: ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
* @param	:(unsigned char **) sign	: signner data
* @param	:(int *) signLen			: signner data length
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Make_Signed_Data_Init_HSM_Without_Plain_With_MD(unsigned char *hash_data, int hash_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int out_type, int remove_timestamp, unsigned char **signinfo, int *signinfo_len, unsigned char **out, int *out_len);


/**
 * @brief	: PKCS#7 generate signed-data_hsm_init
 * @param	:(unsigned char *) msg			: plain message for sign
 * @param	:(int) msg_len				: length of msg
 * @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
 * @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(int) remove_timestamp		: ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
 * @param	:(unsigned char **) sign	: signner data
 * @param	:(int *) signLen			: signner data length
 * @param	:(unsigned char *)replay_attack_check_data : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.4.2  - replay_attack_check_data)
 * @param	:(int) replay_attack_check_data_len        : length of replayattackdata
 * @param	:(unsigned char **) out		: signed_data (return)
 * @param	:(int *) out_len				: length of signed_data (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Make_Signed_Data_Init_HSM_Without_Plain_With_MD_ReplayAttack(unsigned char *hash_data, int hash_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int out_type, int remove_timestamp, unsigned char **signinfo, int *signinfo_len, unsigned char *replay_attack_check_data, int replay_attack_check_data_len, unsigned char **out, int *out_len);


/**
* @brief	: PKCS#7 generate signed-data_hsm_init
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @par
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) ins_random			: 0 - no add, 1 - add random.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char **) sign	: signner data
* @param	:(int *) signLen			: signner data length
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/

INISAFECORE_API int ICL_PK7_Make_Signed_Data_Init_HSM_With_Random(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time,int version, int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char **signinfo, int *signinfo_len, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 generate signed-data_hsm_init
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) ins_random			: 0 - no add, 1 - add random.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(int) remove_timestamp		: ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
* @param	:(unsigned char **) sign	: signner data
* @param	:(int *) signLen			: signner data length
* @param	:(unsigned char *)unauthmsg : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.3.2  - initech more info)
* @param	:(int) unauthmsg_len        : length of unauthmsg
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/

INISAFECORE_API int ICL_PK7_Make_Signed_Data_Init_HSM_With_Unauth_Attr(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys,
													   char *hash_alg, struct tm *recv_time,int version, int ins_cert, int ins_contentinfo, int ins_random, int out_type, int remove_timestamp, unsigned char **signinfo, int *signinfo_len,
													   unsigned char *unauthmsg, int unauthmsg_len, unsigned char **out, int *out_len);

/**
 * @brief	: PKCS#7 generate signed-data_hsm_init
 * @param	:(unsigned char *) msg			: plain message for sign
 * @param	:(int) msg_len				: length of msg
 * @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
 * @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
 * @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
 * @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
 * @param	:(int) ins_random			: 0 - no add, 1 - add random.
 * @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(int) remove_timestamp		: ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
 * @param	:(unsigned char **) sign	: signner data
 * @param	:(int *) signLen			: signner data length
 * @param	:(unsigned char *)unauthmsg : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.3.2  - initech more info)
 * @param	:(int) unauthmsg_len        : length of unauthmsg
 * @param	:(unsigned char *)replay_attack_check_data : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.4.2  - replay_attack_check_data)
 * @param	:(int) replay_attack_check_data_len        : length of replayattackdata
 * @param	:(unsigned char **) out		: signed_data (return)
 * @param	:(int *) out_len				: length of signed_data (return)
 * @return	:(int) success=0, error=error code
 */

INISAFECORE_API int ICL_PK7_Make_Signed_Data_Init_HSM_With_Unauth_Attr_ReplayAttack(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys,
                                                                       char *hash_alg, struct tm *recv_time,int version, int ins_cert, int ins_contentinfo, int ins_random, int out_type, int remove_timestamp, unsigned char **signinfo, int *signinfo_len,
                                                                       unsigned char *unauthmsg, int unauthmsg_len, unsigned char *replay_attack_check_data, int replay_attack_check_data_len, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 generate signed-data
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) sign		: encryptedDigest
* @param	:(int) signLen				: encryptedDigest Length
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Make_Signed_Data_Final_HSM(int in_type, unsigned char *p7der, int p7der_len, unsigned char* sign, int signLen, int out_type, unsigned char **out, int *out_len);

/**
 * @brief	: PKCS#7 add signed-data to original signed-data
 * @param	:(int) in_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) in			: oroginal signed_data
 * @param	:(int) in_len					: length of signed_data
 * @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
 * @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
 * @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char **) out		: signed_data (return)
 * @param	:(int *) out_len				: length of signed_data (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Add_Signed_Data(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int out_type, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 add signed-data to original signed-data
* @param	:(int) in_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) in			: oroginal signed_data
* @param	:(int) in_len					: length of signed_data
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Add_Signed_Data_With_Option(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version,int ins_cert, int ins_contentinfo, int out_type, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 add signed-data to original signed-data
* @param	:(int) in_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) in			: oroginal signed_data
* @param	:(int) in_len					: length of signed_data
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) ins_random			: 0 - no add, 1 - add random.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Add_Signed_Data_With_Random(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version,int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 add signed-data to original signed-data
* @param	:(int) in_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) in			: oroginal signed_data
* @param	:(int) in_len					: length of signed_data
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) ins_random			: 0 - no add, 1 - add random.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *)unauthmsg : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.3.2  - initech more info)
* @param	:(int) unauthmsg_len        : length of unauthmsg
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/

INISAFECORE_API int ICL_PK7_Add_Signed_Data_With_Unauth_Attr(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time,
											 int version,int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char *unauthmsg, int unauthmsg_len,
											 unsigned char **out, int *out_len);

/**
 * @brief	: PKCS#7 add signed-data to original signed-data
 * @param	:(int) in_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) in			: oroginal signed_data
 * @param	:(int) in_len					: length of signed_data
 * @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
 * @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
 * @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
 * @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
 * @param	:(int) ins_random			: 0 - no add, 1 - add random.
 * @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *)unauthmsg : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.3.2  - initech more info)
 * @param	:(int) unauthmsg_len        : length of unauthmsg
 * @param	:(unsigned char *)replay_attack_check_data : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.4.2  - replay_attack_check_data)
 * @param	:(int) replay_attack_check_data_len        : length of replayattackdata
 * @param	:(unsigned char **) out		: signed_data (return)
 * @param	:(int *) out_len				: length of signed_data (return)
 * @return	:(int) success=0, error=error code
 */

INISAFECORE_API int ICL_PK7_Add_Signed_Data_With_Unauth_Attr_ReplayAttack(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time,
                                                             int version,int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char *unauthmsg, int unauthmsg_len,
                                                             unsigned char *replay_attack_check_data, int replay_attack_check_data_len, unsigned char **out, int *out_len);

/**
 * @brief    : PKCS#7 add signed-data to original signed-data
 * @param    :(int) in_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(unsigned char *) in            : oroginal signed_data
 * @param    :(int) in_len                    : length of signed_data
 * @param    :(PKI_STR_INFO *) rsa_keys        : cert, privkey, priv_passwd structure of signer
 * @param    :(char *) hash_alg            : hash algorithm name
 *             ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param    :(struct tm *) recv_time        : received sign time (if this is NULL, generate system time)
 * @param    :(int) version                : ICL_PK7_VER_14 | ICL_PK7_VER_15
 * @param    :(int) ins_cert                : 0 - no add, 1 - add cert.
 * @param    :(int) ins_contentinfo        : 0 - no add, 1 - add contentinfo.
 * @param    :(int) ins_random            : 0 - no add, 1 - add random.
 * @param    :(int) out_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(unsigned char *)unauthmsg : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.3.2  - initech more info)
 * @param    :(int) unauthmsg_len        : length of unauthmsg
 * @param    :(unsigned char *)replay_attack_check_data : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.4.2  - replay_attack_check_data)
 * @param    :(int) replay_attack_check_data_len        : length of replayattackdata
 * @param    :(int) enc_alg                : SignerInfo DigestEncryptionAlgorithm (ICL_RSASSA_PKCS1_15 | ICL_RSASSA_PSS)
 * @param    :(unsigned char **) out        : signed_data (return)
 * @param    :(int *) out_len                : length of signed_data (return)
 * @return    :(int) success=0, error=error code
 */

INISAFECORE_API int ICL_PK7_Add_Signed_Data_With_Unauth_Attr_ReplayAttack_EncAlg(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time,
                                                             int version,int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char *unauthmsg, int unauthmsg_len,
                                                             unsigned char *replay_attack_check_data, int replay_attack_check_data_len, int enc_alg, unsigned char **out, int *out_len);



/**
 * @brief    : PKCS#7 add signed-data to original signed-data
 * @param    :(int) in_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(unsigned char *) in            : oroginal signed_data
 * @param    :(int) in_len                    : length of signed_data
 * @param    :(PKI_STR_INFO *) rsa_keys        : cert, privkey, priv_passwd structure of signer
 * @param    :(char *) hash_alg            : hash algorithm name
 *             ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param    :(struct tm *) recv_time        : received sign time (if this is NULL, generate system time)
 * @param    :(int) version                : ICL_PK7_VER_14 | ICL_PK7_VER_15
 * @param    :(int) out_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(unsigned char **) out        : signed_data (return)
 * @param    :(int *) out_len                : length of signed_data (return)
 * @return    :(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Add_Signed_Data_Without_Plain(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int out_type, unsigned char **out, int *out_len);

/**
 * @brief    : PKCS#7 add signed-data to original signed-data
 * @param    :(int) in_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(unsigned char *) in            : oroginal signed_data
 * @param    :(int) in_len                    : length of signed_data
 * @param    :(PKI_STR_INFO *) rsa_keys        : cert, privkey, priv_passwd structure of signer
 * @param    :(char *) hash_alg            : hash algorithm name
 *             ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param    :(struct tm *) recv_time        : received sign time (if this is NULL, generate system time)
 * @param    :(int) version                : ICL_PK7_VER_14 | ICL_PK7_VER_15
 * @param    :(int) ins_cert                : 0 - no add, 1 - add cert.
 * @param    :(int) ins_contentinfo        : 0 - no add, 1 - add contentinfo.
 * @param    :(int) out_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(unsigned char **) out        : signed_data (return)
 * @param    :(int *) out_len                : length of signed_data (return)
 * @return    :(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Add_Signed_Data_With_Option_Without_Plain(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version,int ins_cert, int ins_contentinfo, int out_type, unsigned char **out, int *out_len);

/**
 * @brief    : PKCS#7 add signed-data to original signed-data
 * @param    :(int) in_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(unsigned char *) in            : oroginal signed_data
 * @param    :(int) in_len                    : length of signed_data
 * @param    :(PKI_STR_INFO *) rsa_keys        : cert, privkey, priv_passwd structure of signer
 * @param    :(char *) hash_alg            : hash algorithm name
 *             ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param    :(struct tm *) recv_time        : received sign time (if this is NULL, generate system time)
 * @param    :(int) version                : ICL_PK7_VER_14 | ICL_PK7_VER_15
 * @param    :(int) ins_cert                : 0 - no add, 1 - add cert.
 * @param    :(int) ins_contentinfo        : 0 - no add, 1 - add contentinfo.
 * @param    :(int) ins_random            : 0 - no add, 1 - add random.
 * @param    :(int) out_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(unsigned char **) out        : signed_data (return)
 * @param    :(int *) out_len                : length of signed_data (return)
 * @return    :(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Add_Signed_Data_With_Random_Without_Plain(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version,int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char **out, int *out_len);

/**
 * @brief    : PKCS#7 add signed-data to original signed-data
 * @param    :(int) in_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(unsigned char *) in            : oroginal signed_data
 * @param    :(int) in_len                    : length of signed_data
 * @param    :(PKI_STR_INFO *) rsa_keys        : cert, privkey, priv_passwd structure of signer
 * @param    :(char *) hash_alg            : hash algorithm name
 *             ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param    :(struct tm *) recv_time        : received sign time (if this is NULL, generate system time)
 * @param    :(int) version                : ICL_PK7_VER_14 | ICL_PK7_VER_15
 * @param    :(int) ins_cert                : 0 - no add, 1 - add cert.
 * @param    :(int) ins_contentinfo        : 0 - no add, 1 - add contentinfo.
 * @param    :(int) ins_random            : 0 - no add, 1 - add random.
 * @param    :(int) out_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(unsigned char *)unauthmsg : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.3.2  - initech more info)
 * @param    :(int) unauthmsg_len        : length of unauthmsg
 * @param    :(unsigned char **) out        : signed_data (return)
 * @param    :(int *) out_len                : length of signed_data (return)
 * @return    :(int) success=0, error=error code
 */

INISAFECORE_API int ICL_PK7_Add_Signed_Data_With_Unauth_Attr_Without_Plain(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm 		*recv_time,int version,int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char *unauthmsg, int unauthmsg_len, unsigned char **out, int *out_len);

/**
 * @brief    : PKCS#7 add signed-data to original signed-data
 * @param    :(int) in_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(unsigned char *) in            : oroginal signed_data
 * @param    :(int) in_len                    : length of signed_data
 * @param    :(PKI_STR_INFO *) rsa_keys        : cert, privkey, priv_passwd structure of signer
 * @param    :(char *) hash_alg            : hash algorithm name
 *             ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param    :(struct tm *) recv_time        : received sign time (if this is NULL, generate system time)
 * @param    :(int) version                : ICL_PK7_VER_14 | ICL_PK7_VER_15
 * @param    :(int) ins_cert                : 0 - no add, 1 - add cert.
 * @param    :(int) ins_contentinfo        : 0 - no add, 1 - add contentinfo.
 * @param    :(int) ins_random            : 0 - no add, 1 - add random.
 * @param    :(int) out_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(unsigned char *)unauthmsg : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.3.2  - initech more info)
 * @param    :(int) unauthmsg_len        : length of unauthmsg
 * @param     :(int) enc_alg : SignerInfo DigestEncryptionAlgorithm (ICL_RSASSA_PKCS1_15 | ICL_RSASSA_PSS)
 * @param    :(unsigned char **) out        : signed_data (return)
 * @param    :(int *) out_len                : length of signed_data (return)
 * @return    :(int) success=0, error=error code
 */

INISAFECORE_API int ICL_PK7_Add_Signed_Data_With_Unauth_Attr_Without_Plain_EncAlg(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time,int version,int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char *unauthmsg, int unauthmsg_len, int enc_alg, unsigned char **out, int *out_len);



/**
* @brief	: PKCS#7 add signed-data to original signed-data
* @param	:(int) in_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) in			: oroginal signed_data
* @param	:(int) in_len					: length of signed_data
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) sign		: encryptedDigest
* @param	:(int) signLen				: encryptedDigest Length
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Add_Signed_Data_HSM(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int out_type, unsigned char* sign, int signLen, unsigned char **out, int *out_len);


/**
* @brief	: PKCS#7 add signed-data to original signed-data
* @param	:(int) in_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) in			: oroginal signed_data
* @param	:(int) in_len					: length of signed_data
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) sign		: encryptedDigest
* @param	:(int) signLen				: encryptedDigest Length
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Add_Signed_Data_HSM_With_Option(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version,int ins_cert, int ins_contentinfo, int out_type, unsigned char* sign, int signLen, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 add signed-data to original signed-data
* @param	:(int) in_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) in			: oroginal signed_data
* @param	:(int) in_len					: length of signed_data
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) ins_random			: 0 - no add, 1 - add random.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) sign		: encryptedDigest
* @param	:(int) signLen				: encryptedDigest Length
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Add_Signed_Data_HSM_With_Random(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version,int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char* sign, int signLen, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 add signed-data to original signed-data
* @param	:(int) in_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) in			: oroginal signed_data
* @param	:(int) in_len					: length of signed_data
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
* @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
* @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
* @param	:(int) ins_random			: 0 - no add, 1 - add random.
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) sign		: encryptedDigest
* @param	:(int) signLen				: encryptedDigest Length
* @param	:(unsigned char *)unauthmsg : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.3.2  - initech more info)
* @param	:(int) unauthmsg_len        : length of unauthmsg
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len				: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/

INISAFECORE_API int ICL_PK7_Add_Signed_Data_HSM_With_Unauth_Attr(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version,int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char* sign, int signLen, unsigned char *unauthmsg, int unauthmsg_len, unsigned char **out, int *out_len);


/**
 * @brief	: PKCS#7 generate signed-data - replay attack
 * @param	:(unsigned char *) msg			: plain message for sign
 * @param	:(int) msg_len				: length of msg
 * @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
 * @param	:(int) version				: ICL_PK7_VER_14 | ICL_PK7_VER_15
 * @param	:(int) ins_cert				: 0 - no add, 1 - add cert.
 * @param	:(int) ins_contentinfo		: 0 - no add, 1 - add contentinfo.
 * @param	:(int) ins_random			: 0 - no add, 1 - add random.
 * @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(int) remove_timestamp		: ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
 * @param	:(unsigned char *)unauthmsg : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.3.2  - initech more info)
 * @param	:(int) unauthmsg_len        : length of unauthmsg
 * @param	:(unsigned char *)replay_attack_check_data : add Unauthenticated Attribute ( 1.3.6.1.4.1.7150.4.2  - replay_attack_check_data)
 * @param	:(int) replay_attack_check_data_len        : length of replayattackdata
 * @param	:(unsigned char **) out		: signed_data (return)
 * @param	:(int *) out_len				: length of signed_data (return)
 * @return	:(int) success=0, error=error code
 */

INISAFECORE_API int ICL_PK7_Make_Signed_Data_With_Unauth_Attr_ReplayAttack(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int ins_cert, int ins_contentinfo, int ins_random, int out_type, int remove_timestamp, unsigned char *unauthmsg, int unauthmsg_len, unsigned char *replay_attack_check_data, int replay_attack_check_data_len, unsigned char **out, int *out_len);

/**
 * @brief	: PKCS#7 verify signed-data
 * @param	:(int) in_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) in			: signed_data
 * @param	:(int) in_len					: length of signed_data
 * @param	:(unsigned char **) out		: plain message (return)
 * @param	:(int *) out_len				: length of plain message (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Verify_Signed_Data(int in_type, unsigned char *in, int in_len, unsigned char **out, int *out_len);
INISAFECORE_API int ICL_PK7_Verify_Signed_Data_With_Add_Cert_Data(int in_type, unsigned char *in, int in_len, unsigned char *cert, int certlen, unsigned char *data, int datalen, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 verify signed-data : wothout plain.
*/

INISAFECORE_API int ICL_PK7_Verify_Signed_Data_WithOut_Plain(int in_type, unsigned char *in, int in_len);

/**
 * @brief	: get signer count from PKCS#7 signed-data
 * @param	:(int) data_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) p7_str		: signed_data string PKCS#7
 * @param	:(int) p7_len					: length of p7_str
 * @param	:(int *) count				: count of singer-info (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Get_Signer_Count(int data_type, unsigned char *p7_str, int p7_len, int *count);

/**
 * @brief	: get signer certificate from PKCS#7 signed-data
 * @param	:(int) data_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) p7_str		: signed_data string PKCS#7
 * @param	:(int) p7_len					: length of p7_str
 * @param	:(int) signer_index			: index of signer-info (from 0)
 * @param	:(int) out_type				: ICL_DER | ICL_PEM
 * @param	:(unsigned char **) out		: certificate string (return)
 * @param	:(int *) out_len				: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Get_Signer_Certs(int data_type, unsigned char *p7_str, int p7_len, int signer_index, int out_type, unsigned char **out, int *out_len);

/**
 * @brief	: get signer public key from PKCS#7 signed-data for reduced sign
 * @param	:(int) data_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) p7_str		: signed_data string PKCS#7
 * @param	:(int) p7_len					: length of p7_str
 * @param	:(int) signer_index			: index of signer-info (from 0)
 * @param	:(unsigned char **) out		: public key string (return)
 * @param	:(int *) out_len				: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Get_PubKey(int data_type, unsigned char *p7_str, int p7_len, int signer_index, unsigned char **out, int *out_len);

/**
 * @brief	: get signature from PKCS#7 signed-data for reduced sign
 * @param	:(int) data_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) p7_str		: signed_data string PKCS#7
 * @param	:(int) p7_len					: length of p7_str
 * @param	:(int) signer_index			: index of signer-info (from 0)
 * @param	:(unsigned char **) out		: signature(EncryptedDigest) string (return)
 * @param	:(int *) out_len				: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Get_EncDigest(int data_type, unsigned char *p7_str, int p7_len, int signer_index, unsigned char **out, int *out_len);

/**
 * @brief	: get sign-time from PKCS#7 signed-data
 * @param	:(int) data_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) p7_str		: signed_data string PKCS#7
 * @param	:(int) p7_len					: length of p7_str
 * @param	:(int) signer_index			: index of signer-info (from 0)
 * @param	:(int) out_type				: ICL_DER | ICL_PEM
 * @param	:(unsigned char **) out		: certificate string (return)
 * @param	:(int *) out_len				: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Get_Sign_Time(int data_type, unsigned char *p7_str, int p7_len, int signer_index, char *sign_time);

/**
 * @brief	: PKCS#7 generate enveloped-data
 * @param	:(unsigned char *) in			: plaintext to encrypt
 * @param	:(int) in_len					: length of plaintext
 * @param	:(PKI_STR_INFO *) rsa_keys		: set cert of receiver
 * @param	:(char *) sym_alg				: symmetric algorithm name
 * 			"SEED-ECB"	| "SEED-CBC"		| "SEED-CFB"		| "SEED-OFB"
 * 			"ARIA128-ECB"	| "ARIA128-CBC"	| "ARIA128-CFB"	| "ARIA128-OFB"
 * 			"DES-ECB" 	| "DES-CBC"		| "DES-CFB"		| "DES-OFB"
 * 			"DES_EDE-ECB"	| "DES_EDE-CBC"	| "DES_EDE-CFB"	| "DES_EDE-OFB"
 * 			"AES128-ECB"	| "AES128-CBC"	| "AES128-CFB"	| "AES128-OFB"
 * 			"AES192-ECB"	| "AES192-CBC"	| "AES192-CFB"	| "AES192-OFB"
 * 			"AES256-ECB"	| "AES256-CBC"	| "AES256-CFB"	| "AES256-OFB"
 * 			"RC5-ECB"		| "RC5-CBC"		| "RC5-CFB"		| "RC5-OFB"
 * @param	:(unsigned char *) sym_key		: symmetric key to encrypt	(if this value is NULL, generate random key)
 * @param	:(unsigned char *) sym_iv		: iv for symmetric algorithm (if this sym_key is NULL, set NULL)
 * @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char **) out		: enveloped_data (return)
 * @param	:(int *) out_len				: length of enveloped_data (return)
 * @param	:(int ) padding_type		: padding or encodding type (ICL_RSAES_PKCS1_15, ICL_RSAES_OAEP_20, ICL_RSAES_OAEP_21)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Make_Enveloped_Data(unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *sym_alg, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **out, int *out_len, int padding_type);
/**
 * @brief    : PKCS#7 generate enveloped-data (Suhyup Scraping)
 * @param    :(unsigned char *) in            : plaintext to encrypt
 * @param    :(int) in_len                    : length of plaintext
 * @param    :(PKI_STR_INFO *) rsa_keys        : set cert of receiver
 * @param    :(char *) sym_alg                : symmetric algorithm name
 *             "SEED-ECB"    | "SEED-CBC"        | "SEED-CFB"        | "SEED-OFB"
 *             "ARIA128-ECB"    | "ARIA128-CBC"    | "ARIA128-CFB"    | "ARIA128-OFB"
 *             "DES-ECB"     | "DES-CBC"        | "DES-CFB"        | "DES-OFB"
 *             "DES_EDE-ECB"    | "DES_EDE-CBC"    | "DES_EDE-CFB"    | "DES_EDE-OFB"
 *             "AES128-ECB"    | "AES128-CBC"    | "AES128-CFB"    | "AES128-OFB"
 *             "AES192-ECB"    | "AES192-CBC"    | "AES192-CFB"    | "AES192-OFB"
 *             "AES256-ECB"    | "AES256-CBC"    | "AES256-CFB"    | "AES256-OFB"
 *             "RC5-ECB"        | "RC5-CBC"        | "RC5-CFB"        | "RC5-OFB"
 * @param    :(unsigned char *) sym_key        : symmetric key to encrypt    (if this value is NULL, generate random key)
 * @param    :(unsigned char *) sym_iv        : iv for symmetric algorithm (if this sym_key is NULL, set NULL)
 * @param    :(int) out_type                : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param    :(unsigned char **) out        : enveloped_data (return)
 * @param    :(int *) out_len                : length of enveloped_data (return)
 * @param    :(int ) padding_type        : padding or encodding type (ICL_RSAES_PKCS1_15, ICL_RSAES_OAEP_20, ICL_RSAES_OAEP_21)

 * @return    :(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Make_Enveloped_Data_Scraping(unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *sym_alg, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **out, int *out_len, int padding_type);

/**
 * @brief	: PKCS#7 decrypt enveloped-data
 * @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) in			: plaintext to encrypt
 * @param	:(int) in_len					: length of plaintext
 * @param	:(unsigned char *) cert		: read cert-string from file. (PEM|DER)
 * @param	:(int) cert_len				: length of cert
 * @param	:(unsigned char *) priv		: read pkcs8_privkey-string from file. (PEM|DER)
 * @param	:(int) priv_len				: length of priv
 * @param	:(char *) priv_pwd			: private-key password
 * @param	:(unsigned char *) sym_key		: The key used to symmetric-algorithem (return)
 * @param	:(int *) sym_key_len			: length of sym_key (return)
 * @param	:(unsigned char *) sym_iv		: The iv used to symmetric-algorithem (return)
 * @param	:(int *) sym_iv_len			: length of sym_iv (return)
 * @param	:(unsigned char **) out		: plaintext (return)
 * @param	:(int *) out_len				: length of plaintext (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Verify_Enveloped_Data(int in_type, unsigned char *in, int in_len, unsigned char *cert, int cert_len, unsigned char *priv, int priv_len, char *priv_pwd, unsigned char *sym_key, int *sym_key_len, unsigned char *sym_iv, int *sym_iv_len, unsigned char **out, int *out_len);
INISAFECORE_API int ICL_PK7_Decrypt_Data(int in_type, unsigned char *in, int in_len, unsigned char *key, int key_len, unsigned char *iv, int iv_len, unsigned char **out, int *out_len);


/**
 * @brief	: PKCS#7 generate signed_and_enveloped data
 * @param	:(unsigned char *) in			: plaintext to encrypt
 * @param	:(int) in_len					: length of plaintext
 * @param	:(PKI_STR_INFO *) user_rsa		: cert of recipient
 * @param	:(PKI_STR_INFO *) signer_rsa	: cert, privkey, priv_passwd structure of signer
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
 * @param	:(char *) sym_alg				: symmetric algorithm name
 * 			"SEED-ECB"	| "SEED-CBC"		| "SEED-CFB"		| "SEED-OFB"
 * 			"ARIA128-ECB"	| "ARIA128-CBC"	| "ARIA128-CFB"	| "ARIA128-OFB"
 * 			"DES-ECB" 	| "DES-CBC"		| "DES-CFB"		| "DES-OFB"
 * 			"DES_EDE-ECB"	| "DES_EDE-CBC"	| "DES_EDE-CFB"	| "DES_EDE-OFB"
 * 			"AES128-ECB"	| "AES128-CBC"	| "AES128-CFB"	| "AES128-OFB"
 * 			"AES192-ECB"	| "AES192-CBC"	| "AES192-CFB"	| "AES192-OFB"
 * 			"AES256-ECB"	| "AES256-CBC"	| "AES256-CFB"	| "AES256-OFB"
 * 			"RC5-ECB"		| "RC5-CBC"		| "RC5-CFB"		| "RC5-OFB"
 * @param	:(unsigned char *) sym_key		: symmetric key to encrypt	(if this value is NULL, generate random key)
 * @param	:(unsigned char *) sym_iv		: iv for symmetric algorithm (if this sym_key is NULL, set NULL)
 * @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char **) out		: signed_and_enveloped_data (return)
 * @param	:(int *) out_len				: length of signed_and_enveloped_data (return)
 * @param	:(int ) padding_type		: padding or encodding type (ICL_RSAES_PKCS1_15, ICL_RSAES_OAEP_20, ICL_RSAES_OAEP_21)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Make_Signed_And_Enveloped_Data(unsigned char *in, int in_len, PKI_STR_INFO *user_rsa, PKI_STR_INFO *signer_rsa, char *hash_alg, struct tm *recv_time, char *sym_alg, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **out, int *out_len, int padding_type);

/**
 * @brief	: PKCS#7 decrypt signed_and_enveloped data
 * @param	:(int) in_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) in			: signed_and_enveloped data string
 * @param	:(int) in_len					: length of signed_and_enveloped data
 * @param	:(unsigned char *) cert		: read cert-string from file. (PEM|DER)
 * @param	:(int) cert_len				: length of cert
 * @param	:(unsigned char *) priv		: read pkcs8_privkey-string from file. (PEM|DER)
 * @param	:(int) priv_len				: length of priv
 * @param	:(char *) priv_pwd			: private-key password
 * @param	:(unsigned char *) sym_key		: The key used to symmetric-algorithem (return)
 * @param	:(int *) sym_key_len			: length of sym_key (return)
 * @param	:(unsigned char *) sym_iv		: The iv used to symmetric-algorithem (return)
 * @param	:(int *) sym_iv_len			: length of sym_iv (return)
 * @param	:(unsigned char **) out		: plaintext (return)
 * @param	:(int *) out_len				: length of plaintext (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Verify_Signed_And_Enveloped_Data(int in_type, unsigned char *in, int in_len, unsigned char *cert, int cert_len, unsigned char *priv, int priv_len, char *priv_pwd, unsigned char *sym_key, int *sym_key_len, unsigned char *sym_iv, int *sym_iv_len, unsigned char **out, int *out_len);
INISAFECORE_API int ICL_PK7_Make_Signed_And_Enveloped_Data_MOTP(unsigned char *in, int in_len, PKI_STR_INFO *user_rsa, PKI_STR_INFO *signer_rsa, char *hash_alg, struct tm *recv_time, char *sym_alg, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **out, int *out_len, int padding_type);


/**
 * brief		: check PKCS7 content format
 * @param	:(int) in_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) in			: PKCS7 format data string
 * @param	:(int) in_len					: length of PKCS7 format data string
 * @return	:(int) success=0(PKCS7 format), error=error code (NO PKCS7 foramt)
 */
INISAFECORE_API int ICL_PK7_Check_Format(int in_type, unsigned char *in, int in_len);

/**
 * brief        : generate ucpid(mydatasign) data format
 * @param    :(unsigned char*) ucpid_nonce      : ucpidNonce
 * @param    :(int) ucpid_nonce_len                   : length of ucpidNonce
 * @param    :(char*) user_agreement                : string of userAgreement
 * @param    :(int) real_name                              : 0 - false, 1 - true
 * @param    :(int) gender                                    : 0 - false, 1 - true
 * @param    :(int) national_info                           : 0 - false, 1 - true
 * @param    :(int) birth_date                               : 0 - false, 1 - true
 * @param    :(int) ci                                             : 0 - false, 1 - true
 * @param    :(char*) module_name                    : string of moduleName
 * @param    :(char*) module_vendor_name       : string of moduleVendorName
 * @param    :(int) major                                      : major version
 * @param    :(int) minor                                      : minor version
 * @param    :(int) build                                        : build version
 * @param    :(int) revision                                   : revision version
 * @param    :(char*) isp_url_info                        : string of ispUrlInfo
 * @param    :(unsigned char **) out                    : ucpid data format (return)
 * @param    :(int*) out_len                                 : ucpid data format length (return)
 * @return   :(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Generate_Ucpid_Request_Info_Data(unsigned char* ucpid_nonce, int ucpid_nonce_len, char* user_agreement,
                                                             int real_name, int gender, int national_info, int birth_date, int ci,
                                                             char* module_name, char* module_vendor_name,
                                                             int major, int minor, int build, int revision,
                                                             char* isp_url_info, unsigned char **out, int* out_len);

/**
 * brief		: Get PK7 Initech Random
 * @param	:(UTC_TIME *) signTime 			: sign time in pkcs7
 * @param	:(unsigned char *) enc_rand			: encrypted random value (initech format)
 * @param	:(int) enc_rand_len					: encrypted random value length
 * @param	:(unsigned char **) rand			: decrypted random value (return)
 * @param	:(int *) rand_len 					: decrypted random value length (return)
 * @return	:(int) success=0, error=error code
 */
int ICL_PK7_Decrypt_InitechRandom(UTC_TIME *signTime, unsigned char *enc_rand, int enc_rand_len, unsigned char **rand, int *rand_len);

/**
 * brief		: PKCS7 Verify Initech VID
 * @param	:(int) data_type : ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) p7_str			: PKCS7 format data string
 * @param	:(int) p7_len						: PKCS7 length
 * @param	:(unsigned char *) idnum			: idnum
 * @param	:(int) idnum_len					: idnum length
 * @return	:(int) success=0, error=error code
 */
int ICL_PK7_Verify_InitechVID(int data_type, unsigned char *p7_str, int p7_len, const char *idnum, int idnum_len );


/* cms.c */
/**
 * @brief	: CMS generate signed-data
 * @param	:(unsigned char *) msg			: plain message for sign
 * @param	:(int) msg_len				: length of msg
 * @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
 * @param	:(char) pad_mode		: padding or encodding type (ISC_RSASSA_PKCS1_v1_5_ENCODE | RSASSA_PSS_ENCODE)
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
 * @param	:(int) version				: ICL_CMS_VER_1 | ICL_CMS_VER_3
 * @param	:(int) out_type				: ICL_DER | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char **) out		: signed_data (return)
 * @param	:(int *) out_len			: length of signed_data (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_CMS_Make_Signed_Data(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char pad_mode, char *hash_alg, struct tm *recv_time, int version, int out_type, unsigned char **out, int *out_len);

/**
* @brief	: CMS generate signed-data
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char) pad_mode		: padding or encodding type (ISC_RSASSA_PKCS1_v1_5_ENCODE | RSASSA_PSS_ENCODE)
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) version				: ICL_CMS_VER_1 | ICL_CMS_VER_3
* @param	:(int) out_type				: ICL_DER | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(int) bAddAttr				: ICL_CMS_ADD_ATTR | ICL_CMS_NOT_ADD_ATTR
* @param	:(unsigned char **) out		: signed_data (return)
* @param	:(int *) out_len			: length of signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_CMS_Make_Signed_Data_With_AttrOption(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char pad_mode, char *hash_alg, struct tm *recv_time, int version, int out_type, int bAddAttr, unsigned char **out, int *out_len);

/**
 * @brief	: CMS add signed-data to original signed-data
 * @param	:(int) in_type				: ICL_DER | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) in			: oroginal signed_data
 * @param	:(int) in_len					: length of signed_data
 * @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
 * @param	:(char) pad_mode		: padding or encodding type (ISC_RSASSA_PKCS1_v1_5_ENCODE | RSASSA_PSS_ENCODE)
 * @param	:(char *) hash_alg			: hash algorithm name
 * 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
 * @param	:(int) version				: ICL_CMS_VER_1 | ICL_CMS_VER_3
 * @param	:(int) out_type				: ICL_DER | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char **) out		: signed_data (return)
 * @param	:(int *) out_len				: length of signed_data (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_CMS_Add_Signed_Data(int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char pad_mode, char *hash_alg, struct tm *recv_time, int version, int out_type, unsigned char **out, int *out_len);

/**
 * @brief	: CMS verify signed-data
 * @param	:(int) in_type				: ICL_DER | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) in			: signed_data
 * @param	:(int) in_len					: length of signed_data
 * @param	:(unsigned char **) out		: plain message (return)
 * @param	:(int *) out_len				: length of plain message (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_CMS_Verify_Signed_Data(int in_type, unsigned char *in, int in_len, unsigned char **out, int *out_len);

/**
 * @brief	: get signer count from CMS signed-data
 * @param	:(int) data_type				: ICL_DER | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) cms_str		: signed_data string CMS
 * @param	:(int) cms_len					: length of p7_str
 * @param	:(int *) count				: count of singer-info (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_CMS_Get_Signer_Count(int data_type, unsigned char *cms_str, int cms_len, int *count);

/**
 * @brief	: get signer certificate from CMS signed-data
 * @param	:(int) data_type				: ICL_DER | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) cms_str		: signed_data string CMS
 * @param	:(int) cms_len					: length of cms_str
 * @param	:(int) signer_index			: index of signer_info (from 0)
 * @param	:(int) out_type				: ICL_DER | ICL_PEM
 * @param	:(unsigned char **) out		: certificate string (return)
 * @param	:(int *) out_len				: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_CMS_Get_Signer_Certs(int data_type, unsigned char *cms_str, int cms_len, int signer_index, int out_type, unsigned char **out, int *out_len);

/**
 * @brief	: get sign-time from CMS signed-data
 * @param	:(int) data_type				: ICL_DER | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) cms_str		: signed_data string CMS
 * @param	:(int) cms_len					: length of cms_str
 * @param	:(int) signer_index			: index of signer-info (from 0)
 * @param	:(char *) sign_time		: sign-time string (return)
  * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_CMS_Get_Sign_Time(int data_type, unsigned char *cms_str, int cms_len, int signer_index, char *sign_time);

/**
 * @brief	: CMS generate enveloped-data
 * @param	:(unsigned char *) in			: plaintext to encrypt
 * @param	:(int) in_len					: length of plaintext
 * @param	:(int) data_oid					: in data 's type
 * 			ICL_OID_P7_DATA | ICL_OID_P7_SIGNED_DATA | ICL_OID_P7_ENVELOPEDDATA | ICL_OID_P7_ENCRYPTEDDATA
 * @param	:(PKI_STR_INFO *) rsa_keys		: set cert of receiver
 * @param	:(char *) sym_alg				: symmetric algorithm name
 * 			"SEED-ECB"	| "SEED-CBC"		| "SEED-CFB"		| "SEED-OFB"
 * 			"ARIA128-ECB"	| "ARIA128-CBC"	| "ARIA128-CFB"	| "ARIA128-OFB"
 * 			"DES-ECB" 	| "DES-CBC"		| "DES-CFB"		| "DES-OFB"
 * 			"DES_EDE-ECB"	| "DES_EDE-CBC"	| "DES_EDE-CFB"	| "DES_EDE-OFB"
 * 			"AES128-ECB"	| "AES128-CBC"	| "AES128-CFB"	| "AES128-OFB"
 * 			"AES192-ECB"	| "AES192-CBC"	| "AES192-CFB"	| "AES192-OFB"
 * 			"AES256-ECB"	| "AES256-CBC"	| "AES256-CFB"	| "AES256-OFB"
 * 			"RC5-ECB"		| "RC5-CBC"		| "RC5-CFB"		| "RC5-OFB"
 * @param	:(unsigned char *) sym_key		: symmetric key to encrypt	(if this value is NULL, generate random key)
 * @param	:(unsigned char *) sym_iv		: iv for symmetric algorithm (if this sym_key is NULL, set NULL)
 * @param	:(int) out_type				: ICL_DER | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char **) out		: enveloped_data (return)
 * @param	:(int *) out_len				: length of enveloped_data (return)
 * @param	:(int ) padding_type		: padding or encodding type (ICL_RSAES_PKCS1_15, ICL_RSAES_OAEP_20, ICL_RSAES_OAEP_21)
 * @param	:(char) hash_algo: hash algorithm. (SHA1 | SHA256 | SHA512 | HAS160)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_CMS_Make_Enveloped_Data(unsigned char *in, int in_len, int data_oid, PKI_STR_INFO *rsa_keys, char *sym_alg, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **out, int *out_len, int padding_type, char *hash_algo);
/**
 * @brief	: CMS decrypt enveloped-data
 * @param	:(int) out_type				: ICL_DER | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) in			: plaintext to encrypt
 * @param	:(int) in_len					: length of plaintext
 * @param	:(unsigned char *) cert		: read cert-string from file. (PEM|DER)
 * @param	:(int) cert_len				: length of cert
 * @param	:(unsigned char *) priv		: read pkcs8_privkey-string from file. (PEM|DER)
 * @param	:(int) priv_len				: length of priv
 * @param	:(char *) priv_pwd			: private-key password
 * @param	:(unsigned char *) sym_key		: The key used to symmetric-algorithem (return)
 * @param	:(int *) sym_key_len			: length of sym_key (return)
 * @param	:(unsigned char *) sym_iv		: The iv used to symmetric-algorithem (return)
 * @param	:(int *) sym_iv_len			: length of sym_iv (return)
 * @param	:(unsigned char **) out		: plaintext (return)
 * @param	:(int *) out_len				: length of plaintext (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_CMS_Verify_Enveloped_Data(int in_type, unsigned char *in, int in_len, unsigned char *cert, int cert_len, unsigned char *priv, int priv_len, char *priv_pwd, unsigned char *sym_key, int *sym_key_len, unsigned char *sym_iv, int *sym_iv_len, unsigned char **out, int *out_len);
/**
 * brief		: check CMS content format
 * @param	:(int) in_type				: ICL_DER | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
 * @param	:(unsigned char *) in			: CMS format data string
 * @param	:(int) in_len					: length of CMS format data string
 * @return	:(int) success=0(CMS format), error=error code (NO PKCS7 foramt)
 */
INISAFECORE_API int ICL_CMS_Check_Format(int in_type, unsigned char *in, int in_len);



/* pkcs8.c */
/**
 * @brief	: check password of encrypted private-key
 * @param	:(unsigned char *) pk8_str: read private-key string from file (PEM|DER)
 * @param	:(int) pk8_len: length of pk8_str
 * @param	:(char *)passwd: password of private-key
 * @param	:(char *) passwd	: private-key password
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK8_Check_Passwd(unsigned char *pk8_str, int pk8_len, char *passwd, int passwd_len);

/**
 * @brief	: get random from pkcs8 format private-key
 * @param	:(unsigned char *) pk8_str: read pkcs8_privkey-string from file. (PEM|DER)
 * @param	:(int) pk8_len	: length of pk8_str
 * @param	:(char *) passwd	: private-key password
 * @param	:(int) passwd_len	: length of password
 * @param	:(unsigned char **) out		: random (return)
 * @param	:(int *) out_len				: length of random (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK8_Get_Random(unsigned char *pk8_str, int pk8_len, char *passwd, int passwd_len, unsigned char **out, int *out_len);

/**
 * @brief	: change password of pkcs8 private-key
 * @param	:(unsigned char *) pk8_str: read pkcs8_privkey-string from file. (PEM|DER)
 * @param	:(int) pk8_len: length of pk8_str
 * @param	:(char *) old_passwd: original private-key password
 * @param	:(int) old_pwd_len	: length of old_passwd
 * @param	:(char *) new_passwd: new private-key password
 * @param	:(int) new_pwd_len	: length of new_passwd
 * @param	:(unsigned char **) out		: encrypted private-key of pkcs8(DER format) (return)
 * @param	:(int *) out_len				: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK8_Change_Passwd(unsigned char *pk8_str, int pk8_len, char *old_passwd, int old_pwd_len, char *new_passwd, int new_pwd_len, unsigned char **out, int *out_len);

/**
 * @brief	: make private-key of pkcs#8 format (DER)
 * @param	:(unsigned char *) pk1_priv: private-key string
 * @param	:(int) pk1_priv_len: length of pk1_priv
 * @param	:(int) oid: use one of these
 * 				ICL_PBE_MD5_DES_CBC | ICL_PBE_SHA1_3DES_CBC | ICL_PBE_SHA1_DES_CBC | ICL_PBE_SHA1_SEED_CBC
 * 				ICL_PBE_SHA1_ARIA_CBC | ICL_PBE_SHA256_ARIA_CBC | ICL_PBE_HAS160_ARIA_CBC
 * @param	:(char *) old_passwd: original private-key password
 * @param	:(char *) new_passwd: new private-key password
 * @param	:(unsigned char **) out		: encrypted private-key of pkcs8(DER format) (return)
 * @param	:(int *) out_len				: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK8_Make_PrivateKey(unsigned char *pk1_priv, int pk1_priv_len, int oid, unsigned char *rand, int rand_len, char *pwd, int pwd_len, unsigned char **out_pk8, int *out_len);

/**
 * @brief	: 암호화된 개인키를 전달받아서 암호화를 해제한 후 der 파일로 저장하는 함수
 * @param	:(unsigned char *) pk8_str: p8 형태의 암호화된 개인키 바이너리
 * @param	:(int) pk8_len: p8 형태의 암호화된 개인키 바이너리의 길이
 * @param	:(char *) passwd: 암호화된 개인키의 패스워드
 * @param	:(int) passwd_len: 암호화된 개인키의 패스워드 길이
 * @param	:(unsigned char **) out_der: 복호화된 개인키를 der 형식으로 리턴
 * @param	:(int *) out_der_len: 복호화된 개인키의 길이를 리턴
 */
INISAFECORE_API int ICL_PK8_Make_Non_Encrypt_PrivateKey(unsigned char *pk8_str, int pk8_len, char *passwd, int passwd_len, unsigned char **out_der, int *out_der_len);

/**
* @brief     : P8Key DER to P1Key PEM
* @param     : (unsigned char *) priv_str:[in] PKCS8 Private Key (DER)
* @param     : (int)                          priv_len:[in] hash length
* @param     : (char *)                 password:[in] privkey password
* @param     : (int)                          passwordLen:[in] prvkey password length
* @param     : (unsigned char **)seq :[out] PKCS1 prvkey binary (PEM) (return)
* @param     : (int *)                  seq_len      :[out] XPKCS8 prvkey binary length (return)
* @return    : (int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK8_DER_to_PK1_PEM(unsigned char *priv_str, int priv_len, char *password, int passwordLen, char **out, int *out_len);

/**
* @brief     : P8Key to P1Key
* @param     : (unsigned char *) p8 :[in] PKCS8 private key (DER/PEM)
* @param     : (int) p8_len :[in] PKCS8 private key length
* @param     : (char *) password:[in] privkey password
* @param     : (int) passwordLen:[in] prvkey password length
* @param     : (int) out_form:[in] out format (ICL_DER/ICL_PEM)
* @param     : (unsigned char **) out :[out] PKCS1 private key (return)
* @param     : (int *) out_len :[out] PKCS1 private key length (return)
* @return    : (int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK8_to_PK1(unsigned char *p8, int p8_len, char *password, int passwordLen, int out_form, unsigned char **out, int *out_len);
#ifdef _IPHONE
///**
// * @brief     : duplicate pkcs8_data with keyfactor
// * @param     : (unsigned char *) p8 :[in] PKCS8 private key (DER/PEM)
// * @param     : (int) p8_len :[in] PKCS8 private key length
// * @param     : (char*) oid_string
// * @param     : (char *) obj_Name: [in]object Name(ex: Hanabank, ShinhanBank)
// * @param     : (char *) keyFactorIDs: [in] keyFactor list("&" seperator)
// * @param     : (unsigned char **) out :[out] PKCS8 private key (return)
// * @param     : (int *) out_len :[out] PKCS8 private key length (return)
// * @return    : (int) success=0, error=error code
// */
//
//INISAFECORE_API int ICL_dup_PK8_with_KeyFactor(unsigned char *pk8_str, int pk8_len,  char* oid_string, char* obj_Name, char* keyFactorIDs, unsigned char **out, int *out_len);

/**
 * @brief     : duplicate pkcs8_data with keyfactor
 * @param     : (unsigned char *) p8 :[in] PKCS8 private key (DER/PEM)
 * @param     : (int) p8_len :[in] PKCS8 private key length
 * @param     : (int) oid type
 * @param     : (char *) obj_Name: [in]object Name(ex: Hanabank, ShinhanBank)
 * @param     : (char *) keyFactorIDs: [in] keyFactor list("&" seperator)
 * @param     : (unsigned char **) out :[out] PKCS8 private key (return)
 * @param     : (int *) out_len :[out] PKCS8 private key length (return)
 * @return    : (int) success=0, error=error code
 */
INISAFECORE_API int ICL_dup_PK8_with_KeyFactor(unsigned char *pk8_str, int pk8_len,  int oid_Type, char* obj_Name, char* keyFactorIDs, unsigned char **out, int *out_len);

/**
 * @brief     : get an extended-privatedKey(ecncryptedPKCS8) form extended-privateKey list
 * @param     : (unsigned char *) extPK8List_str :[in] PKCS8 privateKey list (seq type)
 * @param     : (int) p8_len :[in] length of PKCS8 privateKeylist binary
 * @param     : (char *) password: [in] password
 * @param     : (char *) oid string
 * @param     : (char *) obj_Name: [in]object Name(ex: Hanabank, ShinhanBank)(nullable)
 * @param     : (unsigned char **) out_PK8_str :[out] 'PKCS8 private key', not 'extended' type. (return)
 * @param     : (int *) out_PK8_len :[out] PKCS8 private key length (return)
 * @return    : (int) success=0, error=error code
 */
int ICL_get_extPK8_oidString(unsigned char *extPK8List_str, int extPK8List_len, char* password, int password_len, char* oid_string, char* obj_Name_str, unsigned char **out_PK8_str, int *out_PK8_len);
/**
 * @brief     : get an extended-privatedKey(ecncryptedPKCS8) form extended-privateKey list
 * @param     : (unsigned char *) extPK8List_str :[in] PKCS8 privateKey list (seq type)
 * @param     : (int) p8_len :[in] length of PKCS8 privateKeylist binary
 * @param     : (char *) password: [in] password
 * @param     : (int) oid type
 * @param     : (char *) obj_Name: [in]object Name(ex: Hanabank, ShinhanBank)(nullable)
 * @param     : (unsigned char **) out_PK8_str :[out] 'PKCS8 private key', not 'extended' type. (return)
 * @param     : (int *) out_PK8_len :[out] PKCS8 private key length (return)
 * @return    : (int) success=0, error=error code
 */
int ICL_get_extPK8(unsigned char *extPK8List_str, int extPK8List_len, char* password, int password_len, int oid_Type, char* obj_Name_str, unsigned char **out_PK8_str, int *out_PK8_len);

/**
 * @brief     : get oid form pkcs8_data
 * @param     : (unsigned char *) pk8_str :[in] PKCS8 private key (DER/PEM)
 * @param     : (int) p8_len :[in] PKCS8 private key length
 * @param     : (char **) out_str :[out] oid value (return)
 * @return    : (int) success=0, error=error code
 */
int ICL_PK8_Get_oid(unsigned char *pk8_str, int extPK8List_len, char **out_str);

/**
 * @brief     : get oid list from pkcs8_data list
 * @param     : (unsigned char *) pk8_list_str :[in] PKCS8 private key list (seq type)
 * @param     : (int) p8_len :[in] PKCS8-privatekey-seq length
 * @param     : (char **) out_oid_str :[out] oidList (return, "&" seperator)
 * @return    : (int) success=0, error=error code
 */
int ICL_extPK8List_Get_oidList(unsigned char *pk8_list_str, int extPK8List_len, char **out_oid_str);

/**
 * @brief     : count oid, same oid in extended-privatekey list
 * @param     : (unsigned char *) pk8_list_str :[in] PKCS8 private key list (seq type)
 * @param     : (int) p8_len :[in] PKCS8-privatekey-seq length
 * @param     : (char*) oid_str
 * @param     : (int*) out_count :[out] number of oid (return)
 * @return    : (int) success=0, error=error code
 */
int ICL_extPK8List_Get_oidCount(unsigned char *pk8_list_str, int extPK8List_len, int oid_type, int *out_count);



/**
 * @brief     : get objname from extended-privatekey list
 * @param     : (unsigned char *) pk8_list_str :[in] PKCS8 private key list (seq type)
 * @param     : (int) p8_len :[in] PKCS8-privatekey-seq length
 * @param     : (unsigned char **) outlist :[out]object Name(ex: Hanabank, ShinhanBank)
 * @param     : (int *) out_len :[out] PKCS8 private key length (return)
 * @return    : (int) success=0, error=error code
 */
int ICL_PK8_Get_objNameList(unsigned char *pk8_list_str, int pk8_len, char **outlist);


/**
 * @brief     : make pkcs8_data
 * @param     : (unsigned char *) p8 :[in] PKCS8 private key (DER/PEM)
 * @param     : (int) p8_len :[in] PKCS8 private key length
 * @param     : (char *) password:[in] privkey password
 * @param     : (int) passwordLen:[in] prvkey password length
 * @param     : (char *) password:[in] new privkey password
 * @param     : (int) passwordLen:[in] new privkey password length
 * @param     : (int) oid type
 * @param     : (char *) obj_Name: [in]object Name(ex: Hanabank, ShinhanBank)
 * @param     : (char *) keyFactorIDs: [in] keyFactor list("&" seperator)
 * @param     : (unsigned char **) out_exPK8 :[out] PKCS8 private key (return)
 * @param     : (int *) out_extPK8_len :[out] PKCS8 private key length (return)
 * @return    : (int) success=0, error=error code
 */
int ICL_make_extPK8(unsigned char *enc_pk8_str, int enc_pk8_len, char* password, int password_len, char* newPassword, int newPassword_len, int oid_Type, char* obj_Name, char* keyFactorIDs, unsigned char **out_exPK8, int *out_extPK8_len);


/**
 * @brief     : add pkcs8_data to pkcs8_data_list_sequence
 * @param     : (unsigned char *) extPK8_list_str :[in] extended PKCS8 private key list (sequence data)
 * @param     : (int) extPK8_list_len :[in]length of PKCS8 private key sequence list
 * @param     : (unsigned char *) add_extPK8_str :[in] extendedPKCS8 private key to add (DER/PEM)
 * @param     : (int) add_extPK8_len :[in] PKCS8 private key length to add
 * @param     : (unsigned char **) out :[out] PKCS8 private key (return)
 * @param     : (int *) out_len :[out] PKCS8 private key length (return)
 * @return    : (int) success=0, error=error code
     */
int ICL_add_extPK8List(unsigned char *extPK8_list_str, int extPK8_list_len, unsigned char *add_extPK8_str, int add_extPK8_len, unsigned char **out_extPK8_List_str, int *out_extPK8_List_len);

/**
 * @brief     : delete pkcs8_data from pkcs8_data_list_sequence
 * @param     : (unsigned char *) p8 :[in] PKCS8 private key (DER/PEM)
 * @param     : (int) p8_len :[in] PKCS8 private key length
 * @param     : (int) oid type (nullable)
 * @param     : (char *) obj_Name: [in]object Name(ex: Hanabank, ShinhanBank) (nullable)
 * @param     : (char *) keyFactorIDs: [in] keyFactor list("&" seperator) (nullable)
 * @param     : (unsigned char **) out :[out] sequence of PKCS8 private key list (return)
 * @param     : (int *) out_len :[out]  length of PKCS8 private key list sequence (return)
 * @return    : (int) success=0, error=error code
 */
int ICL_delete_extPK8List(unsigned char *extPK8_list_str, int extPK8_list__len, int oid_Type, char* obj_Name, unsigned char **out_extPK8_list_str, int *out_extPK8_list_len);

/**
 * @brief     : return oid_value of pkcs8_data
 * @param     : (unsigned char *) p8 :[in] PKCS8 private key (DER/PEM)
 * @param     : (char**) out :[out] oid_value
 * @return    : (int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK8_Get_oid(unsigned char *pk8_str, int pk8_len, char **out);


#endif
/*INISAFECORE_API int ICL_PK8_Get_Binary(unsigned char *p8, int p8_len, char *password, int passwordLen, char **out, int *out_len);*/

/* pkcs11.c */
/**
 * @brief	: get issuer_DN of signer in hsm.der file
 * @param	:(unsigned char *) drv_str		: read string from hsm.der file
 * @param	:(int) drv_len				: length of drv_str
 * @param	:(char **) issuer_dn			: issuer_DN string, same format with X509_INFO->issuerDN (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_HSM_Signer_IssuerDN(unsigned char *drv_str, int drv_len, char **issuer_dn);

/**
 * @brief	: get driver total count in hsm.der file
 * @param	:(unsigned char *) drv_str		: read string from hsm.der file
 * @param	:(int) drv_len				: length of drv_str
 * @param	:(int *) count				: total count of driver_info(use this value to malloc) (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_HSM_Driver_Count(unsigned char *drv_str, int drv_len, int *count);

/**
 * @brief	: verify sign of hsm.der and return driver_info structure
 * @param	:(unsigned char *) drv_str		: read string from hsm.der file
 * @param	:(int) drv_len				: length of drv_str
 * @param	:(unsigned char *) cert_str	: read string from Issuer certificate of hsm.der file
 * @param	:(int) cert_len				: length of cert_str
 * @param	:(DRIVER_INFO *) drv_info		: allocated structure to return driver_info (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Verify_HSM_Driver_Info(unsigned char *drv_str, int drv_len, unsigned char *cert_str, int cert_len, DRIVER_INFO *drv_info);

/**
 * @brief	: get driver_file_hash total count in vid&pid.der file
 * @param	:(unsigned char *) drv_str		: read string from vid&pid.der file
 * @param	:(int) drv_len				: length of drv_str
 * @param	:(int *) count				: total count of driver_file_hash(use this value to malloc) (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_HSM_Driver_Signature_Count(unsigned char *drv_str, int drv_len, int *count);

/**
 * @brief	: verify sign of vid&pid.der and return driver_file_hash structure
 * @param	:(unsigned char *) drv_str		: read string from vid&pid.der file
 * @param	:(int) drv_len				: length of drv_str
 * @param	:(unsigned char *) cert_str	: read string from Issuer certificate of hsm.der file
 * @param	:(int) cert_len				: length of cert_str
 * @param	:(DRIVER_SIGNATURE_INFO *) drv_info	: allocated structure to return driver_file_hash structure (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Verify_HSM_Driver_Signature_Info(unsigned char *drv_str, int drv_len, unsigned char *cert_str, int cert_len, DRIVER_SIGNATURE_INFO *drv_info);

/**
 * @brief	: load dynamic library (최초 한번만 호출해야함)
 * @param	:(char *) path		: absoulute path to library file
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Load_Library(char *path);

/**
 * @brief	: unload dynamic library (마지막 한번만 호출해야함)
 * @param	:(void)
 * @return	:(void)
 */
INISAFECORE_API void ICL_PK11_Unload_Library();

/**
 * @brief	: initialize HSM driver (최초 한번만 호출해야함)
 * @param	:(void)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Initialize();

/**
 * @brief	: finalize HSM driver (마지막 한번만 호출해야함)
 * @param	:(void)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Finalize();

/**
 * @brief	: get total slot number in HSM
 * @param	:(int *) count (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_Slot_Count(int *count);

/**
 * @brief	: get total slots in HSM
 * @param	:(CK_SLOT_ID_PTR*) slots (return)
 * @param	:(int *) count (return)
 * @return	:(int) success=0, error=error code
 */
//sykim 2023.06.14
//INISAFECORE_API int ICL_PK11_Get_Slots(CK_SLOT_ID_PTR* slots, int *count);

/**
 * @brief	: open session and login to HSM
 * @param	:(int ) slot		: slot number to connect
 * @param	:(char *)pin		: PIN	(if PIN is NULL, do not login)
 * @param	:(int) pin_len	: length of PIN
 * @param	:(CK_HANDLE *) hSession	: session handler (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Open_Session(int slot, char *pin, int pin_len, CK_HANDLE *hSession);

/**
 * @brief	: open session for HSM
 * @param	:(int ) slot		: slot number to connect
 * @param	:(CK_HANDLE *) hSession	: session handler (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Open_Session_Without_Login(int slot, CK_HANDLE *hSession);

/**
 * @brief	: get slot index and token info from label
 * @param	:(const unsigned char*) label	: token label to connect
 * @param	:(int) label_len				: length of token label
 * @param	:(CK_SLOT_ID*) slot				: slot (slot can be a NULL)
 * @param	:(CK_TOKEN_INFO*) info			: info (info can be a NULL)
 * @return	:(int) success=0, error=error cod
 */
//sykim 2023.06.14
//INISAFECORE_API int ICL_PK11_Find_SlotAndToken_By_Label(const unsigned char* label, int label_len, CK_SLOT_ID* slot, CK_TOKEN_INFO* info);

/**
 * @brief	: begin quorum authentication for HSM
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(CK_USER_TYPE) userType: the user type
 * @param	:(CK_ULONG_PTR) pulK: cards required to load logincal token
 * @param	:(CK_ULONG_PTR) pulN: number of cards in set
 * @return	:(int) success=0, error=error code
 */
//sykim 2023.06.14
//INISAFECORE_API int ICL_PK11_LoginBegin(CK_HANDLE hSession, CK_USER_TYPE userType, CK_ULONG_PTR pulK, CK_ULONG_PTR pulN);

/**
 * @brief	: continue quorum authentication for HSM
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(CK_USER_TYPE) userType: the user type
 * @param	:(CK_CHAR_PTR) pPin: the user's pin
 * @param	:(CK_ULONG) ulPinLen:  the length of the PIN
 * @param	:(CK_ULONG_PTR) pulSharesLeft: number of remaining shares
 * @return	:(int) success=0, error=error code
 */
//sykim 2023.06.14
//INISAFECORE_API int ICL_PK11_LoginNext(CK_HANDLE hSession, CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen, CK_ULONG_PTR pulSharesLeft);

/**
 * @brief	: end quorum authentication for HSM
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(CK_USER_TYPE) userType: the user type
 * @return	:(int) success=0, error=error code
 */
//sykim 2023.06.14
//INISAFECORE_API int ICL_PK11_LoginEnd(CK_HANDLE hSession, CK_USER_TYPE userType);

/**
 * @brief	: logout session to HSM
 * @param	:(CK_HANDLE *) hSession	: session handler (return)
 * @return	:(void)
 */
INISAFECORE_API void ICL_PK11_Logout(CK_HANDLE hSession);

/**
 * @brief	: close session to HSM
 * @param	:(CK_HANDLE *) hSession	: session handler (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Close_Session(CK_HANDLE *hSession);

/**
 * @brief	: symmetric encrypt with HSM
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(unsigned char *)key_name		: key_lable or key_id in HSM
 * @param	:(int) name_len		: length of key_name
 * @param	:(char) name_type		: type of key_name (ICL_KEYLABLE | ICL_KEYID)
 * @param	:(char *) alg			: symmectric algorithm name
 *			"BF-CBC"
 *			"DES-ECB" 		| "DES-CBC"
 *			"DES_2EDE-ECB"	| "DES_2EDE-CBC"
 *			"DES_3EDE-ECB"	| "DES_3EDE-CBC"
 *			"AES-ECB" 		| "AES-CBC"
 *			"SEED-ECB"		| "SEED-CBC"
 *			"ARIA-ECB"		| "ARIA-CBC"
 *			"RC5-ECB"			| "RC5-CBC"
 * @param	:(unsigned char *) iv: Initial vector (if ECB mode, input NULL)
 * @param	:(int) iv_len: length of Initial vector (if ECB mode, input 0)
 * @param	:(unsigned char *) in: plaintext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: ciphertext (return)
 * @param	:(int *) out_len: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Sym_Encrypt(CK_HANDLE hSession, unsigned char *key_name, int name_len, char name_type, char *alg, unsigned char *iv, int iv_len, unsigned char *in, int in_len, unsigned char **out, int *out_len);

/**
 * @brief	: symmetric decrypt with HSM
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(unsigned char *)key_name		: key_lable or key_id in HSM
 * @param	:(int) name_len		: length of key_name
 * @param	:(char) name_type		: type of key_name (ICL_KEYLABLE | ICL_KEYID)
 * @param	:(char *) alg			: symmectric algorithm name
 *			"BF-CBC"
 *			"DES-ECB" 		| "DES-CBC"
 *			"DES_2EDE-ECB"	| "DES_2EDE-CBC"
 *			"DES_3EDE-ECB"	| "DES_3EDE-CBC"
 *			"AES-ECB" 		| "AES-CBC"
 *			"SEED-ECB"		| "SEED-CBC"
 *			"ARIA-ECB"		| "ARIA-CBC"
 *			"RC5-ECB"			| "RC5-CBC"
 * @param	:(unsigned char *) iv: Initial vector (if ECB mode, input NULL)
 * @param	:(int) iv_len: length of Initial vector (if ECB mode, input 0)
 * @param	:(unsigned char *) in: ciphertext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: plaintext (return)
 * @param	:(int *) out_len: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Sym_Decrypt(CK_HANDLE hSession, unsigned char *key_name, int name_len, char name_type, char *alg, unsigned char *iv, int iv_len, unsigned char *in, int in_len, unsigned char **out, int *out_len);

/**
 * @brief	: RSA encrypt with HSM
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(unsigned char *)key_name		: key_lable or key_id in HSM
 * @param	:(int) name_len		: length of key_name
 * @param	:(char) name_type		: type of key_name (ICL_KEYLABLE | ICL_KEYID)
 * @param	:(char) key_type		: public-key or private-key type (ICL_PUBK | ICL_PRIV)
 * @param	:(char) pad_mode		: padding mode (ICL_RSAES_PKCS1_15 | ICL_RSAES_OAEP_20)
 * @param	:(unsigned char *) in: plaintext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: ciphertext (return)
 * @param	:(int *) out_len: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_RSA_Encrypt(CK_HANDLE hSession, unsigned char *key_name, int name_len, char name_type, char key_type, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len);

/**
 * @brief	: RSA decrypt with HSM
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(unsigned char *)key_name		: key_lable or key_id in HSM
 * @param	:(int) name_len		: length of key_name
 * @param	:(char) name_type		: type of key_name (ICL_KEYLABLE | ICL_KEYID)
 * @param	:(char) key_type		: public-key or private-key type (ICL_PUBK | ICL_PRIV)
 * @param	:(char) pad_mode		: padding mode (ICL_RSAES_PKCS1_15 | ICL_RSAES_OAEP_20)
 * @param	:(unsigned char *) in: ciphertext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: plaintext (return)
 * @param	:(int *) out_len: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_RSA_Decrypt(CK_HANDLE hSession, unsigned char *key_name, int name_len, char name_type, char key_type, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len);

/**
 * @brief	: make RSA sign with private-key in HSM
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(unsigned char *)key_name		: key_lable or key_id in HSM
 * @param	:(int) name_len		: length of key_name
 * @param	:(char) name_type		: type of key_name (ICL_KEYLABLE | ICL_KEYID)
 * @param	:(char *)hash_name		: hash algorithm name (if this value is NULL, make sign without hash)
 * 								  use only ( "MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" )
 * @param	:(char) pad_mode		: padding mode (ICL_RSASSA_PKCS1_15 | ICL_RSASSA_PSS)
 * @param	:(unsigned char *) in: plaintext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: signed-data (return)
 * @param	:(int *) out_len: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_RSA_Sign_ex(CK_HANDLE hSession, unsigned char *key_name, int name_len, char name_type, char *hash_name, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, int *hsm_errcode);





/**
 * @brief	: make RSA sign with private-key in HSM
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(unsigned char *)key_name		: key_lable or key_id in HSM
 * @param	:(int) name_len		: length of key_name
 * @param	:(char) name_type		: type of key_name (ICL_KEYLABLE | ICL_KEYID)
 * @param	:(char *)hash_name		: hash algorithm name (if this value is NULL, make sign without hash)
 * 								  use only ( "MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" )
 * @param	:(char) pad_mode		: padding mode (ICL_RSASSA_PKCS1_15 | ICL_RSASSA_PSS)
 * @param	:(unsigned char *) in: plaintext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char **) out: signed-data (return)
 * @param	:(int *) out_len: length of out (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_RSA_Sign(CK_HANDLE hSession, unsigned char *key_name, int name_len, char name_type, char *hash_name, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len);

/**
 * @brief	: verify RSA sign with public-key in HSM
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(unsigned char *)key_name		: key_lable or key_id in HSM
 * @param	:(int) name_len		: length of key_name
 * @param	:(char) name_type		: type of key_name (ICL_KEYLABLE | ICL_KEYID)
 * @param	:(char *)hash_name		: hash algorithm name (if this value is NULL, verify sign without hash)
 * 								  use only ( "MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" )
 * @param	:(char) pad_mode		: padding mode (ICL_RSASSA_PKCS1_15 | ICL_RSASSA_PSS)
 * @param	:(unsigned char *) in: plaintext
 * @param	:(int) in_len: length of in
 * @param	:(unsigned char *) out: signed-data
 * @param	:(int) out_len: length of out
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_RSA_Verify(CK_HANDLE hSession, unsigned char *key_name, int name_len, char name_type, char *hash_name, char pad_mode, unsigned char *msg, int msg_len, unsigned char *sign, int sign_len);

/**
 * @brief	: generate RSA key pair in HSM (exponent is 0x10001)
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(unsigned char *)pub_key_id	: public-key ID to save in HSM (same as key_lable)
 * @param	:(int) pub_key_id_len	: length of pub_key_id
 * @param	:(unsigned char *)pri_key_id	: private-key ID to save in HSM (same as key_lable)
 * @param	:(int) pri_key_id_len	: length of pri_key_id
 * @param	:(int) key_bit		: generate key bit length ex)512, 1024, 2048...
 * @param	:(unsigned char *) out_pubk: generated modulus value (return)
 * @param	:(int *) out_pubk_len	: length of out_pubk (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_RSA_Key_Generate(CK_HANDLE hSession, unsigned char *pub_key_id, int pub_key_id_len, unsigned char *pri_key_id, int pri_key_id_len, int key_bit, unsigned char *out_pubk, int *out_pubk_len);

/**
 * @brief	: generate ECDSA key pair in HSM
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(unsigned char *)pubkey_id	: public-key ID to save in HSM (same as key_lable)
 * @param	:(int) length_pubkey_id	: length of pub_key_id
 * @param	:(unsigned char *)prikey_id	: private-key ID to save in HSM (same as key_lable)
 * @param	:(int) length_prikey_id	: length of pri_key_id
 * @param	:(unsigned char *) ecpoint_x		: expoint x
 * @param	:(int) length_ecpoint_x	: length of ecpoint x
 * @param	:(unsigned char *) ecpoint_y		: expoint y
 * @param	:(int) length_ecpoint_y	: length of ecpoint y
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_ECDSA_Key_Generate(CK_HANDLE hSession, char* curve_name
					, unsigned char* pubkey_id, int length_pubkey_id
					, unsigned char* prikey_id, int length_prikey_id
					, unsigned char** ecpoint_x, int* length_ecpoint_x
					, unsigned char** ecpoint_y, int* length_ecpoint_y);

/**
 * @brief	: get ECDSA public key in HSM
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(unsigned char *)key_id	: key id to save in HSM (same as key_lable)
 * @param	:(int) id_len	: length of key ID
 * @param	:(unsigned char *)name_type	: ICL_KEYID or ICL_KEYLABLE
 * @param	:(unsigned char *) ecpoint_x		: expoint x
 * @param	:(int) length_ecpoint_x	: length of ecpoint x
 * @param	:(unsigned char *) ecpoint_y		: expoint y
 * @param	:(int*) length_ecpoint_y	: length of ecpoint y
 * @param	:(char **) curveName		: curve-name (secp224r1, secp256r1, sect233k1, sect283k1)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_ECDSAPublic_Key(CK_HANDLE hSession, unsigned char *key_id, int id_len, char name_type,
			unsigned char** ecpoint_x, int* length_ecpoint_x, unsigned char** ecpoint_y, int* length_ecpoint_y, char** curveName);



/**
 * @brief	: generate ECDSA-signature by hsm
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *)key_name	: key_name to save in HSM (same as key_lable)
 * @param	:(int) length_key_name		: length of key ID
 * @param	:(unsigned char)name_type	: ICL_KEYID or ICL_KEYLABLE
 * @param	:(unsigned char)hashName	: hash alg (SHA1, SHA256)
 * @param	:(unsigned char *) in		: in
 * @param	:(int*) length_in			: length of in
 * @param	:(unsigned char **) out		: signature
 * @param	:(int*) length_out			: length of signature
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_ECDSA_Sign(CK_HANDLE hSession, unsigned char *key_name, int length_key_name
								, char name_type, char* hashName
								, unsigned char *in, int length_in
								, unsigned char **out, int *length_out);


/**
 * @brief	: generate ECDSA-signature by hsm
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *)key_name	: key_name to save in HSM (same as key_lable)
 * @param	:(int) length_key_name		: length of key ID
 * @param	:(unsigned char)name_type	: ICL_KEYID or ICL_KEYLABLE
 * @param	:(unsigned char)hashName	: hash alg (SHA1, SHA256)
 * @param	:(unsigned char *) in		: in
 * @param	:(int*) length_in			: length of in
 * @param	:(unsigned char **) out		: signature
 * @param	:(int*) length_out			: length of signature
 * @param	: hsm_errcode				: hsm_errcode(HSM hardware)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_ECDSA_Sign_ex(CK_HANDLE hSession, unsigned char *key_name, int length_key_name
								, char name_type, char* hashName
								, unsigned char *in, int length_in
								, unsigned char **out, int *length_out, int *hsm_errcode);
/**
 * @brief	: verify ECDSA-signature by hsm
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *)key_name	: key_name to save in HSM (same as key_lable)
 * @param	:(int) length_key_name		: length of key ID
 * @param	:(unsigned char)name_type	: ICL_KEYID or ICL_KEYLABLE
 * @param	:(unsigned char)hashName	: hash alg (SHA1, SHA256)
 * @param	:(unsigned char *) msg		: plaintext
 * @param	:(int*) msg_len				: length of plaintext
 * @param	:(unsigned char **) sign	: signature
 * @param	:(int*) sign_len			: length of signature
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_ECDSA_Verify(CK_HANDLE hSession, unsigned char *key_name, int length_key_name
						, char name_type, char *hashName
						, unsigned char *msg, int msg_len
						, unsigned char *sign, int sign_len);


/**
 * @brief	: make asymmetrickey from ecdsa_publickeyInfo (ecpoint_x, ecpoint_y)
 * @param	:(unsigned char *) ecpoint_x		: expoint x
 * @param	:(int) length_ecpoint_x	: length of ecpoint x
 * @param	:(unsigned char *) ecpoint_y		: expoint y
 * @param	:(int) length_ecpoint_y				: length of ecpoint y
 * @param	:(char *)curve_name					: curve_name (secp224r1, secp256r1, sect233k1, sect283k1)
 * @param	:(unsigned char **) ASYMMETRIC_KEY	: ASymmetric Key

 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_ECDSA_RawPubkeyValue_to_ASYMMETRIC_KEY(unsigned char* ecpoint_x, int lenghth_ecpoint_x
												, unsigned char* ecpoint_y, int lenghth_ecpoint_y
												, char* curveName
												, ASYMMETRIC_KEY** aSymmkey);


/**
 * @brief	: delete ecdsaKeyInfo in hsm
 * @param	:(CK_HANDLE) hSession			: session
 * @param	:(unsigned char *) pkey_id		: private key
 * @param	:(int) pkey_id_len				: length of private key
 * @param	:(unsigned char *) pubk_id		: public key
 * @param	:(int) pubk_id_len				: length of public key
 * @param	:(unsigned char *) cert_id		: cert
 * @param	:(int) cert_id_len				: length of cert
 * @param	:(unsigned char *) vid_id		: vid
 * @param	:(int) vid_id_len				: length of vid
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Delete_ECDSAKeySets(CK_HANDLE hSession, unsigned char *pkey_id, int pkey_id_len,
                            unsigned char* pubk_id, int pubk_id_len,
                            unsigned char* cert_id, int cert_id_len,
                            unsigned char* vid_id, int vid_id_len );

/**
 * @brief	: make signature of X509_CERT
 * @param	:(CK_HANDLE) hSession			: session
 * @param	:(X509_CERT*) X509_CERT			: X509_CERT
 * @param	:(unsigned char *) pri_key_id	: pruvate key id
 * @param	:(int) pri_key_id_len			: length of private key
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_gen_SIG_X509_Cert_By_ECDSA(CK_HANDLE hSession, X509_CERT* cert, unsigned char* pri_key_id, int pri_key_id_len);

/**
 * @brief	: generate RSA key pair in HSM (exponent is 0x10001)
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(unsigned char *)pub_key_id	: public-key ID to save in HSM (same as key_lable)
 * @param	:(int) pub_key_id_len	: length of pub_key_id
 * @param	:(unsigned char *)pri_key_id	: private-key ID to save in HSM (same as key_lable)
 * @param	:(int) pri_key_id_len	: length of pri_key_id
 * @param	:(int) key_bit		: generate key bit length ex)512, 1024, 2048...
 * @param	:(unsigned char **) modulus: generated modulus value (return)
 * @param	:(int *) modulus_len	: length of modulus (return)
 * @param	:(unsigned char **) expo: well known exponent value (return)
 * @param	:(int *) expo_len		: length of exponent (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_RSA_Key_Generate_Ex(CK_HANDLE hSession, unsigned char *pub_key_id, int pub_key_id_len, unsigned char *pri_key_id, int pri_key_id_len, int key_bit, unsigned char **modulus, int *modulus_len, unsigned char** expo, int* expo_len);

/**
 * @brief	: put signature in X509_CERT with key in HSM
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(X509_CERT*) cert		: certificate to sign
 * @param	:(unsigned char *)pri_key_id	: private-key ID to save in HSM (same as key_lable)
 * @param	:(int) pri_key_id_len	: length of pri_key_id
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_gen_SIG_X509_Cert(CK_HANDLE hSession, X509_CERT* cert, unsigned char* pri_key_id, int pri_key_id_len);

/**
 * @brief	: get asymmetrickey-type and info(ECDSA-CUVE info)
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(unsigned char *)key_name 		: key-id
 * @param	:(int) length_key_name	: length of key-id
 * @param	:(char *)keyAlgo	: return asymmetric-key type
 * @param	:(char*) keyCurve	: return ECDSA-CUVE name
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_Public_Key_Algorithm(CK_HANDLE hSession, unsigned char *key_name, int length_key_name, char *keyAlgo, char *keyCurve );

/**
 * @brief	: set ASYMMECTRIC_KEY from raw modulus and exponent
 * @param	:(unsigned char **) mod	: generated modulus value
 * @param	:(int *) mod_len		: length of modulus
 * @param	:(unsigned char **) exp	: well known exponent value
 * @param	:(int *) exp_len		: length of exponent
 * @param	:(ASYMMECTIC_KEY *) akey: result ASYMMECTRIC_KEY (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_RawPubkeyValue_to_ASYMMETRIC_KEY(const unsigned char* mod, int mod_len, const unsigned char* exp, int exp_len, ASYMMETRIC_KEY* akey);

/**
 * @brief	: make hash value
 * @param	:(CK_HANDLE) hSession	: session handler
 * @param	:(char *)alg			: hash algorithm name (only "MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512")
 * @param	:(unsigned char *) in: data
 * @param	:(int) in_len: length of data
 * @param	:(unsigned char *) out: hash value. the buffer size must greater than 128 (return)
 * @param	:(int) out_len: length of out
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Hash(CK_HANDLE hSession, char *alg, unsigned char *in, int in_len, unsigned char *out, int *out_len);

/**
 * @brief	: insert certificate, public-key, private-key and random4VID to HSM (create four objects)
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *)key_id	: key id
 * @param	:(int) keyid_len			: length of key_id
 * @param	:(unsigned char *)cert_der	: certificate string of DER format. (if this value is NULL, skip set certificate)
 * @param	:(int)cert_len			    : length of cert_der
 * @param	:(unsigned char *)priv_der	: private-key string of DER format. (if this value is NULL, skip set private-key)
 * @param	:(int)priv_len			: length of priv_der
 * @param	:(char *)passwd			: password of private-key (if no password set NULL)
 * @param	:(int)passwd_len			: length of passwd	(if no password set 0)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Set_RSAKey(CK_HANDLE hSession, unsigned char *key_id, int id_len, unsigned char *cert_der, int cert_len, unsigned char *priv_der, int priv_len, char *passwd, int passwd_len);


/**
 * @brief	: insert certificate, public-key, private-key and random4VID to HSM (create four objects)
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *)cert_id	: cert id
 * @param	:(int) certid_len			: length of cert_id
 * @param	:(unsigned char *)pubk_id   : public key id
 * @param	:(int) pubkid_len           : length of pubkid_len
 * @param	:(unsigned char *)key_id	: key id
 * @param	:(int) keyid_len			: length of key_id
 * @param	:(unsigned char *)cert_der	: certificate string of DER format. (if this value is NULL, skip set certificate)
 * @param	:(int)cert_len			    : length of cert_der
 * @param	:(unsigned char *)modulus   : modulus of public key (if this value is NULL and pubk_id is not NULL, pubkey is extracted from certficate)
 * @param	:(int)modulus_len			: length of modulus
 * @param	:(unsigned char *)exponent  : exponent of public key (if this value is NULL and pubk_id is not NULL, pubkey is extracted from certficate)
 * @param	:(int)exponent_len			: length of exponent
 * @param	:(unsigned char *)priv_der	: private-key string of DER format. (if this value is NULL, skip set private-key)
 * @param	:(int)priv_len			: length of priv_der
 * @param	:(char *)passwd			: password of private-key (if no password set NULL)
 * @param	:(int)passwd_len			: length of passwd	(if no password set 0)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Set_RSAKey_Ext(CK_HANDLE hSession, unsigned char* cert_id, int certid_len, unsigned char* pubk_id, int pubkid_len, unsigned char *key_id, int keyid_len, unsigned char *cert_der, int cert_len, unsigned char* modulus, int modulus_len, unsigned char* exponent, int exponent_len, unsigned char *priv_der, int priv_len, char *passwd, int passwd_len, int key_usage);

/**
 * @brief	:get private key handle from HSM (create object)
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *)key_id	: key id
 * @param	:(int) id_len				: length of key_id
 * @param   :(CK_OBJECT_HANDLE *) hKey  : handle of private key (return)
 * @return	:() success=0, error=error code
 */
//sykim 2023.06.14
//INISAFECORE_API int ICL_PK11_Get_Private_Key(CK_HANDLE hSession, unsigned char *key_id, int id_len, CK_OBJECT_HANDLE* hKey);

/**
 * @brief	: get certificate from HSM (create object)
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *)key_id	: key id
 * @param	:(int) id_len				: length of key_id
 * @param	:(unsigned char **)cert_der	: certificate string with DER format (return)
 * @param	:(int *)cert_len			: length of cert_der (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_Cert(CK_HANDLE hSession, unsigned char *key_id, int id_len, unsigned char **cert_der, int *cert_len);

/**
 * @brief	: get public key from HSM (create object)
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *)key_id	: key id
 * @param	:(int) id_len				: length of key_id
 * @param	:(unsigned char **)pubkey 	: pubic key - just return modulus (return)
 * @param	:(int *)pubkey_len			: length of public key (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_Public_Key(CK_HANDLE hSession, unsigned char *key_id, int id_len, unsigned char **pubkey, int *pubkey_len);

/**
 * @brief	: get public key from HSM (create object)
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *)key_id	: key id
 * @param	:(int) id_len				: length of key_id
 * @param	:(unsigned char **)pubkey 	: pubic key - just return modulus (return)
 * @param	:(int *)pubkey_len			: length of public key (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_Public_Key_Ex(CK_HANDLE hSession, unsigned char *key_id, int id_len, unsigned char **modulus, int *modulus_len, unsigned char** expo, int* expo_len);

/**
 * @brief	:set certificate in HSM
 * @param	:(CK_HANDLE) hSession : session handler
 * @param	:(unsigned char *) key_id	: key id
 * @param	:(int) id_len				: length of key_id
 * @param	:(unsigned char *) cert_der : cert_der
 * @param	:(int) cert_len				: length of cert
 * @return	:(int) success=0, error=error code
 */
//sykim 2023.06.14
//INISAFECORE_API int ICL_PK11_Set_Cert(CK_HANDLE hSession, unsigned char *key_id, int id_len, unsigned char* cert_der, int cert_len, CK_OBJECT_HANDLE* phKey);

/**
 * @brief	:delete certificate in HSM
 * @param	:(CK_HANDLE) hSession : session handler
 * @param	:(unsigned char *) cert_id	: cert id
 * @param	:(int) cert_id_len          : length of cert_id
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Delete_Cert(CK_HANDLE hSession, unsigned char *cert_id, int cert_id_len);

/**
 * @brief	: delete certificate, public-key, private-key and random4VID in HSM (destroy three objects)
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *)key_id	: key id
 * @param	:(int) id_len				: length of key_id
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Delete_RSAKey(CK_HANDLE hSession, unsigned char *key_id, int id_len);

/**
 * @brief	: delete certificate, public-key, private-key and random4VID in HSM (destroy three objects)
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *)pkey_id	: pkey id
 * @param	:(int) pkey_id_len			: length of pkey_id
 * @param	:(unsigned char *)pubk_id	: pubk id
 * @param	:(int) pubk_id_len			: length of pubk_id
 * @param	:(unsigned char *)cert_id	: cert id
 * @param	:(int) cert_id_len			: length of cert_id
 * @param	:(unsigned char *)vid_id	: vid id
 * @param	:(int) vid_id_len			: length of vid_id
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Delete_RSAKeySets(CK_HANDLE hSession, unsigned char *pkey_id, int pkey_id_len, \
							unsigned char* pubk_id, int pubk_id_len, \
							unsigned char* cert_id, int cert_id_len, \
							unsigned char* vid_id, int vid_id_len );

/**
 * @brief	: get random for VID
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *)key_id	: key id
 * @param	:(int) id_len				: length of key_id
 * @param	:(unsigned char *)rand		: random for VID. buffer size must greater than 20. (return)
 * @param	:(int *) rand_len			: length of rand (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_Vid_Random(CK_HANDLE hSession, unsigned char *key_id, int id_len, unsigned char *rand, int *rand_len);

/**
 * @brief	: get serial from token_info
 * @param	:(int) slot				: slot number
 * @param	:(unsigned char *)serial	: serial (return)
 * @param	:(int) serial_len			: length of serial (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_Token_Serial(int slot, unsigned char *serial, int *serial_len);

/**
 * @brief	: get free memory from token_info
 * @param	:(int) slot				: slot number
 * @param	:(unsigned int *)free_public_memory	: free public memory (return)
 * @param	:(unsigned int *)free_private_memory	: free private memory (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_Token_FreeMemory(int slot, unsigned int *free_public_memory, unsigned int *free_private_memory);

/**
 * @brief	: set symmetric key to HSM
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *) key_id	: key id
 * @param	:(int) id_len				: length of key_id
 * @param	:(char *) alg				: symmectric algorithm name
 *			"BF-CBC"
 *			"DES-ECB" 		| "DES-CBC"
 *			"DES_2EDE-ECB"	| "DES_2EDE-CBC"
 *			"DES_3EDE-ECB"	| "DES_3EDE-CBC"
 *			"AES-ECB" 		| "AES-CBC"
 *			"SEED-ECB"		| "SEED-CBC"
 *			"ARIA-ECB"		| "ARIA-CBC"
 *			"RC5-ECB"			| "RC5-CBC"
 * @param	:(unsigned char *) key		: key value
 * @param	:(int) key_len			: length of key
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Set_Sym_Key(CK_HANDLE hSession, unsigned char *key_id, int id_len, char *alg, unsigned char *key, int key_len);

/**
 * @brief	: set symmetric key to HSM
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(unsigned char *) key_id	: key id
 * @param	:(int) id_len				: length of key_id
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Delete_Sym_Key(CK_HANDLE hSession, unsigned char *key_id, int id_len);

/**
 * @brief	: get count of all certificates in HSM
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(int *) count			: total number of certificate x.509 format (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_All_Certs_Count(CK_HANDLE hSession, int *count);

/**
 * @brief	: get all certificates in HSM
 * @param	:(CK_HANDLE) hSession		: session handler
 * @param	:(PKI_STR_INFO *) certs	: 이 함수를 호출 할 때 certs는 인증서 수 만큼 malloc된 구조체를 넘겨야 함. (return)
 * 									 - certs[].cert		: 인증서
 * 									 - certs[].cert_len	: 인증서의 길이
 * 									 - certs[].priv		: 인증서가 저장된 key_id
 * 									 - certs[].priv_len	: 인증서가 저장된 key_id의 길이
 * 									 - certs[].key_type	: 공개키의 알고리즘 (ICL_RSA | ICL_KCDSA)
 * 									 - certs[].key_type	: 인증서 용도  (ICL_SIGNCERT | ICL_KMCERT)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK11_Get_All_Certs(CK_HANDLE hSession, PKI_STR_INFO *certs);
INISAFECORE_API int ICL_PK11_GetHSMError(void);

/* pkcs12.c */
/**
 * @brief	: make PKCS#12 data include user key-pair (not support KM_KEY_PAIR, CA_CERT yet)
 * @param	:(char *) passwd				: password of private-key
 * @param	:(int) passwd_len				: length of password
 * @param	:(char *) name				: friendlyName (if NULL, not include to P12)
 * @param	:(int) name_len				: length of friendlyName
 * @param	:(int) user_keys_cnt			: number of key pairs imported in 'user_keys'
 * @param	:(PKI_STR_INFO *) user_keys		: cert, private-key structure of user (sign_cert & km_cert)
 * @param	:(int) ca_keys_cnt				: number of ceritificates imported in 'ca_keys'
 * @param	:(PKI_STR_INFO *) ca_keys		: cert string and length of CA
 * @param	:(unsigned char **) out_p12	: PCKS#12 data of DER format (return)
 * @param	:(int *) out_p12_len			: length of out_p12 (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK12_Make_PFX(char *passwd, int passwd_len, char *name, int name_len, int user_keys_cnt, PKI_STR_INFO *user_keys, int ca_keys_cnt, PKI_STR_INFO *ca_keys, unsigned char **out_p12, int *out_p12_len);

/**
* @brief	: make PKCS#12 data include user key-pair (not support KM_KEY_PAIR, CA_CERT yet)
* @param	:(char *) passwd				: password of private-key
* @param	:(int) passwd_len				: length of password
* @param	:(char *) p12_passwd			: password for decrypt pkcs#12_PFX (p12 pass)
* @param	:(int) p12_passwd_len			: length of password
* @param	:(char *) name					: friendlyName (if NULL, not include to P12)
* @param	:(int) name_len					: length of friendlyName
* @param	:(int) user_keys_cnt			: number of key pairs imported in 'user_keys'
* @param	:(PKI_STR_INFO *) user_keys		: cert, private-key structure of user (sign_cert & km_cert)
* @param	:(int) ca_keys_cnt				: number of ceritificates imported in 'ca_keys'
* @param	:(PKI_STR_INFO *) ca_keys		: cert string and length of CA
* @param	:(unsigned char **) out_p12	: PCKS#12 data of DER format (return)
* @param	:(int *) out_p12_len			: length of out_p12 (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK12_Make_PFX_With_Pass(char *passwd, int passwd_len, char *p12_passwd, int p12_passwd_len, char *name, int name_len, int user_keys_cnt, PKI_STR_INFO *user_keys, int ca_keys_cnt, PKI_STR_INFO *ca_keys, unsigned char **out_p12, int *out_p12_len);

/**
 * @brief	: make PKCS#12 data include user key-pair (not support KM_KEY_PAIR, CA_CERT yet)
 * @param	:(char *) passwd				: password of private-key
 * @param	:(int) passwd_len				: length of password
 * @param	:(char *) p12_passwd			: password for decrypt pkcs#12_PFX (p12 pass)
 * @param	:(int) p12_passwd_len			: length of password
 * @param	:(char *) name					: friendlyName (if NULL, not include to P12)
 * @param	:(int) name_len					: length of friendlyName
 * @param	:(int) user_keys_cnt			: number of key pairs imported in 'user_keys'
 * @param	:(PKI_STR_INFO *) user_keys		: cert, private-key structure of user (sign_cert & km_cert)
 * @param	:(int) ca_keys_cnt				: number of ceritificates imported in 'ca_keys'
 * @param	:(PKI_STR_INFO *) ca_keys		: cert string and length of CA
 * @param	:(unsigned char **) out_p12	: PCKS#12 data of DER format (return)
 * @param	:(int *) out_p12_len			: length of out_p12 (return)
 * @param	:(int) safeBagEncryptFlag		: safeBagEncrypt true/false
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK12_Make_PFX_With_SafeBagEncrypt(char *passwd, int passwd_len, char *name, int name_len, int user_keys_cnt, PKI_STR_INFO *user_keys, int ca_keys_cnt, PKI_STR_INFO *ca_keys, unsigned char **out_p12, int *out_p12_len, int safeBagEncryptFlag);
/**
 * @brief	: make PKCS#12 data include user key-pair (not support KM_KEY_PAIR, CA_CERT yet)
 * @param	:(char *) passwd				: password of private-key
 * @param	:(int) passwd_len				: length of password
 * @param	:(char *) p12_passwd			: password for decrypt pkcs#12_PFX (p12 pass)
 * @param	:(int) p12_passwd_len			: length of password
 * @param	:(char *) name					: friendlyName (if NULL, not include to P12)
 * @param	:(int) name_len					: length of friendlyName
 * @param	:(int) user_keys_cnt			: number of key pairs imported in 'user_keys'
 * @param	:(PKI_STR_INFO *) user_keys		: cert, private-key structure of user (sign_cert & km_cert)
 * @param	:(int) ca_keys_cnt				: number of ceritificates imported in 'ca_keys'
 * @param	:(PKI_STR_INFO *) ca_keys		: cert string and length of CA
 * @param	:(unsigned char **) out_p12	: PCKS#12 data of DER format (return)
 * @param	:(int *) out_p12_len			: length of out_p12 (return)
 * @param	:(int) safeBagEncryptFlag		: safeBagEncrypt true/false
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK12_Make_PFX_SafeBagEncrypt(char *passwd, int passwd_len, char *p12_passwd, int p12_passwd_len, char *name, int name_len, int user_keys_cnt, PKI_STR_INFO *user_keys, int ca_keys_cnt, PKI_STR_INFO *ca_keys, unsigned char **out_p12, int *out_p12_len, int safeBagEncryptFlag);


/**
 * @brief	: verify PKCS#12 and export user key-pair (not support KM_KEY_PAIR, CA_CERT yet)
 * @param	:(char *) passwd				: password for decrypt pkcs#12_PFX
 * @param	:(int) passwd_len				: length of password
 * @param	:(unsigned char *) p12_str		: PKCS#12 PFX data string (DER format)
 * @param	:(int) p12_str_len				: length of p12_str
 * @param	:(int *) user_keys_cnt			: number of key pairs imported in 'user_keys' (return)
 * @param	:(PKI_STR_INFO **) user_keys	: cert, private-key structure of user's sign_cert & km_cert. (return)
 * @param	:(int *) ca_keys_cnt			: number of ceritificates imported in 'ca_keys' (return)
 * @param	:(PKI_STR_INFO **) ca_keys		: cert string and length of CA (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK12_Verify_PFX(char *passwd, int passwd_len, unsigned char *p12_str, int p12_str_len, int *user_keys_cnt, PKI_STR_INFO **user_keys, int *ca_keys_cnt, PKI_STR_INFO **ca_key);

/**
* @brief	: verify PKCS#12 and export user key-pair (not support KM_KEY_PAIR, CA_CERT yet)
* @param	:(char *) passwd				: password for decrypt pkcs#12_PFX (priv)
* @param	:(int) passwd_len				: length of password
* @param	:(char *) p12_passwd			: password for decrypt pkcs#12_PFX (p12 pass)
* @param	:(int) p12_passwd_len			: length of password
* @param	:(unsigned char *) p12_str		: PKCS#12 PFX data string (DER format)
* @param	:(int) p12_str_len				: length of p12_str
* @param	:(int *) user_keys_cnt			: number of key pairs imported in 'user_keys' (return)
* @param	:(PKI_STR_INFO **) user_keys	: cert, private-key structure of user's sign_cert & km_cert. (return)
* @param	:(int *) ca_keys_cnt			: number of ceritificates imported in 'ca_keys' (return)
* @param	:(PKI_STR_INFO **) ca_keys		: cert string and length of CA (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK12_Verify_PFX_With_Pass(char *passwd, int passwd_len, char *p12_passwd, int p12_passwd_len, unsigned char *p12_str, int p12_str_len, int *user_keys_cnt, PKI_STR_INFO **user_keys, int *ca_certs_cnt, PKI_STR_INFO **ca_certs);


/* prng.c */

/* 2014.3.20 jhkim: PRNG 관련함수 사용제한을 위해 주석처리 */
#if 0
/**
 * @brief   : initialize RANDOM with time seed in Inicryto_v5
 * @return  :(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PRNG_T_Random_Init(void);

/**
 * @brief   : cleanup RANDOM with time seed in Inicryto_v5
 * @return  :(int) success=0, error=error code
 */
INISAFECORE_API void ICL_PRNG_T_Random_Clean(void);

/**
 * @brief   :get RANDOM in Inicryto_v5
 * @param   :(int) to_size: random size
 * @param   :(unsigned char *) out_rand: random value (return)
 * @return  :(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PRNG_Get_T_Random(int to_size, unsigned char *out_rand);

/**
 * @brief	: generate RANDOM with given seed
 * @param	:(unsigned char *) seed: the seed to generate random
 * @param	:(int) seed_len: length of seed
 * @param	:(unsigned char *) random: generated random (return)
 * @param	:(int) rand_len: length to generate random
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PRNG_Get_SeedRandom(unsigned char *seed, int seed_len, unsigned char *random, int rand_len);

/**
 * @brief	: Generate random with timeseed (RANDOM(SHA1(time)))
 * @param	: (int) to_size: random size
 * @param	: (unsigned char *) out_rand: random value (return)
 * @return	: (int) success=0, error=error code
 */
INISAFECORE_API int ICL_PRNG_Get_TimeRandom(int to_size, unsigned char *out_rand);
#endif

/**
 * @brief	: generate RANDOM with seed in Inicryto_v5
 * @param	:(unsigned char *) random: generated random (return)
 * @param	:(int) rand_len: length to generate random
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PRNG_Get_Random(unsigned char *random, int rand_len);
INISAFECORE_API int ICL_DRBG_Get_Random(unsigned char *random, int rand_len);

/**
 * @brief	: generate RANDOM with seed in Inicryto_v5
 * @param	:(unsigned char *) random: generated random (return)
 * @param	:(int) rand_len: length to generate random
 * @param	:(int) operation_mode: DRBG 운영 모드 (ISC_DRBG_HASH_MODE, ISC_DRBG_HMAC_MODE, ISC_DRBG_CTR_MODE)
 * @param	:(int) hash_id: 난수생성 시 사용할 해쉬 알고리즘
 * @param	:(int) prediction_resistance_flag: 예측내성 설정(예측내성 : ISC_DRBG_PREDICTION_RESISTANCE_MODE, 비예측내성 : ISC_DRBG_NON_PREDICTION_RESISTANCE_MODE)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_DRBG_Get_Random_ex(unsigned char *random, int rand_len, int operation_mode, int hash_id, int prediction_resistance_flag);

/* hash.c */
/**
 * @brief	: API for Message Digest
 * @param	:(unsigned char *) in_data: input message
 * @param	:(int) in_data_len: length to input message
 * @param	:(unsigned char **) hash_data: hash data
 * @param	:(int *) hash_len: length to hash data (return)
 * @param	:(char *) hash_alg: hash algorithm name	("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_HASH_Data(unsigned char *in_data, int in_data_len, unsigned char **hash_data, int *hash_len, char *hash_alg);

/**
 * @brief	: API for Message Digest FILE
 * @param	:(char *) file_path: file path.
 * @param	:(unsigned char **) hash_data: hash data
 * @param	:(int *) hash_len: length to hash data (return)
 * @param	:(char *) hash_alg: hash algorithm name	("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_HASH_FILE(char *file_path, unsigned char **hash_data, int *hash_len, char *hash_alg);

/**
 * @brief	: API for Message Digest Length
 * @param	:(char *) hash_alg	: hash algorithm name	("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @param	:(int *) hash_len		:[out] hash algorithm's length
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_HASH_Get_Length(char *hash_alg, int *hash_len);

/**
 * @brief	: API for Message Digest New
 * @return	:(void *) ctx	: content data point
 */
INISAFECORE_API void *ICL_HASH_New(void);

/**
 * @brief	: API for Message Digest init
 * @param	:(void *) ctx	: content data point
 * @param	:(char *) hash_alg	: hash algorithm name	("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_HASH_Init(void *ctx, char *hash_alg);

/**
 * @brief	: API for Message Digest update
 * @param	:(void *) ctx	: content data point
 * @param	:(unsigned char *) in_data: input message
 * @param	:(int) in_data_len: length to input message
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_HASH_Update(void *ctx, unsigned char *in_data, int in_data_len);

/**
 * @brief	: API for Message Digest final
 * @param	:(void *) ctx	: content data point
 * @param	:(unsigned char **) hash_data: hash data
 * @param	:(int *) hash_len: length to hash data (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_HASH_Final(void *ctx, unsigned char **hash_data, int *hash_len);

/**
 * @brief	: API for Message Digest final
 * @param	:(void *) ctx	: content data point
 * @return	:(void)
 */
INISAFECORE_API void ICL_HASH_Free(void *ctx);

/* mac.c */
/**
 * @brief	: API for Hash MAC
 * @param	:(int) algo_id: algoithm id
 * 				(ICL_HMAC_SHA1|ICL_HMAC_SHA224|ICL_HMAC_SHA256|ICL_HMAC_SHA384|ICL_HMAC_SHA512|ICL_HMAC_MD5|ICL_HMAC_HAS160|ICL_HMAC_MDC2)
 * @param	:(unsigned char *) input: input message
 * @param	:(int) inputlen: length to input message
 * @param	:(unsigned char *) key: the key value to make mac
 * @param	:(int) keylen: length of key
 * @param	:(unsigned char **) output: hash data (return)
 * @param	:(int *) outlen: length to hash data (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_MAC_HMAC(int algo_id, unsigned char *input, int inputlen, unsigned char *key, int keylen, unsigned char **output, int *outlen);

/* mac.c */
/**
 * @brief	: API for CCM, GCM
 * @param	:(char*) alg: algoithm id
 * 			 (LEA128-CCM, LEA192-CCM, LEA256-CCM, ARIA128-CCM, ARIA192-CCM, ARIA256-CCM, AES128-CCM, AES192-CCM, AES256-CCM, SEED-CCM
			  LEA128-GCM, LEA192-GCM, LEA256-GCM, ARIA128-GCM, ARIA192-GCM, ARIA256-GCM, AES128-GCM, AES192-GCM, AES256-GCM, SEED-GCM)
 * @param	:(unsigned char *) key: the key value to make mac
 * @param	:(unsigned char *) input: input message
 * @param	:(int) inlen: length to input message
 * @param	:(unsigned char *) key: the key value to make mac
 * @param	:(unsigned char *) nonce or iv
 * @param	:(int) length of nonce
 * @param	:(unsigned char *) associated data
 * @param	:(int) length of assciated data
 * @param	:(int) length of tag
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_MAC_BLOCKCIPHER(char* alg, unsigned char* key, unsigned char* input, int inlen, unsigned char* nonce, int nlen, unsigned char* adata, int alen, int tlen);

/* x509.c */
/**
 * @brief	: Convert X.509 Certificate Binary String to PEM Binary String
 * @param	:(unsigned char *) cert: certificate binary (PEM or DER)
 * @param	:(int) certlen: length of input certificate binary
 * @param	:(unsigned char **) PEMcert: output pem string	(return)
 * @param	:(int *) PEMlen: length of PEM string	(return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_X509_Conv_Cert2PEM(unsigned char *cert, int certlen, char **PEMcert, int *PEMlen);

/**
 * @brief	: Convert X.509 Certificate Binary String to DER Binary String
 * @param	:(unsigned char *) cert: certificate binary (PEM or DER)
 * @param	:(int) certlen: length of input certificate binary
 * @param	:(unsigned char **) PEMcert: output DER string (return)
 * @param	:(int *) PEMlen: length of DER string (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_X509_Conv_Cert2DER(unsigned char *cert, int certlen, unsigned char **DERcert, int *DERlen);

/**
 * @brief	: Convert X.509 Certificate Binary(PEM or DER) String to X509_INFO Structure
 * @param	:(unsigned char *) cert:[in] certificate binary (PEM or DER)
 * @param	:(int) certlen:[in] length of input certificate binary
 * @param	:(char) field_sep:[in] field separator (default '|')
 * @param	:(X509_INFO **) x509info:[out]  X509_INFO structure
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_X509_Init_X509_Info(unsigned char *cert, int certlen, char field_sep, X509_INFO **x509info);

/**
 * @brief	: Clear X509_INFO Structure's memory clear and free
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API void ICL_X509_Free_X509_Info(X509_INFO *x509info);


/**
 * @brief	: X509_INFO structure 를 받아 확장필드내의 crlDP 값 얻어오기 (0번째 crldp 값 얻어옴)
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @param	:(char **) crldp:[out] 리턴받을 CRL 배포지점.
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Info_Get_CRLdp(X509_INFO *x509info, char **crldp);

/**
 * @brief	: X509_INFO structure 를 받아 확장필드내의 crlDP 의 개수를 얻어온다
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @return	:(int) : CRLdp 의 개수
 */
INISAFECORE_API int ICL_X509_Info_Get_CRLdp_Count(X509_INFO *x509info);

/**
 * @brief	: X509_INFO structure 를 받아 확장필드내의 crlDP 값 얻어오기
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @param	:(char **) crldp:[out] 리턴받을 CRL 배포지점.
 * @param   :(int) index:[in] index 번째 CRLdp (0 번째 부터 시작)
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Info_Get_CRLdp_Index(X509_INFO *x509info, char **crldp, int index);

/**
 * @brief	: X509_INFO structure 를 받아 확장필드내의 crlDP 값 얻어오기
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @param	:(IPADDR **) ips:[out] IP주소들
 * @param	:(int *) ipsCnt: IP 주소 개수.
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Info_Get_LicenseIPs(X509_INFO *x509info, IPADDR **ips, int *ipsCnt);

/**
 * @brief	: X509_INFO structure 를 받아 IssuerDN 값 얻어오기.
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @param	:(char **) issuerDN:[out] issuerDN값(메모리 재할당 됨. free 필요함)
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Info_Get_IssuerDN(X509_INFO *x509info, char **issuerDN);

/**
 * @brief	: X509_INFO structure 를 받아 SubjectDN 값 얻어오기.
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @param	:(char **) subjectDN:[out] subjectDN값(메모리 재할당 됨. free 필요함)
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Info_Get_SubjectDN(X509_INFO *x509info, char **subjectDN);

/**
 * @brief	: DN string 을 받아서 원하는 필드값 얻어오기.
 * @param	:(char *) strDN:[in] DN string
 * @param	:(char *) shortname:[in] DN을 구성하는 값의 short name
 * @param	:(char **) value:[out] 리턴받을 value 값 (메모리 재할당 됨. free 필요함)
 * @return	:(int) ICL_OK(0): success, 그외 error code
 *           ICL_OK 인 경우라해도 해당 name의 field가 없는 경우 value 가 null 로 리턴될 수 있음.
 */
INISAFECORE_API int ICL_X509_Info_Get_DN_Field(char *strDN, char *shortname, char **value);

/**
 * @brief	: X509_INFO structure 를 받아 SubjectDN_DER 값 얻어오기.
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @param	:(char **) subjectDN_DER:[out] subjectDN_DER값(메모리 재할당 됨. free 필요함)
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Info_Get_SubjectDN_DER(X509_INFO *x509info, char **subjectDN_DER);

/**
 * @brief	: X509_INFO structure 를 받아 SubjectDN 값 얻어오기.
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @param	:(char **) serial:[out] serial값(메모리 재할당 됨. free 필요함)
 * @param	:(int) totype:[in] 시리얼의 리턴 형식 (ICL_DEC_STR | ICL_HEX_STR)
 *            ICL_DEC_STR : 시리얼의 10진수 문자열
 *            ICL_HEX_STR : 시리얼의 16진수 문자열
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Info_Get_Serial(X509_INFO *x509info, char **serial, int totype);

/**
 * @brief	: X509_INFO structure 를 받아 validityFrom 값 얻어오기.
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @param	:(char **) validityFrom:[out] validityFrom값(메모리 재할당 됨. free 필요함)
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Info_Get_ValidityFrom(X509_INFO *x509info, char **validityFrom);

/**
 * @brief	: X509_INFO structure 를 받아 validityTo 값 얻어오기.
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @param	:(char **) validityTo:[out] validityTo값(메모리 재할당 됨. free 필요함)
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Info_Get_ValidityTo(X509_INFO *x509info, char **validityTo);

/**
 * @brief	: X509_INFO structure 를 받아 pubkey 값 얻어오기.
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @param	:(unsigned char **) pubkey:[out] pubkey값(메모리 재할당 됨. free 필요함)
 * @param	:(int *) pubkeyLen:[out] pubkey값길이
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Info_Get_Pubkey(X509_INFO *x509info, unsigned char **pubkey, int *pubkeyLen);

/**
 * @brief	: X509_INFO structure 를 받아 pubkey 값 얻어오기.
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @param	:(unsigned char **) signature:[out] signature값(메모리 재할당 됨. free 필요함)
 * @param	:(int *) signatureLen:[out] signature값길이
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Info_Get_Signature(X509_INFO *x509info, char **signature, int *signatureLen);

/**
 * @brief	: X509_INFO structure 를 받아 공개키 알고리즘값 얻어오기.
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @param	:(char **) alg:[out] alg값(메모리 재할당 됨. free 필요함)
 * @param	:(int) algtype:[in] 알고리즘 리턴 형식 (ICL_ALGTYPE_OID | ICL_ALGTYPE_SN | ICL_ALGTYPE_LN)
 *            ICL_ALGTYPE_OID : 알고리즘의 OID 값 리턴
 *            ICL_ALGTYPE_SN : 알고리즘의 ShortName 값 리턴
 *            ICL_ALGTYPE_LN : 알고리즘의 LongName 값 리턴
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Info_Get_PubkeyAlg(X509_INFO *x509info, char **alg, int algtype);

/**
 * @brief	: X509_INFO structure 를 받아 서명 알고리즘 값 얻어오기.
 * @param	:(X509_INFO *) x509info:[in] X509_INFO structure point
 * @param	:(char **) alg:[out] alg값(메모리 재할당 됨. free 필요함)
 * @param	:(int) algtype:[in] 알고리즘 리턴 형식 (ICL_ALGTYPE_OID | ICL_ALGTYPE_SN | ICL_ALGTYPE_LN)
 *            ICL_ALGTYPE_OID : 알고리즘의 OID 값 리턴
 *            ICL_ALGTYPE_SN : 알고리즘의 ShortName 값 리턴
 *            ICL_ALGTYPE_LN : 알고리즘의 LongName 값 리턴
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Info_Get_SignatureAlg(X509_INFO *x509info, char **alg, int algtype);

/**
 * @brief	: 국내 KISA 공인인증서의 VID를 이용한 본인 확인 함수
 * @param	:(unsed char *) cert:[in] certificate binary (PEM or DER)
 * @param	:(int) certlen:[in] length of input certificate binary
 * @param	:(const unsigned char *) rand:[in] 개인키에 포함된 random 값
 * @param	:(int) rand_len				: length of rand
 * @param	:(const char *) idnum:[in] 주민등록번호 ('-' 없이)
 * @param	:(int) id_len				: length of idnum
 * @return	:(int) ICL_RET_VALID(0) : 본인확인 성공, ICL_RET_INVALID(-1): 본인확인 실패, 그외: error code
 */
INISAFECORE_API int ICL_X509_Check_VID(unsigned char *cert, int certlen, const unsigned char *rand, int rand_len, const char *idnum, int id_len);

/**
 * @brief	: 국내 KISA 공인인증서의 VID의 존재여부 확인
 * @param	:(unsed char *) cert_str	:[in] certificate binary (PEM or DER)
 * @param	:(int) cert_len			:[in] length of input certificate binary
 * @return	:(int) ICL_OK=VID존재함, 그 외=error code
 */
INISAFECORE_API int ICL_X509_Exist_VID(unsigned char *cert_str, int cert_len);


/**
 * @brief	: 인증서 유효성 검증 (유효기간, 서명, DN)
 * @param	:(unsed char *) cert:[in] certificate binary (PEM or DER)
 * @param	:(int) certlen:[in] length of input certificate binary
 * @param	:(unsed char *) cacert:[in] CA certificate binary (PEM or DER)
 * @param	:(int) cacertlen:[in] length of input CA certificate binary
 * @param	:(int) actflag:[in] 검증 대상 플래그 (ICL_X509_VERIFY_SIGNATURE | ICL_X509_VERIFY_VALIDITY | ICL_X509_VERIFY_DN)
 *            ICL_X509_VERIFY_SIGNATURE : 알고리즘의 OID 값 리턴
 *            ICL_X509_VERIFY_VALIDITY : 알고리즘의 ShortName 값 리턴
 *            ICL_X509_VERIFY_DN : 알고리즘의 LongName 값 리턴
 * @return	:(int) ICL_RET_VALID(0) : 유효한 인증서, 그외: error code
 *            ICL_RET_VALID                  : 유효한 인증서
 *            ICL_RET_VERIFY_CERT_NOT_BEFORE : 유효기간 시작 전.
 *            ICL_RET_VERIFY_CERT_NOT_AFTER  : 유효기간 만료
 *            ICL_RET_VERIFY_CERT_FAIL_SIG   : 서명 검증 실패
 *            ICL_RET_VERIFY_CERT_FAIL_DN    : DN 검증 실패
 */
INISAFECORE_API int ICL_X509_Verify(unsigned char *cert, int certlen, unsigned char *cacert, int cacertlen, int actflag);

/**
 * @brief	: 인증서 DN 검증 (CA 인증서의 subjectDN 과 subject 인증서의 issuerDN 값이 일치해야 함.)
 * @param	:(unsed char *) cert:[in] certificate binary (PEM or DER)
 * @param	:(int) certlen:[in] length of input certificate binary
 * @param	:(unsed char *) cacert:[in] CA certificate binary (PEM or DER)
 * @param	:(int) cacertlen:[in] length of input CA certificate binary
 * @return	:(int) ICL_RET_VALID(0) : 유효한 인증서, 그외: error code
 *            ICL_RET_VALID                  : 유효한 인증서
 *            ICL_RET_VERIFY_CERT_FAIL_DN    : DN 검증 실패
 */
INISAFECORE_API int ICL_X509_Verify_DN(unsigned char *cert, int certlen, unsigned char *cacert, int cacertlen);

/**
 * @brief	: 기관키 식별자 검증 ( 인증서의 기관키 식별자와 CRL의 기관키 식별자 일치 여부 )
 * @param	:(unsed char *) cert:[in] certificate binary (PEM or DER)
 * @param	:(int) certlen:[in] length of input certificate binary
 * @param	:(unsed char *) crl:[in] crl binary (PEM or DER)
 * @param	:(int) crllen:[in] length of input crl
* @return	: 0: 일치, -1: 불일치 1: 비교 불가
 */
INISAFECORE_API int ICL_X509_CompareWithCRL_AutorityKeyIndentifier( unsigned char* cert, int certlen, unsigned char* crl, int crllen );

/**
 * @brief	: 발급자 검증 ( 인증서의 발급자와 CRL의 발급자 일치 여부 )
 * @param	:(unsed char *) cert:[in] certificate binary (PEM or DER)
 * @param	:(int) certlen:[in] length of input certificate binary
 * @param	:(unsed char *) crl:[in] crl binary (PEM or DER)
 * @param	:(int) crllen:[in] length of input crl
* @return	: 0: 일치, -1: 불일치 1: 비교 불가
 */
INISAFECORE_API int ICL_X509_CompareWithCRL_Issuer( unsigned char* cert, int certlen, unsigned char* crl, int crllen );

/**
 * @brief	: DistributionPointName ( 인증서와 CRL 의 DistributionPointName 일치 여부 )
 * @param	:(unsed char *) cert:[in] certificate binary (PEM or DER)
 * @param	:(int) certlen:[in] length of input certificate binary
 * @param	:(unsed char *) crl:[in] crl binary (PEM or DER)
 * @param	:(int) crllen:[in] length of input crl
* @return	: 0: 일치, -1: 불일치 1: 비교 불가
 */
INISAFECORE_API int ICL_X509_CompareWithCRL_DistributionPointName( unsigned char* cert, int certlen, unsigned char* crl, int crllen );

/**
 * @brief	: 특정 인증서가 인자로 주어지는 keyusage 에 해당하는 권한을 가지고 있는지 확인 ( 포함하고 있는 지 확인 )
 * @param	:(unsed char *) cacert:[in] certificate binary (PEM or DER)
 * @param	:(int) cacertlen:[in] length of input certificate binary
 * @param	:(int) keyusage
* @return	: 0:해당 권한을 포함하고 있음, -1: 포함하지 않음 1: 확인 불가(keyusage 확장필드가 존재하지 않음)
 */
INISAFECORE_API int ICL_X509_Check_Have_KeyUsage( unsigned char* cacert, int cacertlen, int keyusage );
/**
 * @brief	: 인증서 서명 검증 (CA 인증서의 공개키로 subject 인증서의 서명 검증.)
 * @param	:(unsed char *) cert:[in] certificate binary (PEM or DER)
 * @param	:(int) certlen:[in] length of input certificate binary
 * @param	:(unsed char *) cacert:[in] CA certificate binary (PEM or DER)
 * @param	:(int) cacertlen:[in] length of input CA certificate binary
 * @return	:(int) ICL_RET_VALID(0) : 유효한 인증서, 그외: error code
 *            ICL_RET_VALID                  : 유효한 인증서
 *            ICL_RET_VERIFY_CERT_FAIL_DN    : DN 검증 실패
 */
INISAFECORE_API int ICL_X509_Verify_Signature(unsigned char *cert, int certlen, unsigned char *cacert, int cacertlen);
/**
 * @brief	: 인증서 유효기간 검증. (인증서 바이너리 또는 X509_INFO 구조체 둘중 하나만 입력값으로 주면 됨)
 * @param	:(unsed char *) cert:[in] certificate binary (PEM or DER)
 * @param	:(int) certlen:[in] length of input certificate binary
 * @param	:(X509_INFO *) x509info:[in] X509_INFO 구조체
 * @return	:(int) ICL_RET_VALID(0) : 유효한 인증서, 그외: error code
 *            ICL_RET_VERIFY_CERT_NOT_BEFORE : 유효기간 시작 전.
 *            ICL_RET_VERIFY_CERT_NOT_AFTER  : 유효기간 만료
 */
INISAFECORE_API int ICL_X509_Verify_Validity(unsigned char *cert, int certlen, X509_INFO *x509info, time_t *ltime);


/**
* @brief	: 인증서 갱신 기간 체크. (X509_INFO 구조체, 갱신 체크 기간 (초 단위))
* @param	:(X509_INFO *) x509info:[in] X509_INFO 구조체
* @param	: 갱신 기간 ( 초단위로 설정 )
* @return	:(int) ICL_RET_VALID(0) : 유효한 인증서
*			 ICL_RET_UPDATE(1)				: 인증서 갱신 기간
*            ICL_RET_VERIFY_CERT_NOT_BEFORE : 유효기간 시작 전.
*            ICL_RET_VERIFY_CERT_NOT_AFTER  : 유효기간 만료
*/
INISAFECORE_API int ICL_X509_Check_Update(X509_INFO *x509info, long seconds) ;

/**
 * @brief	: crl binary string 과 CA의 인증서 binary를 받아 CRL 서명 검증.
 * @param	:(unsed char *) crl:[in] CRL binary (DER)
 * @param	:(unsed char *) cacert:[in] CA CERT binary (DER or PEM)
 * @param	:(int) cacertlen:[in] length of input CERT binary
 * @return	:(int) ICL_RET_VALID: valid한 CRL, ICL_RET_INVALID: invalid 한 CRL, 그외: error code
 */
INISAFECORE_API int ICL_X509_CRL_Verify(unsigned char *crl, unsigned char *cacert, int cacertlen);

/**
 * @brief	: crl binary string 을 받아 현재 시간이 nextupdate 이전인지 체크 한다.
 * @param	:(unsed char *) crl:[in] CRL binary (DER)
 * @return	:(int) ICL_RET_VALID: 현재 시간이 NextUpdate 이전 , 현재 시간이 nextUpdate 이후다. 즉, 새로운 CRL이 배포됐다. 이걸로 체크 하면 안된다., 그외: error code
 */
INISAFECORE_API int ICL_X509_CRL_Verify_NextUpdate(unsigned char *crl);

/**
 * @brief	: crl binary string 과 인증서 binary 를 받아서 issuer 가 일치하는지 검증.
 * @param	:(unsed char *) crl:[in] CRL binary (DER)
 * @param	:(int) crllen:[in] CRL binary length
 * @param	:(unsed char *) cert:[in] CERT binary (DER or PEM)
 * @param	:(int) certlen:[in] length of input CERT binary
 * @return	:(int) ICL_RET_VALID: CRL issuer 와 Cert issuer 일치, ICL_RET_INVALID: 불일치 , 그외: error code
 */
INISAFECORE_API int ICL_X509_CRL_Verify_Issuer(unsigned char *crl, int crllen, unsigned char *cert, int certlen);

/**
 * @brief	: crl binary string 과 인증서 binary string 을 받아 cert 인증서가 폐기되었는지 검사.
 * @param	:(unsed char *) crl:[in] CRL binary (DER)
 * @param	:(int) crllen:[in] length of input CRL binary
 * @param	:(unsed char *) cert:[in] CERT binary (DER or PEM)
 * @param	:(int) certlen:[in] length of input CERT binary
 * @param	:(int *) is_revoked:[out] 폐기되었으면 목록의 위치값, 폐기되지 않았으면 0
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Is_Revoked(unsigned char *crl, unsigned char *cert, int certlen, int *is_revoked);


/**
 * @brief	: crl binary string 과 인증서 binary string 을 받아 cert 인좁?? * 폐기되었는지 체크하고 폐기되었다면 폐기일자와 이유를 반환한다.
 * @param	:(unsed char *) crl:[in] CRL binary (DER)
 * @param	:(int) crllen:[in] length of input CRL binary
 * @param	:(unsed char *) cert:[in] CERT binary (DER or PEM)
 * @param	:(int) certlen:[in] length of input CERT binary
 * @param	:(int *) is_revoked:[out] 폐기되었으면 목록의 위치값, 폐기되지 않았으면 0
 * @param	:(char *) revoked_date:[out] 폐기되었으면 폐기날짜를 반환.
 * @param	:(char *) revoked_reason:[out] 폐기되었으면 폐기이유를 반환.
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_X509_Is_Revoked_With_Reason(unsigned char *crl, unsigned char *cert, int certlen, int *is_revoked, char *revoked_date, char *revoked_reason);

/**
 * @brief	:Generalized Time 을 Local Time 으로 변환.(YYYYMMDDHHMISS)
 * @param	:(char *) generalized_time_str :[in] generalize time
 * @param	:(char *) local_time_str :[out] local time (generalized time * 7hour)
 * @return	:(int) ICL_OK(0): success, 그외 error code
 */
INISAFECORE_API int ICL_GenTime_To_LocalTime(char *generalized_time_str, char *local_time_str);

/* common.c */
/**
 * @brief	: check pem format
 * @param	:(char *) in: input parameter string (DER or PEM)
 * @return	:(int) PEM->0, not 0->not PEM
 */
INISAFECORE_API int ICL_COM_Is_Pem(char *in);

/**
 * @brief	: Encrypt password with SEED-CBC and fixed key.
 * @param	:(char *) pwd: password to encrypt
 * @param	:(int) pwd_len: length of password
 * @param	:(unsigned char **) out: encrypted password (return)
 * @param	:(int *) out_len: length of encrypted password (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_COM_Encrypt_Password(char *pwd, int pwd_len, unsigned char **out, int *out_len);

/**
 * @brief	: Decrypt password with SEED-CBC and fixed key.
 * @param	:(char *) in: encrypted password
 * @param	:(int) in_len: length of encrypted password
 * @param	:(unsigned char **) out: decrypted password (return)
 * @param	:(int *) out_len: length of decrypted password (return)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_COM_Decrypt_Password(unsigned char *in, int in_len, char **out, int *out_len);

/**
 * @brief	: Convert DER to PEM
 * @param	: (unsigned char *) in_der_str: der string
 * @param	: (int) in_len: der string length
 * @param	: (unsigned char **) out_pem: out pem string (return)
 * @param	: (int *) out_len: out pem string length (return)
 * @param	: (int) key_mode: cert or privkey (ICL_P1_PUBK | ICL_P1_PRIV | ICL_P8_PRIV | ICL_CERT)
 * @return	:(int) success=0, error=error code
 */
INISAFECORE_API int ICL_COM_DER_to_PEM(const unsigned char *in_der_str, int in_len, unsigned char **out_pem, int *out_len, int key_mode);

/**
 * @brief	: Convert PEM to DER
 * @param	: (unsigned char *) in_pem_str: pem string
 * @param	: (int) in_len: pem string length
 * @param	: (unsigned char **) out_der: out der string (return)
 * @param	: (int *) out_len: out pem string length (return)
 * @return	: (int) success=0, error=error code
 */
INISAFECORE_API int ICL_COM_PEM_to_DER(const unsigned char *in_pem_str, int in_len, unsigned char **out_der, int *out_len);

/**
 * @brief	: Initialize (inicrypto 초기화)
 * @param	: (void)
 * @return	: (int) success=0, error=error code
 */
INISAFECORE_API int ICL_Initialize(void);


/**
 * @brief	: Change non proven mode (비검증모드 상태로 inicrypto변경)
 * @param	: (void)
 * @return	: (void)
 */
INISAFECORE_API void ICL_COM_Change_Non_Proven(void);

/**
* @brief	: Get Status proven mode (검증모드 상태인지 체크하는 함수)
* @param	: (void)
* @return	: (int)
*/
INISAFECORE_API int ICL_Is_Proven_Mode(void);

/**
* @brief	: 알고리즘을 자가테스트를 하지 않게 설정함
* @param	: (void)
* @return	: (void)
*/
INISAFECORE_API void ICL_COM_ChangeTestMode(void);

/**
 * @brief	: 알고리즘 string 알고리즘 id로 변경 함.
 * @param	: (char*) alg : 알고리즘 이름(string)
 * @param	: (int*) alg_id : 변경 된 알고리즘 id
 * @return	: (int) success=0, error=error code
 */
INISAFECORE_API int ICL_COM_Convert_Hash_Name(char *alg, int *alg_id);

INISAFECORE_API int ICL_COM_Convert_Hash_id(int alg_id, char *alg);

/* otp.c */
/**
 * @brief	: Generate OTP message
 * @param	: (char *) otpPhase	: 공유된 세션키
 * @param	: (char *) otpSeed	: 생성된 랜덤 (ICL_PRNG_Get_Random()이용)
 * @param	: (char *) otpAlg		: 해시 알고리즘 ("MD4" | "MD5" | "SHA1")
 * @param	: (unsigned int) times	: OTP생성 갯수
 * @param	: (unsigned char **) msg: 생성된 OTP메시지 (return)
 * @return	: (int) success=0, error=error code
 */
INISAFECORE_API int ICL_OTP_Gen_Message(char *otpPhase, char *otpSeed, char *otpAlg, unsigned int times, unsigned char **msg);


INISAFECORE_API int ICL_COM_Check_Password(unsigned char* pem_str, int pem_str_len, char *passwd, int passwd_len);

INISAFECORE_API int ICL_COM_Get_Random(unsigned char* pem_str, int pem_str_len, char *passwd, int passwd_len, unsigned char **out, int *out_len);


/**
* @brief	: get private-key key type from priv_str. (RSA | KCDSA)
* @param	:(unsigned char *) priv_str: read pkcs8_privkey-string from file. (PKCS#1 or PKCS#8, PEM or DER)
* @param	:(int) priv_len: length of priv_str
* @param	:(char *) passwd: private-key password	(if not encrypted file, input NULL)
* @param	:(int) passwd_len: length of passwd		(if not encrypted file, input 0)
* @param	:(char) retKeyType: (RSA(1) | KCDSA(2))
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_COM_GetPrivateKeyType(unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, int *retKeyType);


INISAFECORE_API int ICL_COM_Change_Password(unsigned char* pem_str, int pem_str_len, char *old_passwd, int old_pwd_len, char *new_passwd, int new_pwd_len, unsigned char **out, int *out_len);

/**
 * @brief	: convert X509_SIGN_INFO Structure to binary
 * @param	: (char *) hash_alg			:[in] hash algorithm
 * @param	: (unsigned char *) hash_data	:[in] hash data
 * @param	: (int) hashdata_len			:[in] hash length
 * @param	: (unsigned char **) seq		:[out] X509_SIGN_INFO binary (DER) (return)
 * @param	: (int *) seq_len				:[out] X509_SIGN_INFO binary length (return)
 * @return	: (int) success=0, error=error code
 */
INISAFECORE_API int ICL_X509_SIGN_to_binary(char* hash_alg, unsigned char* hash_data, int hashdata_len, unsigned char **seq, int *seq_len);

/**
 * @brief	: convert binary to X509_SIGN_INFO Structure
 * @param	: (unsigned char *) seq:[in] X509_SIGN_INFO binary (DER)
 * @param	: (X509_SIGNED_INFO *) sign: X509_SIGN_INFO Structure (return)
 * @return	: (int) success=0, error=error code
 */
INISAFECORE_API int ICL_binary_to_X509_SIGN(unsigned char *seq, X509_SIGNED_INFO *sign);

/* 2010-04-13 OSK Add Function                                                                       */
/**
* @brief     : Remove Random Value to PKCS8 Private Key
* @param     : (unsigned char *) pk8_str:[in] PKCS8 Private Key (DER)
* @param     : (int)                          pk8_len:[in] hash length
* @param     : (char *)                 passwd:[in] privkey password
* @param     : (int)                          pwd_len:[in] prvkey password length
* @param     : (unsigned char **)seq :[out] PKCS8 prvkey binary (DER) (return)
* @param     : (int *)                  seq_len      :[out] XPKCS8 prvkey binary length (return)
* @return    : (int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK8_Remove_RData(unsigned char *pk8_str, int pk8_len, char *passwd, int pwd_len, unsigned char **out, int *out_len);

/**
* @brief     : RSAINFO to Cert
* @param     : (unsigned char *) cert_str:[in] Cert binary (DER)
* @param     : (int *) cert_len: Cert Length(return)
* @param     : (RSA_INFO **)rsa_info :[out] rsa_info struct (return)
* @return    : (int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK1_Cert_To_RSAINFO(unsigned char *cert_str, int cert_len, RSA_INFO **rsa_info);

/**
* @brief     : NTP Server Time init (호출 이후 core 모듈의 현재시간은 NTP 시간으로 적용됨)
* @param     : (char *) ntp_ip:[in] Time Server IP Address (NULL 입력시 default 사용)
* @param     : (int) ntp_port:[in] Time Server port (0 입력시 default 사용)
* @return    : (int) success=0, error=error code
*/
INISAFECORE_API int ICL_NTP_Init(char *ntp_ip, int ntp_port);

/**
* @brief     : NTP Server 초기화(Core 모듈에서 NTP Server 시간 적용 안됨)
* @return    : (void)
*/
INISAFECORE_API void ICL_NTP_Close();

/**
* @brief     : NTP Server 로 부터 현재 시간을 읽어 Local 시간 문자열로 리턴 (호출마다 서버 연결)
* @param     : (char *) ntp_ip:[in] Time Server IP Address (NULL 입력시 default 사용)
* @param     : (int) ntp_port:[in] Time Server port (0 입력시 default 사용)
* @param     : (char **) timestr:[out] NTP current Local time 문자열 (YYYYMMDDhhmmss 형식)
* @return    : (int) success=0, error=error code
*/
INISAFECORE_API int ICL_NTP_Get_Current_Local_Time(char* ip, int port, char **timestr);

/**
* @brief     : NTP Server 로 부터 현재 시간을 읽어 GM 시간 문자열로 리턴 (호출마다 서버 연결)
* @param     : (char *) ntp_ip:[in] Time Server IP Address (NULL 입력시 default 사용)
* @param     : (int) ntp_port:[in] Time Server port (0 입력시 default 사용)
* @param     : (char **) timestr:[out] NTP current GM time 문자열 (YYYYMMDDhhmmss 형식)
* @return    : (int) success=0, error=error code
*/
INISAFECORE_API int ICL_NTP_Get_Current_GM_Time(char* ip, int port, char **timestr);

/**
* @brief     : NTP Server 로 부터 현재 시간을 읽어 Local 시간 time_t 리턴 (호출마다 서버 연결)
* @param     : (char *) ntp_ip:[in] Time Server IP Address (NULL 입력시 default 사용)
* @param     : (int) ntp_port:[in] Time Server port (0 입력시 default 사용)
* @param     : (char **) timestr:[out] NTP current Local time 문자열 (YYYYMMDDhhmmss 형식)
* @return    : (int) success=0, error=error code
*/
INISAFECORE_API int ICL_NTP_Get_Current_Local_Time_t(char *ip, int port, time_t *timet);

/**
* @brief     : NTP Server 로 부터 현재 시간을 읽어 GM 시간 time_t 리턴 (호출마다 서버 연결)
* @param     : (char *) ntp_ip:[in] Time Server IP Address (NULL 입력시 default 사용)
* @param     : (int) ntp_port:[in] Time Server port (0 입력시 default 사용)
* @param     : (char **) timestr:[out] NTP current GM time 문자열 (YYYYMMDDhhmmss 형식)
* @return    : (int) success=0, error=error code
*/
INISAFECORE_API int ICL_NTP_Get_Current_GM_Time_t(char *ip, int port, time_t *timet);

/**
* @brief	: PKCS#7 generate signeddata's authenticatedattribute
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(struct tm *) recv_time		: received sign time (if this is NULL, generate system time)
* @param	:(int) remove_timestamp		: ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
* @param	:(unsigned char **) out		: authenticatedattribute encoding by DER type (return)
* @param	:(int *) out_len				: length of out (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Make_SignedData_Init(unsigned char *msg, int msg_len, char *hash_alg, struct tm *recv_time, int remove_timestamp, unsigned char **out, int *out_len);

/**
 * @brief	: PKCS#7 generate signeddata's authenticatedattribute
 * @param	: (unsigned char *) hash	:[in] hash data
 * @param	: (int) hashdata_len		:[in] hash length
 * @param	: (struct tm *) recv_time	:[in] received sign time (if this is NULL, generate system time)
 * @param	: (int) remove_timestamp		: ICL_PK7_REMOVE_TIMESTAMP | ICL_PK7_NOT_REMOVE_TIMESTAMP
 * @param	: (unsigned char **) out	:[out] authenticatedattribute encoding by DER type (return)
 * @param	: (int *) out_len			:[out] length of out (return)
 * @return	: (int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK7_Make_Authenticated_Attribute(unsigned char *hash, int hash_len, struct tm *recv_time, int remove_timestamp, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7 generate signed-data with signature and authenticated attribute
* @param	:(unsigned char *) msg			: plain message for sign
* @param	:(int) msg_len				: length of msg
* @param	:(PKI_STR_INFO *) rsa_keys		: cert, privkey, priv_passwd structure of signer
* @param	:(char *) hash_alg			: hash algorithm name
* 			("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(int) contatincert			: 0 = no add cert, 1 = add cert
* @param	:(unsigned char *) sign		: encryptedDigest
* @param	:(int) signLen				: encryptedDigest Length
* @param	:(unsigned char *) auth_attr : SignerInfo's authenticated attribute
* @param	:(int) auth_attr_len		 : auth_attr Length
* @param	:(unsigned char **) out		: pkcs7 signed_data (return)
* @param	:(int *) out_len				: length of pkcs7 signed_data (return)
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Make_Signed_Data_With_SignData(unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys,char *hash_alg, int version, int ins_cert, int ins_contentinfo,int out_type,unsigned char* sign, int signLen,unsigned char *auth_attr, int auth_attr_len, unsigned char **out, int *out_len);

/**
* @brief	: PKCS#7에서 contenttype을 제거한 후 인코딩 함.
* @param	:(int) in_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char *) in	: PKCS#7
* @param	:(int) in_len				: length of in
* @param	:(int) out_type				: ICL_DER | ICL_PEM | ICL_B64_ENCODE | ICL_B64_LF_ENCODE
* @param	:(unsigned char **) out	: PKCS#7 content 인코딩 데이타
* @param	:(int*) out_len				: length of out
* @return	:(int) success=0, error=error code
*/
INISAFECORE_API int ICL_PK7_Remove_ContentType(int in_type, unsigned char *in, int in_len, int out_type, unsigned char **out, int *out_len);

/**
* @brief	: 2개의 HEX값을 BIGINT로 바꿔서 비교
* @param	:(const char*) hex1 : 비교할 hex1
* @param	:(const char*) hex2 : 비교할 hex2
* @return	:(int) success=1,0,-1, error=-99
*/
INISAFECORE_API int ICL_COM_HEX2BIGINT_n_cmp(const char *hex1, const char *hex2);

/**
* @brief	: script의 param을 받아 webcontentscriptverfier 구조체 형식으로 변환.
* @param	:(const char*) script data
* @param	:(SCRIPT_VERIFY_CORE**) swebcontentscriptverfier 구조체
* @return	:(int) success=0
*/
INISAFECORE_API int ICL_COM_WebContentScriptInit(const char *scriptparam, SCRIPT_VERIFY_CORE **wcVerifier);


/**
* @brief	: webcontentscriptverfier 형식을 실제 검증한다.
* @param	:(const char*) base64_rsakey - base64된 공개키
* @param	:(unsigned char*) sign - 서명값
* @param	:(int) sign_len - 서명 길이
* @param	:(const char*) dest_data - 원문
* @param	:(int) dest_data_len - 원문 길이
* @return	:(int) success=0
*/
INISAFECORE_API int ICL_COM_WebContentScriptVerifier_RSA(const char* base64_rsakey, unsigned char* sign, int sign_len, const char* dest_data, int dest_data_len);

INISAFECORE_API int ICL_COM_convert_hash_id_to_name(int nSignAlg, char *HashName );

INISAFECORE_API int ICL_X509_str_to_utc_time(char *str, UTC_TIME **utctime, int time_form);
INISAFECORE_API int ICL_X509_conv_cert2x509(unsigned char *cert, int certlen, X509_CERT **x509);
INISAFECORE_API int ICL_PK1_priv_convert_keyunit(unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, ASYMMETRIC_KEY **out_key);
INISAFECORE_API int ICL_PK7_Get_CertDataAndMessageDigest(int in_type, unsigned char *p7Data, int p7Data_Len, unsigned char **outCert, int *outCert_len, unsigned char **md, int *md_len, unsigned char **subjectDN);
INISAFECORE_API int ICL_PK1_Get_Pub_KeyType(unsigned char *pubk_str, int pubk_len, int *keyType);
INISAFECORE_API int ICL_PK1_Get_Pri_KeyType(unsigned char *priv_str, int priv_len, int *keyType);

INISAFECORE_API int ICL_X509_str_to_generalize_time(char *str,  GENERALIZED_TIME **gentime, int time_form);
INISAFECORE_API int ICL_X509_str_to_X509_TIME(X509_TIME *x509time,  char *str_date, int time_form);

#ifndef _IPHONE
/**
 * @brief [ 파일의 최종수정된 날짜를 ASN.1으로 변환 ]
 * @param fileName [ 파일의 절대경로 ][IN]
 * @param timeZone [ "GMT" 형으로만 지원 ][IN]
 * @param outData [ 변환된 ASN.1 데이터 ][OUT]
 * @param outLen [ ASN.1 데이터 길이 ] [OUT]
 */
INISAFECORE_API int ICL_Generate_ModifiedDate_ASN1(unsigned char *fileName, unsigned char *timeZone, unsigned char **outData, unsigned int *outLen);

#endif
/**
 * @brief [ 파일의 이름을 ASN.1으로 변환 ]
 * @param inData [ 파일의 이름(파일명.확장자) ][IN]
 * @param inLen [ 파일이름의 길이 ][IN]
 * @param outData [ 변환된 ASN.1 데이터 ][OUT]
 * @param outLen [ ASN.1 데이터 길이 ] [OUT]
 */
INISAFECORE_API int ICL_Generate_FileName_ASN1(unsigned char* inData, unsigned int inLen, unsigned char** outData, unsigned int*outLen);

/**
 * @brief [ 파일의 크기를 ASN.1으로 변환 ]
 * @param fileName [ 파일의 절대경로 ][IN]
 * @param outData [ 변환된 ASN.1 데이터 ][OUT]
 * @param outLen [ ASN.1 데이터 길이 ] [OUT]
 */
INISAFECORE_API int ICL_Generate_FileSize_ASN1(unsigned char *fileName, unsigned char **outData, unsigned int *outLen);
INISAFECORE_API int ICL_get_kisaVid(unsigned char *cert, int certLen, unsigned char **kisaVid, int *kisaVidLen);

/**
 * @brief    : generate ECDSA Key pair string (format PKCS#1) (Not support function)
 * @param    :(int) curve_name: EC CURVE Name - secp224r1, secp256r1, sect233k1, sect283k1
 * @param    :(char) format: ICL_DER | ICL_PEM
 * @param    :(unsigned char **) pubk_str: generated ECDSA public-key string (return)
 * @param    :(int) pubk_len : length of pubk_str
 * @param    :(unsigned char **) prik_str: generated ECDSA private-key string (return)
 * @param    :(int) pubk_len : length of prik_str
 * @return    :(int) success=0, error=error code
 */
INISAFECORE_API int ICL_PK1_Generate_ECDSA_Key(char *curve_name, char out_type, unsigned char **pubk_str, int *pubk_len, unsigned char **prik_str, int *prik_len);

/**
 * @brief    : generate Connecting Information
 * @param    :(char *) rn : Resident Number
 * @param    :(unsigned char *) si : Secret Information
 * @param    :(int) si_len : length of si
 * @param    :(unsigned char *) sk : Secret Key
 * @param    :(int) sk_len : length of sk
 * @param    :(char **) out : Connecting Information (return)
 * @return    :(int) success=0, error=error code
 */
INISAFECORE_API int ICL_Generate_CI(char *rn, unsigned char *si, int si_len, unsigned char *sk, int sk_len, char **out);

/**
 * @brief    : generate Duplicated Joining Verification Information
 * @param    :(char *) rn : Resident Number
 * @param    :(char *) si : webSite Identification information
 * @param    :(unsigned char *) sk : Secret Key
 * @param    :(int) sk_len : length of sk
 * @param    :(char **) out : Duplicated Joining Verification Information (return)
 * @return    :(int) success=0, error=error code
 */
INISAFECORE_API int ICL_Generate_DI(char *rn, char *si, unsigned char *sk, int sk_len, char **out);
/*Kakao bank*/
INISAFECORE_API int ICL_PK7_Add_Random(int in_type, unsigned char *in, int in_len, unsigned char *oidString, int oidString_len, unsigned char*random,  int random_len, unsigned char **outPkcs7Data, int *outPkcs7DataLen);

#if defined(WIN32) || defined(WIN64) || defined(_WIN32_WCE)
#else
/**
 * @brief [ 현재 시간을 ASN1_TIME 형식으로 반환한다. ]
 */
INISAFECORE_API ASN1_TIME *ICL_COM_getCurrentLocalTime(void);

/**
 * @brief [ 현재 GMT 시간을 ASN1_TIME 형식으로 반환한다. ]
 */
INISAFECORE_API ASN1_TIME *ICL_COM_getCurrentGMTime(void);

/**
 * @brief [ PKCS#1서명 ]
 * @param akey [ 서명에 사용할 개인키 ]
 * @param pad_mode [ 패딩 모드 ]
 * @param hash_id [ 해쉬 알고리즘 ]
 * @param in [ 입력 ]
 * @param in_len [ 입력 길이 ]
 * @param out [ 서명 결과 값 ]
 * @param out_len [ 서명 결과 값 길이 ]
 */
INISAFECORE_API int ICL_PK1_signature_schemes(ASYMMETRIC_KEY *akey, char pad_mode, int hash_id, unsigned char *in, int in_len, unsigned char *out, int *out_len);

/**
 * @brief [ PKCS#1 서명 검증 ]
 * @param akey [ 서명에 사용할 개인키 ]
 * @param pad_mode [ 패딩 모드 ]
 * @param hash_id [ 해쉬 알고리즘 ]
 * @param msg [ 원본 메시지 ]
 * @param msg_len [ 원본 길이 ]
 * @param sign [ 서명 값 ]
 * @param sign_len [ 서명 값 길이 ]
 */
INISAFECORE_API int ICL_PK1_verify_schemes(ASYMMETRIC_KEY *akey, char pad_mode, int hash_id, unsigned char *msg, int msg_len, unsigned char *sign, int sign_len);

/**
 * @brief [ DER스트링을 P8_PRIV_KEY_INFO구조체로 변환 ]
 * @param pk8_str [ der 인코딩 된 P8 키 ]
 * @param pk8_len [ pk8_str 키 길이 ]
 * @param passwd [ 비밀번호 ]
 * @param passwd_len [ 비밀번호 길이 ]
 * @param out_p8 [ pkcs8 개인키 ]
 */
INISAFECORE_API int ICL_PK8_decode_pkcs8(unsigned char *pk8_str, int pk8_len, char *passwd, int passwd_len, P8_PRIV_KEY_INFO **out_p8);

/**
 * @brief [ DER스트링개인키를 ASYMMETRIC_KEY구조체로 변환 ]
 * @param pk8_len [ pk8_str 키 길이 ]
 * @param passwd [ 비밀번호 ]
 * @param passwd_len [ 비밀번호 길이 ]
 * @param out_key [ pkcs8 개인키 ]
 */
INISAFECORE_API int ICL_PK8_get_asym_key(unsigned char *pk8_str, int pk8_len, char *passwd, int passwd_len, ASYMMETRIC_KEY **out_key);

/**
 * @brief [ P7_CONTENT_INFO구조체를 DER스트링으로 변환 ]
 * @param p7 [ P7_CONTENT_INFO 구조체 ]
 * @param out_type [ ICL_DER or ICL_PEM ]
 * @param out
 * param out_len
 */
int ICL_PK7_encode_pkcs7(P7_CONTENT_INFO *p7, int out_type, unsigned char **out, int *out_len);

/**
 * @brief [ DER스트링을 P7_CONTENT_INFO구조체로 변환 ]
 * @param p7 [ P7_CONTENT_INFO 구조체 ]
 * @param out_type [ ICL_DER or ICL_PEM ]
 * @param out
 * param out_len
 */
int ICL_PK7_decode_pkcs7(int in_type, unsigned char *in, int in_len, P7_CONTENT_INFO **p7_out);

/**
 * @brief [ 문자열을 구분자로 나눌 때 요소의 갯수를 반환 ]
 * @param str [ 입력 문자열 ]
 * @param sep [ 구분자 ]
 * @return [ 요소의 갯수 ]
 */
int ICL_X509_get_field_cnt(char *str, char sep);

/**
 * @brief [ 문자열을 구분자로 나눌 때 지정한 순번에 해당하는 요소를 반환한다 ]
 * @param str [ 입력 문자열 ]
 * @param sep [ 구분자 ]
 * @param idx [ 순번 ]
 * @param out
 * @return [ 0:성공, n < 0:실패 ]
 */
int ICL_X509_parse_str_at(char *str, char sep, int idx, char **out);

int ICL_PK11_Check_Hsm(CK_HANDLE hSession);
#endif // defined(WIN32) || defined(WIN64) || defined(_WIN32_WCE)

#else
INI_RET_LOADLIB_CORE(int, ICL_SYM_Get_Block_Length, (char *alg), (alg), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SYM_Encrypt, (unsigned char *key, unsigned char *iv, char *alg, int pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode), (key,iv,alg,pad_mode,in,in_len,out,out_len,encode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SYM_Encrypt_F, (unsigned char *key, unsigned char *iv, char *alg, int pad_mode, unsigned char *in, int in_len, unsigned char *out, int *out_len), (key,iv,alg,pad_mode,in,in_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SYM_Decrypt, (unsigned char *key, unsigned char *iv, char *alg, int pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode), (key,iv,alg,pad_mode,in,in_len,out,out_len,encode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SYM_Decrypt_F, (unsigned char *key, unsigned char *iv, char *alg, int pad_mode, unsigned char *in, int in_len, unsigned char *out, int *out_len), (key,iv,alg,pad_mode,in,in_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(PKI_STR_INFO*, ICL_PK1_New_PKISTRINFO, (void), (), NULL);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Set_PKISTRINFO, (PKI_STR_INFO *pki_st, unsigned char *cert, int cert_len, unsigned char *priv, int priv_len, char *passwd), (pki_st,cert,cert_len,priv,priv_len,passwd), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_PK1_Free_PKISTRINFO, (PKI_STR_INFO *pki_st), (pki_st) );
INI_VOID_LOADLIB_CORE(void, ICL_PK1_Free_PKISTRINFOS, (PKI_STR_INFO *pki_st, int count), (pki_st,count) );
INI_RET_LOADLIB_CORE(int, ICL_PK1_Generate_RSA_Key, (int version, int len_bit, char out_type, unsigned char **pubk_str, int *pubk_len, unsigned char **prik_str, int *prik_len), (version,len_bit,out_type,pubk_str,pubk_len,prik_str,prik_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Cert_To_Publickey_Pemfile, (int version, int len_bit, char out_type, unsigned char **pubk_str, int *pubk_len, unsigned char **prik_str, int *prik_len), (version,len_bit,out_type,pubk_str,pubk_len,prik_str,prik_len,object_index), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Cert_To_Publickey_Pemfile, (unsigned char *cert_str, int cert_len, char **out, int *out_len), (cert_str,cert_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Cert_To_Privatekey_Pemfile, (unsigned char *cert_str, int cert_len, unsigned char *priv_str, int priv_len, unsigned char *password, int passwordLen, char **out, int *out_len), (cert_str,cert_len,priv_str,priv_len,password,passwordLen,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Privatekey_To_RSAINFO, (unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, RSA_INFO **rsa_info), (priv_str,priv_len,passwd,passwd_len,rsa_info), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Private_Encrypt, (unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode), (priv_str,priv_len,passwd,passwd_len,pad_mode,in,in_len,out,out_len,encode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Private_Encrypt_ex, (unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode, char *hash_algo), (priv_str,priv_len,passwd,passwd_len,pad_mode,in,in_len,out,out_len,encode,hash_algo), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Public_Decrypt, (unsigned char *pubk_str, int pubk_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode), (pubk_str,pubk_len,pad_mode,in,in_len,out,out_len,encode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Public_Decrypt_ex, (unsigned char *pubk_str, int pubk_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode, char *hash_algo), (pubk_str,pubk_len,pad_mode,in,in_len,out,out_len,encode,hash_algo), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Public_Decrypt_all, (unsigned char *pubk_str, int pubk_len, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode, char *outmode), (pubk_str,pubk_len,in,in_len,out,out_len,encode,outmode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Public_Encrypt, (unsigned char *pubk_str, int pubk_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode), (pubk_str,pubk_len,pad_mode,in,in_len,out,out_len,encode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Public_Encrypt_With_Param, (unsigned char *pubk_str, int pubk_len, char pad_mode, char *param_hashAlg, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode), (pubk_str,pubk_len,pad_mode,in,in_len,out,out_len,encode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Public_Encrypt_ex, (unsigned char *pubk_str, int pubk_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode, char *hash_algo), (pubk_str,pubk_len,pad_mode,in,in_len,out,out_len,encode,hash_algo), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Private_Decrypt, (unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode), (priv_str,priv_len,passwd,passwd_len,pad_mode,in,in_len,out,out_len,encode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Private_Decrypt_ex, (unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode, char *hash_algo), (priv_str,priv_len,passwd,passwd_len,pad_mode,in,in_len,out,out_len,encode,hash_algo), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Private_Decrypt_all, (unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode, char *outmode), (priv_str,priv_len,passwd,passwd_len,in,in_len,out,out_len,encode,outmode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Private_Sign, (unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, char pad_mode, char *hash_alg, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode), (priv_str,priv_len,passwd,passwd_len,pad_mode,hash_alg,in,in_len,out,out_len,encode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Public_Verify, (unsigned char *pubk_str, int pubk_len, char pad_mode, char *hash_alg, unsigned char *msg, int msg_len, unsigned char *sign, int sign_len, char encode), (pubk_str,pubk_len,pad_mode,hash_alg,msg,msg_len,sign,sign_len,encode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_PK8file_Hashvalue_Sign, (unsigned char *pk8_str, int pk8_len, char *passwd, int passwd_len, char pad_mode, char *hash_alg, unsigned char *in, int in_len, unsigned char **out, int *out_len, char encode), (pk8_str,pk8_len,passwd,passwd_len,pad_mode,hash_alg,in,in_len,out,out_len,encode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK5_Encrypt_PBES1_KISA, (const unsigned char *in_msg, int in_msg_len, unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, unsigned char *out, int *out_len, char *in_cipher_alg, char *in_hash_alg, int in_iv_opt), (in_msg,in_msg_len,in_passwd,in_passwd_len,in_salt,in_salt_len,in_iter,out,out_len,in_cipher_alg,in_hash_alg,in_iv_opt), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK5_Decrypt_PBES1_KISA, (const unsigned char *in_cipher, int in_cipher_len, unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, unsigned char *out, int *out_len, char *in_cipher_alg, char *in_hash_alg, int in_iv_opt ), (in_cipher,in_cipher_len,in_passwd,in_passwd_len,in_salt,in_salt_len,in_iter,out,out_len,in_cipher_alg,in_hash_alg,in_iv_opt), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK5_Encrypt_PBES1, (const unsigned char *in_msg, int in_msg_len, unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, unsigned char *out, int *out_len, char *in_cipher_alg, char *in_hash_alg), (in_msg,in_msg_len,in_passwd,in_passwd_len,in_salt,in_salt_len,in_iter,out,out_len,in_cipher_alg,in_hash_alg), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK5_Decrypt_PBES1, (const unsigned char *in_cipher, int in_cipher_len, unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, unsigned char *out, int *out_len, char *in_cipher_alg, char *in_hash_alg), (in_cipher,in_cipher_len,in_passwd,in_passwd_len,in_salt,in_salt_len,in_iter,out,out_len,in_cipher_alg,in_hash_alg), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK5_Encrypt_PBES2, (const unsigned char *in_msg, int in_msg_len, unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, unsigned char *out, int *out_len, unsigned char **out_iv, int *out_iv_len, char *in_cipher_alg, char *in_hash_alg), (in_msg,in_msg_len,in_passwd,in_passwd_len,in_salt,in_salt_len,in_iter,out,out_len,out_iv,out_iv_len,in_cipher_alg,in_hash_alg), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK5_Decrypt_PBES2, (const unsigned char *in_cipher, int in_cipher_len, unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, unsigned char *out, int *out_len, unsigned char *in_iv, char *in_cipher_alg, char *in_hash_alg), (in_cipher,in_cipher_len,in_passwd,in_passwd_len,in_salt,in_salt_len,in_iter,out,out_len,in_iv,in_cipher_alg,in_hash_alg), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK5_PBKDF1, (unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, char *in_hash_alg, int req_key_len, unsigned char *out_key), (in_passwd,in_passwd_len,in_salt,in_salt_len,in_iter,in_hash_alg,req_key_len,out_key), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK5_PBKDF2, (unsigned char *in_passwd, int in_passwd_len, unsigned char *in_salt, int in_salt_len, int in_iter, char *in_hash_alg, unsigned char *out_key, int in_key_len), (in_passwd,in_passwd_len,in_salt,in_salt_len,in_iter,in_hash_alg,out_key,in_key_len), -10000);
//INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Cert_Trust_List, (int version, unsigned long seq, X509_TIME *this_update, unsigned long valid_days, char *hash_alg, PKI_STR_INFO **trusted_certs, int trusted_certs_cnt, PKI_STR_INFO* sign_cert_key, unsigned char** out, int *out_len), (version, seq, this_update, valid_days, hash_alg, trusted_certs, trusted_certs_cnt, sign_cert_key, out, out_len), -10000);
//INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Cert_Trust_List2, (int version, unsigned long seq, X509_TIME *this_update, X509_TIME *next_update, char *hash_alg, PKI_STR_INFO **trusted_certs, int trusted_certs_cnt, PKI_STR_INFO* sign_cert_key, unsigned char** out, int *out_len, PF_SIGN_CB pf_sign_cb), (version, seq, this_update, next_update, hash_alg, trusted_certs, trusted_certs_cnt, sign_cert_key, out, out_len, pf_sign_cb), -10000);
//INI_RET_LOADLIB_CORE(int, ICL_PK7_Verify_Cert_Trust_List, (int version, unsigned char* ctl_der, int ctl_der_len, PKI_STR_INFO** signer_issuer_chain, int signer_issuer_cnt, PKI_STR_INFO* signer_cert, PKI_STR_INFO** target_issuer_chain, int target_issuer_cnt, PKI_STR_INFO* target_cert ), (version, ctl_der, ctl_der_len, signer_issuer_chain, signer_issuer_cnt, signer_cert, target_issuer_chain, target_issuer_cnt, target_cert ), -10000);
//INI_RET_LOADLIB_CORE(int, ICL_PK7_Verify_Cert_Trust_List2, (int version, unsigned char* ctl_der, int ctl_der_len, PKI_STR_INFO** signer_issuer_chain, int signer_issuer_cnt, PKI_STR_INFO* signer_cert, PKI_STR_INFO** target_issuer_chain, int target_issuer_cnt, PKI_STR_INFO* target_cert, PF_VERIFY_CB pf_verify_cb), (version, ctl_der, ctl_der_len, signer_issuer_chain, signer_issuer_cnt, signer_cert, target_issuer_chain, target_issuer_cnt, target_cert, pf_verify_cb ), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_Data, (unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int out_type, unsigned char **out, int *out_len), (msg,msg_len,rsa_keys,hash_alg,recv_time,version,out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_Data_With_Option, (unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int ins_cert, int ins_contentinfo, int out_type, unsigned char **out, int *out_len), (msg,msg_len,rsa_keys,hash_alg,recv_time,version,ins_cert,ins_contentinfo,out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_Data_With_Random, (unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char **out, int *out_len), (msg,msg_len,rsa_keys,hash_alg,recv_time,version,ins_cert,ins_contentinfo,ins_random,out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_Data_With_OutSign, (unsigned char *sign, int sign_len, unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int ins_cert, int ins_contentinfo, unsigned char *replay_attack_check_data, int replay_attack_check_data_len, int out_type, unsigned char **out, int *out_len), (sign,sign_len,msg,msg_len,rsa_keys,hash_alg,recv_time,ins_cert,ins_contentinfo,replay_attack_check_data, replay_attack_check_data_len, out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_Data_With_OutSign_ReplayAttack, (unsigned char *sign, int sign_len, unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int ins_cert, int ins_contentinfo, int out_type, unsigned char **out, int *out_len), (sign,sign_len,msg,msg_len,rsa_keys,hash_alg,recv_time,ins_cert,ins_contentinfo,out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_Data_HSM, (unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int out_type, unsigned char* sign, int signLen, unsigned char **out, int *out_len), (msg,msg_len,rsa_keys,hash_alg,recv_time,out_type,sign,signLen,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_Data_HSM_With_Option, (unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time,int version, int ins_cert, int ins_contentinfo,int out_type, unsigned char* sign, int signLen, unsigned char **out, int *out_len), (msg,msg_len,rsa_keys,hash_alg,recv_time,version,ins_cert,ins_contentinfo,out_type,sign,signLen,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_Data_HSM_With_Random, (unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time,int version, int ins_cert, int ins_contentinfo,int ins_random, int out_type, unsigned char* sign, int signLen, unsigned char **out, int *out_len), (msg,msg_len,rsa_keys,hash_alg,recv_time,version,ins_cert,ins_contentinfo,ins_random,out_type,sign,signLen,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_Data_Init_HSM, (unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys,char *hash_alg, struct tm *recv_time, int out_type,unsigned char **signinfo, int *signinfo_len, unsigned char **out, int *out_len), (msg,msg_len,rsa_keys,hash_alg,recv_time,out_type,signinfo,signinfo_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_Data_Init_HSM_With_Option, (unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time,int version, int ins_cert, int ins_contentinfo, int out_type,unsigned char **signinfo, int *signinfo_len, unsigned char **out, int *out_len), (msg,msg_len,rsa_keys,hash_alg,recv_time,version,ins_cert,ins_contentinfo,out_type,signinfo,signinfo_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_Data_Init_HSM_With_Random, (unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time,int version, int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char **signinfo, int *signinfo_len, unsigned char **out, int *out_len), (msg,msg_len,rsa_keys,hash_alg,recv_time,version,ins_cert,ins_contentinfo,ins_random,out_type,signinfo,signinfo_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_Data_Final_HSM, (int in_type, unsigned char *p7der, int p7der_len, unsigned char* sign, int signLen, int out_type, unsigned char **out, int *out_len), (in_type,p7der,p7der_len,sign,signLen,out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Add_Signed_Data, (int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version, int out_type, unsigned char **out, int *out_len), (in_type,in,in_len,rsa_keys,hash_alg,recv_time,version,out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Add_Signed_Data_With_Option, (int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version,int ins_cert, int ins_contentinfo, int out_type, unsigned char **out, int *out_len), (in_type,in,in_len,rsa_keys,hash_alg,recv_time,version,ins_cert,ins_contentinfo,out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Add_Signed_Data_With_Random, (int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version,int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char **out, int *out_len), (in_type,in,in_len,rsa_keys,hash_alg,recv_time,version,ins_cert,ins_contentinfo,ins_random,out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Add_Signed_Data_HSM, (int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int out_type, unsigned char* sign, int signLen, unsigned char **out, int *out_len), (in_type,in,in_len,rsa_keys,hash_alg,recv_time,out_type,sign,signLen,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Add_Signed_Data_HSM_With_Option, (int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version,int ins_cert, int ins_contentinfo, int out_type, unsigned char* sign, int signLen, unsigned char **out, int *out_len), (in_type,in,in_len,rsa_keys,hash_alg,recv_time,version,ins_cert,ins_contentinfo,out_type,sign,signLen,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Add_Signed_Data_HSM_With_Random, (int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *hash_alg, struct tm *recv_time, int version,int ins_cert, int ins_contentinfo, int ins_random, int out_type, unsigned char* sign, int signLen, unsigned char **out, int *out_len), (in_type,in,in_len,rsa_keys,hash_alg,recv_time,version,ins_cert,ins_contentinfo,ins_random,out_type,sign,signLen,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Verify_Signed_Data, (int in_type, unsigned char *in, int in_len, unsigned char **out, int *out_len), (in_type,in,in_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Verify_Signed_Data_With_Add_Cert_Data, (int in_type, unsigned char *in, int in_len, unsigned char *cert, int certlen, unsigned char *data, int datalen, unsigned char **out, int *out_len), (in_type,in,in_len,cert,certlen,data,datalen,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Get_Signer_Count, (int data_type, unsigned char *p7_str, int p7_len, int *count), (data_type,p7_str,p7_len,count), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Get_Signer_Certs, (int data_type, unsigned char *p7_str, int p7_len, int signer_index, int out_type, unsigned char **out, int *out_len), (data_type,p7_str,p7_len,signer_index,out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Get_PubKey, (int data_type, unsigned char *p7_str, int p7_len, int signer_index, unsigned char **out, int *out_len), (data_type,p7_str,p7_len,signer_index,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Get_EncDigest, (int data_type, unsigned char *p7_str, int p7_len, int signer_index, unsigned char **out, int *out_len), (data_type,p7_str,p7_len,signer_index,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Get_Sign_Time, (int data_type, unsigned char *p7_str, int p7_len, int signer_index, char *sign_time), (data_type,p7_str,p7_len,signer_index,sign_time), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Enveloped_Data, (unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char *sym_alg, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **out, int *out_len, int padding_type), (in,in_len,rsa_keys,sym_alg,sym_key,sym_iv,out_type,out,out_len,padding_type), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Verify_Enveloped_Data, (int in_type, unsigned char *in, int in_len, unsigned char *cert, int cert_len, unsigned char *priv, int priv_len, char *priv_pwd, unsigned char *sym_key, int *sym_key_len, unsigned char *sym_iv, int *sym_iv_len, unsigned char **out, int *out_len), (in_type,in,in_len,cert,cert_len,priv,priv_len,priv_pwd,sym_key,sym_key_len,sym_iv,sym_iv_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_And_Enveloped_Data, (unsigned char *in, int in_len, PKI_STR_INFO *user_rsa, PKI_STR_INFO *signer_rsa, char *hash_alg, struct tm *recv_time, char *sym_alg, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **out, int *out_len, int padding_type), (in,in_len,user_rsa,signer_rsa,hash_alg,recv_time,sym_alg,sym_key,sym_iv,out_type,out,out_len,padding_type), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Verify_Signed_And_Enveloped_Data, (int in_type, unsigned char *in, int in_len, unsigned char *cert, int cert_len, unsigned char *priv, int priv_len, char *priv_pwd, unsigned char *sym_key, int *sym_key_len, unsigned char *sym_iv, int *sym_iv_len, unsigned char **out, int *out_len), (in_type,in,in_len,cert,cert_len,priv,priv_len,priv_pwd,sym_key,sym_key_len,sym_iv,sym_iv_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Check_Format, (int in_type, unsigned char *in, int in_len), (in_type,in,in_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CMS_Make_Signed_Data, (unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys, char pad_mode, char *hash_alg, struct tm *recv_time, int version, int out_type, unsigned char **out, int *out_len), (msg,msg_len,rsa_keys,pad_mode,hash_alg,recv_time,version,out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CMS_Add_Signed_Data, (int in_type, unsigned char *in, int in_len, PKI_STR_INFO *rsa_keys, char pad_mode, char *hash_alg, struct tm *recv_time, int version, int out_type, unsigned char **out, int *out_len), (in_type,in,in_len,rsa_keys,pad_mode,hash_alg,recv_time,version,out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CMS_Verify_Signed_Data, (int in_type, unsigned char *in, int in_len, unsigned char **out, int *out_len), (in_type,in,in_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CMS_Get_Signer_Count, (int data_type, unsigned char *cms_str, int cms_len, int *count), (data_type,cms_str,cms_len,count), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CMS_Get_Signer_Certs, (int data_type, unsigned char *cms_str, int cms_len, int signer_index, int out_type, unsigned char **out, int *out_len), (data_type,cms_str,cms_len,signer_index,out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CMS_Get_Sign_Time, (int data_type, unsigned char *cms_str, int cms_len, int signer_index, char *sign_time), (data_type,cms_str,cms_len,signer_index,sign_time), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CMS_Make_Enveloped_Data, (unsigned char *in, int in_len, int data_oid, PKI_STR_INFO *rsa_keys, char *sym_alg, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **out, int *out_len, int padding_type, char *hash_algo), (in,in_len,data_oid,rsa_keys,sym_alg,sym_key,sym_iv,out_type,out,out_len,padding_type,hash_algo), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CMS_Verify_Enveloped_Data, (int in_type, unsigned char *in, int in_len, unsigned char *cert, int cert_len, unsigned char *priv, int priv_len, char *priv_pwd, unsigned char *sym_key, int *sym_key_len, unsigned char *sym_iv, int *sym_iv_len, unsigned char **out, int *out_len), (in_type,in,in_len,cert,cert_len,priv,priv_len,priv_pwd,sym_key,sym_key_len,sym_iv,sym_iv_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CMS_Check_Format, (int in_type, unsigned char *in, int in_len), (in_type,in,in_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK8_Check_Passwd, (unsigned char *pk8_str, int pk8_len, char *passwd, int passwd_len), (pk8_str,pk8_len,passwd,passwd_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK8_Get_Random, (unsigned char *pk8_str, int pk8_len, char *passwd, int passwd_len, unsigned char **out, int *out_len), (pk8_str,pk8_len,passwd,passwd_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK8_Change_Passwd, (unsigned char *pk8_str, int pk8_len, char *old_passwd, int old_pwd_len, char *new_passwd, int new_pwd_len, unsigned char **out, int *out_len), (pk8_str,pk8_len,old_passwd,old_pwd_len,new_passwd,new_pwd_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK8_Make_PrivateKey, (unsigned char *pk1_priv, int pk1_priv_len, int oid, unsigned char *rand, int rand_len, char *pwd, int pwd_len, unsigned char **out_pk8, int *out_len), (pk1_priv,pk1_priv_len,oid,rand,rand_len,pwd,pwd_len,out_pk8,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK8_DER_to_PK1_PEM, (unsigned char *priv_str, int priv_len, char *password, int passwordLen, char **out, int *out_len), (priv_str,priv_len,password,passwordLen,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK8_to_PK1, (unsigned char *p8, int p8_len, char *password, int passwordLen, int out_form, unsigned char **out, int *out_len), (p8,p8_len,password,passwordLen,out_form,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Get_HSM_Signer_IssuerDN, (unsigned char *drv_str, int drv_len, char **issuer_dn), (drv_str,drv_len,issuer_dn), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Get_HSM_Driver_Count, (unsigned char *drv_str, int drv_len, int *count), (drv_str,drv_len,count), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Verify_HSM_Driver_Info, (unsigned char *drv_str, int drv_len, unsigned char *cert_str, int cert_len, DRIVER_INFO *drv_info), (drv_str,drv_len,cert_str,cert_len,drv_info), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Get_HSM_Driver_Signature_Count, (unsigned char *drv_str, int drv_len, int *count), (drv_str,drv_len,count), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Verify_HSM_Driver_Signature_Info, (unsigned char *drv_str, int drv_len, unsigned char *cert_str, int cert_len, DRIVER_SIGNATURE_INFO *drv_info), (drv_str,drv_len,cert_str,cert_len,drv_info), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Load_Library, (char *path), (path), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_PK11_Unload_Library, (), () );
INI_RET_LOADLIB_CORE(int, ICL_PK11_Initialize, (), (), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Finalize, (), (), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Get_Slot_Count, (int *count), (count), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Open_Session, (int slot, char *pin, int pin_len, CK_HANDLE *hSession), (slot,pin,pin_len,hSession), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Open_Session_Without_Login, (int slot, CK_HANDLE *hSession), (slot, hSession), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_LoginBegin, (CK_HANDLE hSession, CK_USER_TYPE userType, CK_ULONG_PTR pulK, CK_ULONG_PTR pulN), (hSession, userType, pulK, pulN), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_LoginNext, (CK_HANDLE hSession, CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen, CK_ULONG_PTR pulSharesLeft), (hSession, userType, pPin, ulPinLen, pulSharesLeft), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_LoginEnd, (CK_HANDLE hSession, CK_USER_TYPE userType), (hSession, userType), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_PK11_Logout, (CK_HANDLE hSession), (hSession) );
INI_RET_LOADLIB_CORE(int, ICL_PK11_Close_Session, (CK_HANDLE *hSession), (hSession), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Sym_Encrypt, (CK_HANDLE hSession, unsigned char *key_name, int name_len, char name_type, char *alg, unsigned char *iv, int iv_len, unsigned char *in, int in_len, unsigned char **out, int *out_len), (hSession,key_name,name_len,name_type,alg,iv,iv_len,in,in_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Sym_Decrypt, (CK_HANDLE hSession, unsigned char *key_name, int name_len, char name_type, char *alg, unsigned char *iv, int iv_len, unsigned char *in, int in_len, unsigned char **out, int *out_len), (hSession,key_name,name_len,name_type,alg,iv,iv_len,in,in_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_RSA_Encrypt, (CK_HANDLE hSession, unsigned char *key_name, int name_len, char name_type, char key_type, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len), (hSession,key_name,name_len,name_type,key_type,pad_mode,in,in_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_RSA_Decrypt, (CK_HANDLE hSession, unsigned char *key_name, int name_len, char name_type, char key_type, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len), (hSession,key_name,name_len,name_type,key_type,pad_mode,in,in_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_RSA_Sign, (CK_HANDLE hSession, unsigned char *key_name, int name_len, char name_type, char *hash_name, char pad_mode, unsigned char *in, int in_len, unsigned char **out, int *out_len), (hSession,key_name,name_len,name_type,hash_name,pad_mode,in,in_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_RSA_Verify, (CK_HANDLE hSession, unsigned char *key_name, int name_len, char name_type, char *hash_name, char pad_mode, unsigned char *msg, int msg_len, unsigned char *sign, int sign_len), (hSession,key_name,name_len,name_type,hash_name,pad_mode,msg,msg_len,sign,sign_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_RSA_Key_Generate, (CK_HANDLE hSession, unsigned char *pub_key_id, int pub_key_id_len, unsigned char *pri_key_id, int pri_key_id_len, int key_bit, unsigned char *out_pubk, int *out_pubk_len), (hSession,pub_key_id,pub_key_id_len,pri_key_id,pri_key_id_len,key_bit,out_pubk,out_pubk_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Hash, (CK_HANDLE hSession, char *alg, unsigned char *in, int in_len, unsigned char *out, int *out_len), (hSession,alg,in,in_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Set_RSAKey, (CK_HANDLE hSession, unsigned char* cert_id, int certid_len, unsigned char* pubk_id, int pubkid_len, unsigned char *key_id, int keyid_len, unsigned char *cert_der, int cert_len, unsigned char* modulus, int modulus_len, unsigned char* exponent, int exponent_len, unsigned char *priv_der, int priv_len, char *passwd, int passwd_len, int key_usage), (hSession, cert_id, certid_len, pubk_id, pubkid_len, key_id, id_len, cert_der, cert_len, modulus, modulus_len, exponent, exponent_len, priv_der,priv_len,passwd,passwd_len, key_usage), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Get_Cert, (CK_HANDLE hSession, unsigned char *key_id, int id_len, unsigned char **cert_der, int *cert_len), (hSession,key_id,id_len,cert_der,cert_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Delete_RSAKey, (CK_HANDLE hSession, unsigned char *key_id, int id_len), (hSession,key_id,id_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Get_Vid_Random, (CK_HANDLE hSession, unsigned char *key_id, int id_len, unsigned char *rand, int *rand_len), (hSession,key_id,id_len,rand,rand_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Get_Token_Serial, (int slot, unsigned char *serial, int *serial_len), (slot,serial,serial_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Get_Token_FreeMemory, (int slot, unsigned int *free_public_memory, unsigned int *free_private_memory), (slot,free_public_memory,free_private_memory), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Set_Sym_Key, (CK_HANDLE hSession, unsigned char *key_id, int id_len, char *alg, unsigned char *key, int key_len), (hSession,key_id,id_len,alg,key,key_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Delete_Sym_Key, (CK_HANDLE hSession, unsigned char *key_id, int id_len), (hSession,key_id,id_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Get_All_Certs_Count, (CK_HANDLE hSession, int *count), (hSession,count), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Get_All_Certs, (CK_HANDLE hSession, PKI_STR_INFO *certs), (hSession,certs), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK12_Make_PFX, (char *passwd, int passwd_len, char *name, int name_len, int user_keys_cnt, PKI_STR_INFO *user_keys, int ca_keys_cnt, PKI_STR_INFO *ca_keys, unsigned char **out_p12, int *out_p12_len), (passwd,passwd_len,name,name_len,user_keys_cnt,user_keys,ca_keys_cnt,ca_keys,out_p12,out_p12_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK12_Make_PFX_With_Pass, (char *passwd, int passwd_len, char *p12_passwd, int p12_passwd_len, char *name, int name_len, int user_keys_cnt, PKI_STR_INFO *user_keys, int ca_keys_cnt, PKI_STR_INFO *ca_keys, unsigned char **out_p12, int *out_p12_len), (passwd,passwd_len,p12_passwd,p12_passwd_len,name,name_len,user_keys_cnt,user_keys,ca_keys_cnt,ca_keys,out_p12,out_p12_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK12_Verify_PFX, (char *passwd, int passwd_len, unsigned char *p12_str, int p12_str_len, int *user_keys_cnt, PKI_STR_INFO **user_keys, int *ca_keys_cnt, PKI_STR_INFO **ca_key), (passwd,passwd_len,p12_str,p12_str_len,user_keys_cnt,user_keys,ca_keys_cnt,ca_key), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK12_Verify_PFX_With_Pass, (char *passwd, int passwd_len, char *p12_passwd, int p12_passwd_len, unsigned char *p12_str, int p12_str_len, int *user_keys_cnt, PKI_STR_INFO **user_keys, int *ca_certs_cnt, PKI_STR_INFO **ca_certs), (passwd,passwd_len,p12_passwd,p12_passwd_len,p12_str,p12_str_len,user_keys_cnt,user_keys,ca_certs_cnt,ca_certs), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PRNG_T_Random_Init, (void), (), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_PRNG_T_Random_Clean, (void), () );
INI_RET_LOADLIB_CORE(int, ICL_PRNG_Get_T_Random, (int to_size, unsigned char *out_rand), (to_size,out_rand), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PRNG_Get_Random, (unsigned char *random, int rand_len), (random,rand_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PRNG_Get_SeedRandom, (unsigned char *seed, int seed_len, unsigned char *random, int rand_len), (seed,seed_len,random,rand_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PRNG_Get_TimeRandom, (int to_size, unsigned char *out_rand), (to_size,out_rand), -10000);
INI_RET_LOADLIB_CORE(int, ICL_HASH_Data, (unsigned char *in_data, int in_data_len, unsigned char **hash_data, int *hash_len, char *hash_alg), (in_data,in_data_len,hash_data,hash_len,hash_alg), -10000);
INI_RET_LOADLIB_CORE(int, ICL_HASH_Get_Length, (char *hash_alg, int *hash_len), (hash_alg,hash_len), -10000);
INI_RET_LOADLIB_CORE(void*, ICL_HASH_New, (void), (), NULL);
INI_RET_LOADLIB_CORE(int, ICL_HASH_Init, (void *ctx, char *hash_alg), (ctx,hash_alg), -10000);
INI_RET_LOADLIB_CORE(int, ICL_HASH_Update, (void *ctx, unsigned char *in_data, int in_data_len), (ctx,in_data,in_data_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_HASH_Final, (void *ctx, unsigned char **hash_data, int *hash_len), (ctx,hash_data,hash_len), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_HASH_Free, (void *ctx), (ctx) );
INI_RET_LOADLIB_CORE(int, ICL_MAC_HMAC, (int algo_id, unsigned char *input, int inputlen, unsigned char *key, int keylen, unsigned char **output, int *outlen), (algo_id,input,inputlen,key,keylen,output,outlen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Conv_Cert2PEM, (unsigned char *cert, int certlen, char **PEMcert, int *PEMlen), (cert,certlen,PEMcert,PEMlen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Conv_Cert2DER, (unsigned char *cert, int certlen, unsigned char **DERcert, int *DERlen), (cert,certlen,DERcert,DERlen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Init_X509_Info, (unsigned char *cert, int certlen, char field_sep, X509_INFO **x509info), (cert,certlen,field_sep,x509info), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_X509_Free_X509_Info, (X509_INFO *x509info), (x509info) );
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_CRLdp, (X509_INFO *x509info, char **crldp), (x509info,crldp), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_CRLdp_Count, (X509_INFO *x509info), (x509info), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_CRLdp_Index, (X509_INFO *x509info, char **crldp, int index), (x509info,crldp,index), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_LicenseIPs, (X509_INFO *x509info, IPADDR **ips, int *ipsCnt), (x509info,ips,ipsCnt), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_IssuerDN, (X509_INFO *x509info, char **issuerDN), (x509info,issuerDN), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_SubjectDN, (X509_INFO *x509info, char **subjectDN), (x509info,subjectDN), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_SubjectDN_DER, (X509_INFO *x509info, char **subjectDN_DER), (x509info,subjectDN_DER), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_DN_Field, (char *strDN, char *shortname, char **value), (strDN,shortname,value), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_Serial, (X509_INFO *x509info, char **serial, int totype), (x509info,serial,totype), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_ValidityFrom, (X509_INFO *x509info, char **validityFrom), (x509info,validityFrom), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_ValidityTo, (X509_INFO *x509info, char **validityTo), (x509info,validityTo), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_Pubkey, (X509_INFO *x509info, unsigned char **pubkey, int *pubkeyLen), (x509info,pubkey,pubkeyLen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_Signature, (X509_INFO *x509info, char **signature, int *signatureLen), (x509info,signature,signatureLen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_PubkeyAlg, (X509_INFO *x509info, char **alg, int algtype), (x509info,alg,algtype), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Info_Get_SignatureAlg, (X509_INFO *x509info, char **alg, int algtype), (x509info,alg,algtype), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Check_VID, (unsigned char *cert, int certlen, const unsigned char *rand, int rand_len, const char *idnum, int id_len), (cert,certlen,rand,rand_len,idnum,id_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Exist_VID, (unsigned char *cert_str, int cert_len), (cert_str,cert_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Verify, (unsigned char *cert, int certlen, unsigned char *cacert, int cacertlen, int actflag), (cert,certlen,cacert,cacertlen,actflag), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Verify_DN, (unsigned char *cert, int certlen, unsigned char *cacert, int cacertlen), (cert,certlen,cacert,cacertlen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_CompareWithCRL_AutorityKeyIndentifier, (unsigned char *cert, int certlen, unsigned char *crl, int crllen), (cert,certlen,crl,crllen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_CompareWithCRL_Issuer, (unsigned char *cert, int certlen, unsigned char *crl, int crllen), (cert,certlen,crl,crllen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_CompareWithCRL_DistributionPointName, (unsigned char *cert, int certlen, unsigned char *crl, int crllen), (cert,certlen,crl,crllen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Check_Have_KeyUsage, (unsigned char *cacert, int cacertlen, int keyusage), (cacert,cacertlen,keyusage), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Verify_Signature, (unsigned char *cert, int certlen, unsigned char *cacert, int cacertlen), (cert,certlen,cacert,cacertlen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Verify_Validity, (unsigned char *cert, int certlen, X509_INFO *x509info, time_t *ltime), (cert,certlen,x509info,ltime), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Check_Update, (X509_INFO *x509info, long seconds), (x509info,seconds), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_CRL_Verify, (unsigned char *crl, unsigned char *cacert, int cacertlen), (crl,cacert,cacertlen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_CRL_Verify_NextUpdate, (unsigned char *crl), (crl), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_CRL_Verify_Issuer, (unsigned char *crl, int crllen, unsigned char *cert, int certlen), (crl,crllen,cert,certlen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Is_Revoked, (unsigned char *crl, unsigned char *cert, int certlen, int *is_revoked), (crl,cert,certlen,is_revoked), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_Is_Revoked_With_Reason, (unsigned char *crl, unsigned char *cert, int certlen, int *is_revoked, char *revoked_date, char *revoked_reason), (crl,cert,certlen,is_revoked,revoked_date,revoked_reason), -10000);
INI_RET_LOADLIB_CORE(int, ICL_GenTime_To_LocalTime, (char *generalized_time_str, char *local_time_str), (generalized_time_str,local_time_str), -10000);
INI_RET_LOADLIB_CORE(int, ICL_COM_Is_Pem, (char *in), (in), -10000);
INI_RET_LOADLIB_CORE(int, ICL_COM_Encrypt_Password, (char *pwd, int pwd_len, unsigned char **out, int *out_len), (pwd,pwd_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_COM_Decrypt_Password, (unsigned char *in, int in_len, char **out, int *out_len), (in,in_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_COM_DER_to_PEM, (const unsigned char *in_der_str, int in_len, unsigned char **out_pem, int *out_len, int key_mode), (in_der_str,in_len,out_pem,out_len,key_mode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_COM_PEM_to_DER, (const unsigned char *in_pem_str, int in_len, unsigned char **out_der, int *out_len), (in_pem_str,in_len,out_der,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Initialize, (void), (), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_COM_Change_Non_Proven, (void), () );
INI_RET_LOADLIB_CORE(int, ICL_Is_Proven_Mode, (void), (), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_COM_ChangeTestMode, (void), () );
INI_RET_LOADLIB_CORE(int, ICL_COM_Convert_Hash_Name, (char *alg, int *alg_id), (alg, alg_id), -10000);
INI_RET_LOADLIB_CORE(int, ICL_OTP_Gen_Message, (char *otpPhase, char *otpSeed, char *otpAlg, unsigned int times, unsigned char **msg), (otpPhase,otpSeed,otpAlg,times,msg), -10000);
INI_RET_LOADLIB_CORE(int, ICL_COM_Check_Password, (unsigned char* pem_str, int pem_str_len, char *passwd, int passwd_len), (pem_str,pem_str_len,passwd,passwd_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_COM_Get_Random, (unsigned char* pem_str, int pem_str_len, char *passwd, int passwd_len, unsigned char **out, int *out_len), (pem_str,pem_str_len,passwd,passwd_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_COM_GetPrivateKeyType, (unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, int *retKeyType), (priv_str,priv_len,passwd,passwd_len,retKeyType), -10000);
INI_RET_LOADLIB_CORE(int, ICL_COM_Change_Password, (unsigned char* pem_str, int pem_str_len, char *old_passwd, int old_pwd_len, char *new_passwd, int new_pwd_len, unsigned char **out, int *out_len), (pem_str,pem_str_len,old_passwd,old_pwd_len,new_passwd,new_pwd_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_X509_SIGN_to_binary, (char* hash_alg, unsigned char* hash_data, int hashdata_len, unsigned char **seq, int *seq_len), (hash_alg,hash_data,hashdata_len,seq,seq_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_binary_to_X509_SIGN, (unsigned char *seq, X509_SIGNED_INFO *sign), (seq,sign), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK8_Remove_RData, (unsigned char *pk8_str, int pk8_len, char *passwd, int pwd_len, unsigned char **out, int *out_len), (pk8_str,pk8_len,passwd,pwd_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Cert_To_RSAINFO, (unsigned char *cert_str, int cert_len, RSA_INFO **rsa_info), (cert_str,cert_len,rsa_info), -10000);
INI_RET_LOADLIB_CORE(int, ICL_NTP_Init, (char *ntp_ip, int ntp_port), (ntp_ip,ntp_port), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_NTP_Close, (), () );
INI_RET_LOADLIB_CORE(int, ICL_NTP_Get_Current_Local_Time, (char* ip, int port, char **timestr), (ip,port,timestr), -10000);
INI_RET_LOADLIB_CORE(int, ICL_NTP_Get_Current_GM_Time, (char* ip, int port, char **timestr), (ip,port,timestr), -10000);
INI_RET_LOADLIB_CORE(int, ICL_NTP_Get_Current_Local_Time_t, (char *ip, int port, time_t *timet), (ip,port,timet), -10000);
INI_RET_LOADLIB_CORE(int, ICL_NTP_Get_Current_GM_Time_t, (char *ip, int port, time_t *timet), (ip,port,timet), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_SignedData_Init, (unsigned char *msg, int msg_len, char *hash_alg, struct tm *recv_time, unsigned char **out, int *out_len), (msg,msg_len,hash_alg,recv_time,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Make_Signed_Data_With_SignData, (unsigned char *msg, int msg_len, PKI_STR_INFO *rsa_keys,char *hash_alg, int version, int ins_cert, int ins_contentinfo,int out_type,unsigned char* sign, int signLen,unsigned char *auth_attr, int auth_attr_len, unsigned char **out, int *out_len), (msg,msg_len,rsa_keys,hash_alg,version,ins_cert,ins_contentinfo,out_type,sign,signLen,auth_attr,auth_attr_len,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK7_Remove_ContentType, (int in_type, unsigned char *in, int in_len, int out_type, unsigned char **out, int *out_len), (in_type,in,in_len,out_type,out,out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_COM_HEX2BIGINT_n_cmp, (const char *hex1, const char *hex2), (hex1,hex2), -10000);
INI_RET_LOADLIB_CORE(int, ICL_COM_WebContentScriptInit, (const char *scriptparam, SCRIPT_VERIFY_CORE **wcVerifier),(scriptparam,wcVerifier) , -10000);
INI_RET_LOADLIB_CORE(int, ICL_COM_WebContentScriptVerifier_RSA, (const char *base64_rsakey, unsigned char* sign, int sign_len, const char* dest_data, int dest_data_len),(base64_rsakey,sign,sign_len,dest_data,dest_data_len) , -10000);
INI_RET_LOADLIB_CORE(int, ICL_COM_convert_hash_id_to_name, (int nSignAlg, char *HashName ), (nSignAlg, HashName), -10000);
INI_RET_LOADLIB_CORE(int,  ICL_PK1_Generate_ECDSA_Key, (char *curve_name, char out_type, unsigned char **pubk_str, int *pubk_len, unsigned char **prik_str, int *prik_len), (curve_name,out_type,pubk_str,pubk_len,prik_str,prik_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Generate_CI, (char *rn, unsigned char *si, int si_len, unsigned char *sk, int sk_len, char **out), (rn,si,si_len,sk,sk_len,out), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Generate_DI, (char *rn, char *si, unsigned char *sk, int sk_len, char **out), (rn,si,sk,sk_len,out), -10000);
INI_RET_LOADLIB_CORE(ASN1_TIME*, ICL_COM_getCurrentLocalTime, (), (), NULL);
INI_RET_LOADLIB_CORE(ASN1_TIME*, ICL_COM_getCurrentGMTime, (), (), NULL);
INI_RET_LOADLIB_CORE(int, ICL_PK1_signature_schemes, (ASYMMETRIC_KEY *akey, char pad_mode, int hash_id, unsigned char *in, int in_len, unsigned char *out, int *out_len), (akey, pad_mode, hash_id, in, in_len, out, out_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_verify_schemes, (ASYMMETRIC_KEY *akey, char pad_mode, int hash_id, unsigned char *msg, int msg_len, unsigned char *sign, int sign_len), (akey, pad_mode, hash_id, msg, msg_len, sign, sign_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK8_decode_pkcs8, (unsigned char *pk8_str, int pk8_len, char *passwd, int passwd_len, P8_PRIV_KEY_INFO **out_p8), (pk8_str, pk8_len, passwd, passwd_len, out_p8), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK8_get_asym_key, (unsigned char *pk8_str, int pk8_len, char *passwd, int passwd_len, ASYMMETRIC_KEY **out_key), (pk8_str, pk8_len, passwd, passwd_len, out_key), -10000);

INI_RET_LOADLIB_CORE(int, ICL_PK11_Check_Hsm, (CK_HANDLE hSession), (hSession), -10000);

INI_RET_LOADLIB_CORE(int, ICL_PK11_ECDSA_Key_Generate, (CK_HANDLE hSession, char* curve_name, unsigned char* pubkey_id, int length_pubkey_id, unsigned char* prikey_id, int length_prikey_id, unsigned char** ecpoint_x, int* length_ecpoint_x, unsigned char** ecpoint_y, int* length_ecpoint_y), (hSession, curve_name, pubkey_id, length_pubkey_id, prikey_id, length_prikey_id,ecpoint_x, length_ecpoint_x, ecpoint_y, length_ecpoint_y), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_ECDSA_Sign, (CK_HANDLE hSession, unsigned char *key_name, int length_key_name, char name_type, char* hashName, unsigned char *in, int length_in, unsigned char **out, int *length_out), (hSession, key_name, length_key_name, name_type, hashName, in, length_in, out, length_out), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_ECDSA_Sign_ex, (CK_HANDLE hSession, unsigned char *key_name, int length_key_name, char name_type, char* hashName, unsigned char *in, int length_in, unsigned char **out, int *length_out, int *hsm_errcode), (hSession, key_name, length_key_name, name_type, hashName, in, length_in, out, length_out, hsm_errcode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_ECDSA_Verify, (CK_HANDLE hSession, unsigned char *key_name, int length_key_name, char name_type, char *hashName, unsigned char *msg, int msg_len, unsigned char *sign, int sign_len), (hSession, key_name, length_key_name, name_type, hashName, msg, msg_len, sign, sign_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Get_ECDSAPublic_Key, (CK_HANDLE hSession, unsigned char *key_id, int id_len, char name_type, unsigned char** ecpoint_x, int* length_ecpoint_x, unsigned char** ecpoint_y, int* length_ecpoint_y), (hSession, key_id, id_len, name_type, ecpoint_x, length_ecpoint_x, ecpoint_y, length_ecpoint_y), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_ECDSA_RawPubkeyValue_to_ASYMMETRIC_KEY, (unsigned char* ecpoint_x, int lenghth_ecpoint_x, unsigned char* ecpoint_y, int lenghth_ecpoint_y, int curve_id, ASYMMETRIC_KEY** aSymmkey), (ecpoint_x, lenghth_ecpoint_x, ecpoint_y, lenghth_ecpoint_y, curve_id, aSymmkey), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Delete_ECDSAKeySets, (CK_HANDLE hSession, unsigned char *pkey_id, int pkey_id_len, unsigned char* pubk_id, int pubk_id_len, unsigned char* cert_id, int cert_id_len, unsigned char* vid_id, int vid_id_len), (hSession, pkey_id, pkey_id_len, pubk_id, pubk_id_len, cert_id, cert_id_len, vid_id, vid_id_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_gen_SIG_X509_Cert_By_ECDSA, (CK_HANDLE hSession, X509_CERT* cert, unsigned char* pri_key_id, int pri_key_id_len), (hSession, cert, pri_key_id, pri_key_id_len), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Get_Pub_KeyType, (unsigned char *pubk_str, int pubk_len, int *keyType), (pubk_str, pubk_len, keyType), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK1_Get_Pri_KeyType, (unsigned char *priv_str, int priv_len, int *keyType), (priv_str, priv_len, keyType), -10000);
INI_RET_LOADLIB_CORE(int, ICL_PK11_Get_Public_Key_Algorithm(CK_HANDLE hSession, unsigned char *key_name, int length_key_name, char *keyAlgo, char *keyCurve), (CK_HANDLE hSession,key_name,length_key_name,keyAlgo,keyCurve ), -10000);

#endif

char* ICL_Get_Version(void);
char* ICL_Get_Crypto_Version(void);
char* ICL_Get_Pki_Version(void);

#ifdef  __cplusplus
}
#endif

#endif /* ICL_INICRYPTO_H_ */
