/**
 *	@file	: INL_external.h
 *	@brief	  함수들이 선언된 헤더파일
 *	@section  CREATEINFO	Create
 *   - create	:   2009/02/16
 */

#ifndef INL_EXTERNAL_H_
#define INL_EXTERNAL_H_



#ifdef _INI_BADA
#include "INL_bada.h"
#endif

#ifndef INISAFENET_API
#ifdef WIN32
	#ifdef INISAFENET_API_EXPORTS
	#define INISAFENET_API __declspec(dllexport)
	#elif defined(INISAFENET_API_STATIC)
	#define INISAFENET_API
	#else
	#define INISAFENET_API __declspec(dllimport)
	#endif
#else
	#define INISAFENET_API
#endif
#endif

#ifndef STDCALL
#if defined(WIN32) && (!defined(_INI_BADA))
	/* VS2008 하위 버전에서는 필요할 수 있으나 VS2008에서는 노출 함수 사용을 방해해서 사용 안함 */
	#if (_MSC_VER < 1500)
		#define STDCALL __stdcall
	#else
		#define STDCALL
	#endif
#else
#define STDCALL
#endif
#endif

#ifdef _USEATL_
	#define INISAFENET_CHAR_API char*
	#define INISAFENET_VOID_API void				/**< define void type */
	#define INISAFENET_NETCTX_API net_ctx*
	#define INISAFENET_INT_API int					/**< define integer type */
	#define INISAFENET_RSA_API	RSA*


#elif defined(_WIN8STORE) 
	#define INISAFENET_CHAR_API INISAFENET_API char*
	#define INISAFENET_VOID_API INISAFENET_API void 	/**< define void type */
	#define INISAFENET_NETCTX_API INISAFENET_API net_ctx*
	#define INISAFENET_INT_API INISAFENET_API int	/**< define integer type */
	#define INISAFENET_RSA_API INISAFENET_API RSA*

#else
	#define INISAFENET_CHAR_API INISAFENET_API char* STDCALL
	#define INISAFENET_VOID_API INISAFENET_API void STDCALL	/**< define void type */
	#define INISAFENET_NETCTX_API INISAFENET_API net_ctx* STDCALL
	#define INISAFENET_INT_API INISAFENET_API int STDCALL	/**< define integer type */
	#define INISAFENET_RSA_API INISAFENET_API RSA* STDCALL
#endif





#ifdef INISAFENET_64_BIT
	#define SIXTY_FOUR_BIT  /* 64bit */
	#undef THIRTY_TWO_BIT /* 32bit */
#else
	#undef SIXTY_FOUR_BIT  /* 64bit */
	#define THIRTY_TWO_BIT /* 32bit */
#endif


#ifdef  __cplusplus
extern "C" {
#endif /*#ifdef  __cplusplus*/


/*** Include files ***/
#include <stdio.h>
#include <time.h>


/*** Constant Definition ***/
/* BASE CTX */
#define FIXKEY_CTX			0x08	/**<KEY FIX */
#define EXCHGKEY_CTX		0x06	/**<KEY EXCHANGE */

#define CLIENT_CTX			0x02	/**<HANDSHAKE */
#define SERVER_CTX			0x01	/**<HANDSHAKE */
#define RSA_CLIENT_CTX		0x32	/**<HANDSHAKE */
#define RSA_SERVER_CTX		0x31	/**<HANDSHAKE */

#define I_SIGN_VFY    		0x10	/**<SIGN/VERIFY */


#define EXT_EXCHGKEY_CTX    0x0a	/**<BC Card only */
#define SERVER_INT_CTX		0x11	/**<CH Bank only */
#define CLIENT_INT_CTX		0x12	/**<CH Bank only */
#define CLIENT_AUTH			0x04	/**<not use */


#define LEN_KEY_FILE		2048	/**<Max buffer size to read key_file */
#define INL_MAX_HSM_NUM		4
#define INL_MAX_IP_SIZE		128
#define INL_MAX_ID_SIZE		20
#define INL_MAX_PASS_SIZE	128
#define INL_PACCEL_PROTO_SIZE	10
#define INL_KEYID_SIZE		64
#define INL_DAY_SIZE		32
#define INL_SALT_SIZE		32
#define INL_RAND_LEN		20
#define INL_EXKEY_LEN		16
#define INL_EXIV_LEN		16

#define INL_PUBKEYID		0x00
#define INL_PRIVKEYID		0x01
#define INL_SYMMKEYID		0x02

#define INL_TYPE_CERT		"CERT"
#define INL_TYPE_KEY		"KEY"

/* HSM address structure */
typedef struct inl_address_st{
	char ip[INL_MAX_IP_SIZE];
	int port;
}ISP_ADDRESS;

/*** Valiable Declaration ***/
/**
 * @brief	암/복호화용 세션정보를 갖고 있는 구조체
 *			- 세션 생성 시 설정파일에서 로드된 값을 구조체에 할당
 *			- 세션 종료 시 INL_Free_Ctx() 할당된 메모리 해제
 */
typedef struct
{
	int 			type;					/**<ctx_type */
	unsigned char	ran1[20+1];				/**<client random */
	unsigned char	ran2[20+1];				/**<server random*/
	unsigned char	key[32+1];				/**<Session Key*/
	int				key_len;				/**<Session Key*/
	unsigned char	alg[40+1];				/**<Symmetric Algorithm*/
    int             alg_key_size;           /**<Symmetirc Algorithm key length */
	unsigned char	enc[4+1];				/**<Encoding Flag for Data*/
	unsigned char	hs_enc[4+1];			/**<Encoding Flag for Handshake Message*/
	unsigned char	iv[32+1];				/**<Initial vector*/
	int				iv_len;
	char			DigestAlg[24];			/**<Hash Algoritm for session-key*/
	int				grant_flag;				/**<crypto license flag*/
	char			ccert_dir[512];			/**<client cert directory*/
	int				base64_flag;			/**<The flag to insert LINE_FEED at base64 encoding (0=NO, 1=INSERT)*/
	int				useProven;			/**<The flag to use only Proven Crypto Algorithm (0=NO, 1=Yes(default))*/
	int				useCryptoVerify;			/**<The flag to use Crypto Module Verify(0=NO, 1=Yes(default))*/

	unsigned char	scert[LEN_KEY_FILE+1];			/**<Server Certificate*/
	int				scertlen;
   
    
	unsigned char	privkey[LEN_KEY_FILE+1];		/**<Server Private Key*/
	int				privlen;
	unsigned char	privkeypass[100+1];		/**<Private Key Password*/
	int 			privkeypasslen;
    
	unsigned char	ccert[LEN_KEY_FILE+1];			/**<Client Certificate*/
	int				ccertlen;				/**<Length of Client Certificate*/
    
	unsigned char	EncryptedSkey[LEN_KEY_FILE+1];	/**<Encrypted IV_SKEY file path(for key_fix)*/
	int				EncryptedSkeylen;		/**<Length of encrypted IV_SKEY file(for key_fix)*/
	unsigned char	EncSkeyPassword[100];	/**<encrypted IV_SKEY password to decrypt*/
	int				EncSkeyPasswordlen;
	unsigned char	hash_key_use[3+1];	/**<encrypted IV_SKEY password to decrypt*/

	unsigned char	md[64+1];					/**<Message Digest (only for SERVER/CLIENT_INT_CTX)*/

	int				check_expire_cert_flag;

	unsigned char	IssuerDN[128];			/**<Check cert's DN (only for KRX handshake_CTX)*/
	char			sver[20+1];				/**<Server's acceptable handshake message (only for KRX handshake_CTX)*/
	char			cver[4+1];				/**<Client's handshake message (only for KRX handshake_CTX)*/
	char			ccert_req[1+1];				/**<Server's handshake message (only for v4001, v5001)*/
	int 			ranpad_len;				/**< */
	char			integrity_check[3+1];				/**< */
	char			scert_type_req[4+1];

	int				auth_cert_flag;			/**<Compare other cert for auth*/
	unsigned char	your_cert[LEN_KEY_FILE+1];
	int 			your_cert_len;

	int				authFlag;				/**<(for etc)*/
	unsigned char	cer[40+1];				/**<(for etc)*/
	int				cerlen;					/**<(for etc)*/

	unsigned char	cacert[LEN_KEY_FILE+1];
	int				cacert_len;

	unsigned char   cacerts_path[255];

	unsigned char	secseed[20+1];
	int				secseedlen;

	int				exchg_valid_cert_flag;
	char			accept_client_version[32];			/* Accept Client version 7.2.21 */
	char			accept_old_client;					/* 'A'(ccept), 'R'(eject), 'W'(arning) */
	int 		padding_flag;	/* 0: no padding 1: padding(PKCS 5) */
	
	/* advance blockcipher 사용 관련 추가 */
	int use_adv_blockcipher;
	int init_adv_enc;
	int init_adv_dec;
	unsigned char initd_enc_key[4400];
	int initd_enc_keylen;
	unsigned char initd_dec_key[4400];
	int initd_dec_keylen;

	char cert_type[4+1];

	/* paccel 연동 관련 추가 */
    char	scert_path[255+1];			/**<Server Certificate*/
    char	privkey_path[255+1];		/**<Server Private Key*/
    char	ccert_path[255+1];			/**<Client Certificate*/
    char	EncryptedSkey_path[255+1];	/**<Encrypted IV_SKEY file path(for key_fix)*/

    char    old_scert_path[255+1];
    char    old_privkey_path[255+1];
    char    old_ccert_path[255+1];
    char    old_EncryptedSkey_path[255+1];

    
	int hsm_use;
    int hsm_backup_mode;
	int hsm_num; /* hsm 갯수 */
	ISP_ADDRESS hsm_address[INL_MAX_HSM_NUM]; /* hsm ip/port 계정정보 */
	char hsm_user[INL_MAX_ID_SIZE];
	char hsm_pass[INL_MAX_PASS_SIZE];
	char hsm_protocol[INL_PACCEL_PROTO_SIZE]; /* protocol */
	int hsm_enc_use; /* 0:off 1:enc */
	int hsm_enc_alg;
	int hsm_retry;
	int hsm_socket_timeout;

    void *hsm_handle;
    
	char s_pubkid[INL_KEYID_SIZE];
	int s_pubkid_len;
    void *hsm_s_pubk_info;
    
	char c_pubkid[INL_KEYID_SIZE];
	int c_pubkid_len;
    void *hsm_c_pubk_info;
    
	char privkid[INL_KEYID_SIZE];
	int privkid_len;
    void *hsm_privk_info;
    
	char symmkid[INL_KEYID_SIZE];
	int symmkid_len;
    void *hsm_symk_info;
   
   int hsm_update_flag;	
 
#if 0
	unsigned char p_symmkey[32+1];
	int p_symmkey_len;
	unsigned char p_symmiv[32+1];
	int p_symmiv_len;
    
	unsigned char p_privkey[LEN_KEY_FILE+1];
	int p_privkey_len;
    
    
	unsigned char s_pubkey[LEN_KEY_FILE+1];
	int s_pubkey_len;
    
    
	unsigned char c_pubkey[LEN_KEY_FILE+1];
	int c_pubkey_len;
#endif
    
	/* exchange adv 에서 사용할 secret key */
	unsigned char ex_salt[INL_SALT_SIZE+1];
	int ex_salt_len;

	/* exchange adv 에서 사용할 random */
	unsigned char ex_random[INL_RAND_LEN+1];

	/* 키 갱신 주기 */
	int key_renew_term;

	/* 클라이언트 인증서 정보 출력 유무 */
	int view_ccert;

	/*For Windows*/
#ifdef _WIN32
	char hsm_libpath[LEN_KEY_FILE+1];

	/*======================================================================================================
	 For COM의 경우, 여러 Thread에서 동시 접근이 가능하므로 Global 변수의 사용은 문제를 유발할 수 있다.
	   따라서, net_ctx 구조체의 멤버로 선언해서 Global Context의 값을 접근하여 사용해야 문제가 없다 
    ======================================================================================================*/
	CRITICAL_SECTION csGlobalContext; /* INL_Initialize에서 생성하는 Global Context 변수에 하나의 Thread만 접근할 수 있도록 처리하기 위한 Critical Section*/
	CRITICAL_SECTION csCopyContext;	  /* Context 복사할 때 하나의 Thread만 접근할 수 있도록 처리하기 위한 Critical Section*/
#endif
} net_ctx;
    
#define MAX_KEY_ID             100
#define MAX_PUBLIC_KEY         3072
    
    typedef struct _isp_key_info{
        unsigned char keyid[MAX_KEY_ID];
        int keyid_len;
        char key_type; /* KEY_TYPE_PUBKEY/KEY_TYPE_PRIVKEY/KEY_TYPE_SYMMKEY/KEY_TYPE_DATA */
        unsigned char key[MAX_PUBLIC_KEY];
        int key_len;
        unsigned char iv[MAX_PUBLIC_KEY];
        int iv_len;
        char check_type;  /* CHECK_TYPE_TERM: check to expiredate/ CHECK_TYPE_EXP: check to term */
        char check_date_type; /* CHECK_DATE_TYPE_END_DATE: end_date / CHECK_DATE_TYPE_EXP_DATE: expire_date */
        char start_date[14+1];
        char end_date[14+1];
        char expire_date[14+1];
        char check_date[14+1];
        int check_term; /* minute */
    } ISP_KEY_EXP_INFO;


#ifdef INITECH_ASP
extern CRITICAL_SECTION g_csFileAccess;    /* atlINISafeNet.cpp에 Global 변수로 선언된 Critical Section 객체를 다른 곳에서도 사용하기 위해서 선언 */
#endif
    

/*** Function Declaration ***/
/**
 * @brief	: INISAFE Net의 현재 제품 버전을 표준출력
 * @param	:(void)
 * @return	:(void)
 */
INISAFENET_VOID_API INL_Get_Version(void);

/**
 * @brief	: 마지막 에러코드 반환
 * @param	:(void)
 * @return	:(int) 에러코드
 */
INISAFENET_INT_API INL_GetLastError(void);

/**
 * @brief	: 에러코드에 대한 문자열 반환
 * @param	:(int) error_code: 에러 코드
 * @return	:(char *) 에러코드에 해당하는 에러메시지
 */
INISAFENET_CHAR_API INL_Error_String(int error_code);

/**
 * @brief       : 암호모듈 사용 모드를 비검증 모드로 변경
 *                (검증알고리즘 + 비검증알고리즘 사용 가능)
 * @param       :(void)
 * @return      :(void)
 */
INISAFENET_VOID_API INL_Change_Non_Proven(void);

/**
 * @brief	: INISAFE Net 로그 초기화
 *			- INL_Initialize 호출시 conf_path 사용 하지 않는 경우에 사용.
 *			- 즉, 환경설정 파일 사용하지 않고 로그 남기기 위해 사용.
 * @param	:(char *) log_path: 로그 파일이 생성될 디렉토리
 * @param	:(int) log_level : 0: OFF(default) , 2: FATAL , 3: ERROR , 7: INFO , 8: DEBUG
 * @param	:(char) log_output : F(File), S(Stdout)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Log_Init(char *log_path, int log_level, char log_output);

#ifndef INITECH_ASP
/**
 * @brief	: INISAFE Net 모듈 초기화
 * 			  - 암호 라이브러리 로드
 * 			  - 라이센스 확인 (license_path 우선)
 * 			  - 전역구조체 초기화
 * 			  - 설정 파일에서 파라미터 로드하여 전역구조체에 할당
 *			  - 이 함수는 프로그램/데몬 등 처음 구동될 때 한번만 호출하여 사용
 *			  - 이 함수를 호출 하였으면 프로그램/데몬이 종료 될 때 INL_Clean()을 호출해야함.
 *			  - INL_Clean()을 호출 한 경우 이 함수를 반드시 호출해야함.
 * @param	:(int) type: CTX 형태 (INL_external.h참조)
 * @param	:(char *) conf_path: 설정파일 경로 및 파일 명
 * @param	:(char *) license_path: 라이센스파일 경로 및 파일 명
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Initialize(int type, char *conf_path, char *license_path);
#else
/**
* @brief	: For COM을 위한 Global Context를 사용하기 전에 필요한 사전 작업 실행
* @param	: (CRITICAL_SECTION*) pCsInitialize: 함수 안에서 g_nCTXArrayCount 변수에 동시 접근이 안되도록 처리할 때 사용 
* @return	:(int) 성공=0 또는 에러코드
*/
INISAFENET_INT_API INL_Initialize_Array_Start(CRITICAL_SECTION *pCsInitialize);

/**
 * @brief	: 첫번째 파라미터로 설정한 index에 해당하는 Global Context를 설정하고 초기화
 *            For COM에서는 INL_Initialize 함수의 역할을 대신한다. 
 * 			  - 암호 라이브러리 로드
 * 			  - 라이센스 확인 (license_path 우선)
 * 			  - Global Context 초기화
 * 			  - 설정 파일에서 파라미터 로드하여 전역구조체에 할당
 *			  - 이 함수는 프로그램/데몬 등 처음 구동될 때 한번만 호출하여 사용
 *			  - 이 함수를 호출 하였으면 프로그램/데몬이 종료 될 때 INL_Clean()을 호출해야함.
 *			  - INL_Clean_Ex()을 호출 한 경우 이 함수를 반드시 호출해야함.
 * @param	:(int) ctx_index: Global Context 배열에 저장하고자 하는 index 위치
 * @param	:(int) type: CTX 형태 (INL_external.h참조)
 * @param	:(char *) conf_path: 설정파일 경로 및 파일 명
 * @param	:(char *) license_path: 라이센스파일 경로 및 파일 명
 * @param	:(net_ctx *) ctx_st: 세션정보 구조체
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Initialize_Array_Set(int ctx_index, int type, char *conf_path, char *license_path);

/**
* @brief	: Global Context 배열이 순서대로 할당되었는지 검증  
* @return	:(int) success:0 or error_code
*/
INISAFENET_INT_API INL_Initialize_Array_End(CRITICAL_SECTION *pCsInitialize);
#endif

/**
 * @brief	: INISAFE Net 모듈 초기화
 * 			  - 암호 라이브러리 로드
 * 			  - 라이센스 확인 (license_path 우선)
 * 			  - 전역구조체 초기화
 * 			  - 설정 파일에서 파라미터 로드하여 전역구조체에 할당
 *			  - 이 함수는 프로그램/데몬 등 처음 구동될 때 한번만 호출하여 사용
 *			  - 이 함수를 호출 하였으면 프로그램/데몬이 종료 될 때 INL_Clean()을 호출해야함.
 *			  - INL_Clean_Ex()을 호출 한 경우 이 함수를 반드시 호출해야함.
 * @param	:(int) type: CTX 형태 (INL_external.h참조)
 * @param	:(char *) conf_path: 설정파일 경로 및 파일 명
 * @param	:(char *) license_path: 라이센스파일 경로 및 파일 명
 * @param	:(net_ctx *) ctx_st: 세션정보 구조체
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Initialize_Ex(int type, char *conf_path, char *license_path, net_ctx *ctx);

#ifndef INITECH_ASP
/**
 * @brief	: 로드된 암호 라이브러리 해제, 로그 파일 세션 종료, 전역구조체 초기화
 * 			  - 이 함수는 프로그램/데몬 이 종료될 때 반드시 호출해야함.
 * 			  - 이 함수를 호출한 경우 INL_Initialize()부터 다시 시작해야함.
 * @param	:(void)
 * @return	:(void)
 */
INISAFENET_VOID_API INL_Clean(void);
#else
/**
 * @brief	: Global Context 배열로 가지고 있는 값들을 모두 해제한다.
 * 			  - 이 함수는 asp 페이지에서 직접 호출 할 수 있도록 제공하지 않는다.
 * 			  - 이 함수는 com 모듈이 Unload될 때 모듈 내부에서 호출한다.
 * @param	:(void)
 * @return	:(void)
 */
INISAFENET_VOID_API INL_Clean_Array(void);
#endif

/**
 * @brief	: 로드된 암호 라이브러리 해제, 로그 파일 세션 종료, 전역구조체 초기화
 * 			  - 이 함수는 프로그램/데몬 이 종료될 때 반드시 호출해야함.
 * 			  - 이 함수를 호출한 경우 INL_Initialize()부터 다시 시작해야함.
 * @param	:(net_ctx *) ctx_st: 세션정보 구조체
 * @param	:(void)
 * @return	:(void)
 */
INISAFENET_VOID_API INL_Clean_Ex(net_ctx *ctx);

#ifndef INITECH_ASP
/**
 * @brief	: 받은 구조체 포인터에 메모리를 할당하여 전역구조체에 있던 값을 복사.
 * 			  - 이 함수는 세션 생성시 마다 호출 하여 사용.
 * 			  - 이 함수를 호출하여 생성된 세션을 종료하는 경우 반드시 INL_Free_Ctx()를 호출해야함.
 * @param	:(int) type: CTX type
 * @param	:(net_ctx **) ctx_st: 세션정보 구조체(return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_New_Ctx(int type, net_ctx **ctx);
#else
/**
 * @brief	: 첫번째 파라미터로 전달한 index 값을 사용하여 Global Context 배열에서 지정한 값을 복사
 * 			  - 이 함수는 세션 생성시 마다 호출 하여 사용.
 * 			  - 이 함수를 호출하여 생성된 세션을 종료하는 경우 반드시 INL_Free_Ctx()를 호출해야함.
 * @param	:(int) ctx_index: Global Context 배열에서 복사하고자 하는 값을 나타내는 index
 * @param	:(int) type: CTX type
 * @param	:(net_ctx **) ctx_st: 세션정보 구조체(return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_New_Ctx_From_Array(int ctx_index, int type, net_ctx **ctx);
#endif

/**
 * @brief	: 받은 구조체 포인터에 메모리를 할당하여 전역구조체에 있던 값을 복사.
 * 			  - 이 함수는 세션 생성시 마다 호출 하여 사용.
 * 			  - 이 함수를 호출하여 생성된 세션을 종료하는 경우 반드시 INL_Free_Ctx()를 호출해야함.
 * @param	:(int) type: CTX type
 * @param	:(net_ctx **) ctx_st: 세션정보 구조체(return)
 * @param	:(net_ctx **) ctx_st: 초기화된 세션정보 구조체
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_New_Ctx_Ex(int type, net_ctx **ctx, net_ctx *ctx_init);

/**
 * written by j.k.h 2019.02.19
 * @brief	: 메모리할당된 구조체의 멤버변수(포인터)에 할당된 메모리 해제
 * 			  - net_ctx를 지역변수로 선언한 경우 INL_Free_Ctx 대신 이 함수를 호출해야 함 
 * 			  ( KT 전사암호화 연동 중 요청사항 - net_ctx를 지역변수로 선언하여 사용하려 하나
 * 			    기존 INL_Free_Ctx 함수는 free를 호출하므로 지역변수에 사용할 수 없으며 
 *              해당 함수를 호출하지 않을 경우에는 leak이 발생함)
 * @param	:(net_ctx *) ctx: 세션정보 구조체(return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Clean_Ctx(net_ctx *ctx);

/**
 * modified by j.k.h: 2019.02.19
 * @brief	: 메모리할당된 구조체를 메모리 해제
 * 			  - INL_New_Ctx()함수로 생성된 세션을 종료하는 경우 반드시 이 함수를 호출해야함.
 * @param	:(net_ctx *) ctx: 세션정보 구조체(return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Free_Ctx(net_ctx *ctx);

#ifndef INITECH_ASP
/**
 * @brief	: 암호화 함수
 * 			  - EXT_EXCHGKEY_CTX를 제외한 모든 CTX_TYPE은 이 함수로 암호화
 * @param	:(net_ctx *) ctx: 세션정보 구조체
 * @param	:(unsigned char *) pt: 암호화할 평문
 * @param	:(int) pt_len: 평문의 길이
 * @param	:(unsigned char **) ct: 암호문 (return)
 * @param	:(int *) ct_len: 암호문의 길이 (return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Encrypt(net_ctx *ctx, unsigned char *pt, int pt_len, unsigned char **ct, int *ct_len);
#else
/**
 * @brief	: 지정된 Global Context를 사용하여 암호화하는 함수
 * 			  - EXT_EXCHGKEY_CTX를 제외한 모든 CTX_TYPE은 이 함수로 암호화
 * @param	:(int) ctx_index: 배열에서 원하는 Global Context를 찾기 위한 index
 * @param	:(net_ctx *) ctx: 세션정보 구조체
 * @param	:(unsigned char *) pt: 암호화할 평문
 * @param	:(int) pt_len: 평문의 길이
 * @param	:(unsigned char **) ct: 암호문 (return)
 * @param	:(int *) ct_len: 암호문의 길이 (return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Encrypt_Array(int ctx_index, net_ctx *ctx, unsigned char *pt, int pt_len, unsigned char **ct, int *ct_len);
#endif

/**
 * @brief	: 암호화 함수
 * 			  - EXT_EXCHGKEY_CTX를 제외한 모든 CTX_TYPE은 이 함수로 암호화
 * @param	:(net_ctx *) ctx: 세션정보 구조체
 * @param	:(unsigned char *) pt: 암호화할 평문
 * @param	:(int) pt_len: 평문의 길이
 * @param	:(unsigned char **) ct: 암호문 (return)
 * @param	:(int *) ct_len: 암호문의 길이 (return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Encrypt_Ex(net_ctx *ctx, net_ctx *ctx_init, unsigned char *pt, int pt_len, unsigned char **ct, int *ct_len);

#ifndef INITECH_ASP
/**
 * @brief	: 복호화 함수
 * 			  - EXT_EXCHGKEY_CTX를 제외한 모든 CTX_TYPE은 이 함수로 복호화
 * @param	:(net_ctx *) ctx: 세션정보 구조체
 * @param	:(unsigned char *) ct: 복호화할 암호문
 * @param	:(int) ct_len: 암호문의 길이
 * @param	:(unsigned char **) pt: 복호화된 평문 (return)
 * @param	:(int *) pt_len: 평문의 길이 (return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Decrypt(net_ctx *ctx, unsigned char *ct, int ct_len, unsigned char **pt, int *pt_len);
#else
/**
 * @brief	: 첫번째 파라미터로 받은 index를 사용하여 배열에서 원하는 Global Context를 찾아서 복호화를 시도하는 함수
 * 			  - EXT_EXCHGKEY_CTX를 제외한 모든 CTX_TYPE은 이 함수로 복호화
 * @param	:(net_ctx *) ctx: 세션정보 구조체
 * @param	:(unsigned char *) ct: 복호화할 암호문
 * @param	:(int) ct_len: 암호문의 길이
 * @param	:(unsigned char **) pt: 복호화된 평문 (return)
 * @param	:(int *) pt_len: 평문의 길이 (return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Decrypt_Array(int ctx_index, net_ctx *ctx, unsigned char *ct, int ct_len, unsigned char **pt, int *pt_len);
#endif

/**
 * @brief	: 복호화 함수
 * 			  - EXT_EXCHGKEY_CTX를 제외한 모든 CTX_TYPE은 이 함수로 복호화
 * @param	:(net_ctx *) ctx: 세션정보 구조체
 * @param	:(unsigned char *) ct: 복호화할 암호문
 * @param	:(int) ct_len: 암호문의 길이
 * @param	:(unsigned char **) pt: 복호화된 평문 (return)
 * @param	:(int *) pt_len: 평문의 길이 (return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Decrypt_Ex(net_ctx *ctx, net_ctx *ctx_init, unsigned char *ct, int ct_len, unsigned char **pt, int *pt_len);

#ifndef INITECH_ASP
/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_Encrypt_ex(int type, net_ctx *ctx, unsigned char *pt, int pt_len, unsigned char **ct, int *ct_len);

/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_Decrypt_ex(int type, net_ctx *ctx, unsigned char *ct, int ct_len, unsigned char **pt, int *pt_len);
#endif

#ifndef INITECH_ASP
/**
 * @brief	: INIT_HANDSHAKE
 * 			  - client와 server간의 random 및 알고리즘 교환
 * @param	:(net_ctx *)ctx: 세션정보 구조체
 * @param	:(char *)in: CLIENT_CTX => NULL
 *                       SERVER_CTX => 클라이언트로부터 받은 INL_Handshake_Init(CLIENT)의 결과 메시지
 * @param	:(int) inl: CLIENT_CTX =>  0
 *                      SERVER_CTX => 'in'변수에 담겨진 데이터의 길이
 * @param	:(unsigned char **)out: HANDSHAKE_INIT 전문(return)
 * @param	:(int *)outl:HANDSHAKE_INIT 전문의 길이(return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Handshake_Init(net_ctx *ctx, unsigned char *in, int in_len, unsigned char **out, int *out_len);
#else
/**
 * @brief	: 첫번째 파라미터로 들어오는 index를 사용하여 배열에서 Global Contex를 찾아서 Handshake 초기화
 * 			  - client와 server간의 random 및 알고리즘 교환
 * @param	:(net_ctx *)ctx: 세션정보 구조체
 * @param	:(char *)in: CLIENT_CTX => NULL
 *                       SERVER_CTX => 클라이언트로부터 받은 INL_Handshake_Init(CLIENT)의 결과 메시지
 * @param	:(int) inl: CLIENT_CTX =>  0
 *                      SERVER_CTX => 'in'변수에 담겨진 데이터의 길이
 * @param	:(unsigned char **)out: HANDSHAKE_INIT 전문(return)
 * @param	:(int *)outl:HANDSHAKE_INIT 전문의 길이(return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API  INL_Handshake_Init_Array(int ctx_index, net_ctx *ctx, unsigned char *in, int inl, unsigned char **out, int* outl);
#endif

/**
 * @brief	: INIT_HANDSHAKE
 * 			  - client와 server간의 random 및 알고리즘 교환
 * @param	:(net_ctx *)ctx: 세션정보 구조체
 * @param	:(char *)in: CLIENT_CTX => NULL
 *                       SERVER_CTX => 클라이언트로부터 받은 INL_Handshake_Init(CLIENT)의 결과 메시지
 * @param	:(int) inl: CLIENT_CTX =>  0
 *                      SERVER_CTX => 'in'변수에 담겨진 데이터의 길이
 * @param	:(unsigned char **)out: HANDSHAKE_INIT 전문(return)
 * @param	:(int *)outl:HANDSHAKE_INIT 전문의 길이(return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Handshake_Init_Ex(net_ctx *ctx, net_ctx *ctx_init, unsigned char *in, int in_len, unsigned char **out, int *out_len);

#ifndef INITECH_ASP
/**
 * @brief	: UPDATE_HANDSHAKE
 * 			  - 세션키 교환 및 확인
 * @param	:(net_ctx *)ctx: 세션정보 구조체
 * @param	:(char *)in: CLIENT_CTX => 서버로부터 받은 INL_Handshake_Init(SERVER)의 결과 메시지
 *                       SERVER_CTX => 클라이언트로 부터 받은 INL_Handshake_Update(CLIENT)의 결과 메시지
 * @param	:(int) inl: 'in'변수에 담겨진 데이터의 길이
 * @param	:(unsigned char **)out: HANDSHAKE_UPDATE 전문(return)
 * @param	:(int *)outl:HANDSHAKE_UPDATE 전문의 길이(return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Handshake_Update(net_ctx *ctx, unsigned char *in, int in_len, unsigned char **out, int *out_len);
#else
/**
 * @brief	: 첫번째 파라미터로 index 값을 받아서 원하는 Global Context를 찾아서 Handshake Update 처리
 * 			  - 세션키 교환 및 확인
 * @param	:(int)ctx_index: 찾고자 하는 Global Context를 나타내는 index
 * @param	:(net_ctx *)ctx: 세션정보 구조체
 * @param	:(char *)in: CLIENT_CTX => 서버로부터 받은 INL_Handshake_Init(SERVER)의 결과 메시지
 *                       SERVER_CTX => 클라이언트로 부터 받은 INL_Handshake_Update(CLIENT)의 결과 메시지
 * @param	:(int) inl: 'in'변수에 담겨진 데이터의 길이
 * @param	:(unsigned char **)out: HANDSHAKE_UPDATE 전문(return)
 * @param	:(int *)outl:HANDSHAKE_UPDATE 전문의 길이(return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API  INL_Handshake_Update_Array(int ctx_index, net_ctx* ctx, unsigned char* in, int inl, unsigned char** out, int* outl);
#endif

/**
 * @brief	: UPDATE_HANDSHAKE
 * 			  - 세션키 교환 및 확인
 * @param	:(net_ctx *)ctx: 세션정보 구조체
 * @param	:(char *)in: CLIENT_CTX => 서버로부터 받은 INL_Handshake_Init(SERVER)의 결과 메시지
 *                       SERVER_CTX => 클라이언트로 부터 받은 INL_Handshake_Update(CLIENT)의 결과 메시지
 * @param	:(int) inl: 'in'변수에 담겨진 데이터의 길이
 * @param	:(unsigned char **)out: HANDSHAKE_UPDATE 전문(return)
 * @param	:(int *)outl:HANDSHAKE_UPDATE 전문의 길이(return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Handshake_Update_Ex(net_ctx *ctx, net_ctx *ctx_init, unsigned char *in, int in_len, unsigned char **out, int *out_len);

/**
 * @brief	: FINAL_HANDSHAKE
 * 			  - 교환된 세션키로 샘플메시지 암/복호화 확인
 * @param	:(net_ctx *)ctx: 세션정보 구조체
 * @param	:(char *)in: CLIENT_CTX => 서버로부터 받은 INL_Handshake_Update(SERVER)의 결과 메시지
 *                       SERVER_CTX => 클라이언트로 부터 받은 INL_Handshake_Final(CLIENT)의 결과 메시지
 * @param	:(int) inl: 'in'변수에 담겨진 데이터의 길이
 * @param	:(unsigned char **)out: CLIENT_CTX => HANDSHAKE_FINAL 전문(return)
 *                                  SERVER_CTX => NULL
 * @param	:(int *)outl: CLIENT_CTX => HANDSHAKE_FINAL 전문의 길이(return)
 * 						  SERVER_CTX => 0
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Handshake_Final(net_ctx *ctx, unsigned char *in, int in_len, unsigned char **out, int *out_len);

/**
 * @brief	: ctx구조체에 encoding flag 설정
 * @param	:(net_ctx *) ctx: 세션정보 구조체
 * @param	:(char *) enc_flag: 인코딩 플래그 (0000|0001|0010|0011)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Set_Encode_Flag(net_ctx *ctx, char *enc_flag);


/**
 * @brief	: ctx구조체에 IV 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) iv (input)
 * @param	: (int) iv_len: 'iv'의 길이 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Set_IV(net_ctx *ctx, unsigned char *iv, int iv_len);

/**
 * @brief	: ctx구조체에 세션키 전용 해시 알고리즘 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) DigestName: 해시 알고리즘 (input)
 * @param	: (int) HA_len: 'DigestName'변수의 길이 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Set_Hash_Algorithm(net_ctx *ctx, char *DigestName, int HA_len);

/**
 * @brief	: ctx구조체에 세션키 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) key: 세션키 (input)
 * @param	: (int) keylen: 세션키 길이 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Set_Session_Key(net_ctx *ctx, unsigned char *key, int keylen);

/**
 * @brief	: ctx구조체에 대칭키 암호화 알고리즘 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (char *) ciphername: 암호 알고리즘+모드 (input)
 * @param	: (int) len: length of 'ciphername' (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Set_Crypto_Algorithm( net_ctx *ctx, char *ciphername, int len );

/**
 * @brief	: 파일로부터 서버 인증서 스트링 읽어 ctx구조체에 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (char *) svr_cert_path: 서버 인증서 경로+파일명 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_SetServerCertFile(net_ctx *ctx, char *svr_cert_path);

/**
 * @brief	: 파일로부터 클라이언트 인증서 스트링 읽어 ctx구조체에 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (char *) cli_cert_path: 클라이언트 인증서 경로+파일명 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_SetClientCertFile(net_ctx *ctx, char *cli_cert_path);

/**
 * @brief	: 파일로부터 개인키 스트링 읽어 ctx구조체에 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (char *) privkey_path: 개인키 파일 경로+파일명 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_SetPrivKeyFile(net_ctx *ctx, char *privkey_path);

/**
 * @brief	: ctx구조체에 암호화된 개인키 패스워드 스트링 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (char *) EncPkeyPass: 암호화된 개인키 패스워드 스트링(input)
 * @param	: (int) passlen: 암호화된 개인키 패스워드의 길이 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_SetPrivKeyPass( net_ctx *ctx, char *EncPkeyPass, int passlen );

/**
 * @brief	: ctx구조체에 입력받은 개인키 패스워드를 암호화 하여 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (char *) pkeyPass: 암호화되지 않은 개인키 패스워드 스트링(input)
 * @param	: (int) passlen: 개인키 패스워드의 길이 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_SetPrivKeyPasswd( net_ctx *ctx, char *pkeyPass, int passlen );


/**
 * @brief   : handshake 인코딩 플래그를 ctx구조체에 설정
 * @param   : (net_ctx *) ctx: 세션정보 구조체
 * @param   : (char *) hs_enc: 핸드쉐이크 인코딩 플래그 (input)
 * @return  : (int) success:0 or error_code
 */
INISAFENET_INT_API INL_SetHSEncFlag( net_ctx *ctx, char *hs_encflag );



/**
 * @brief   : handshake 클라이언트 버전을 ctx 구조체에 설정
 * @param   : (net_ctx *) ctx: 세션정보 구조체
 * @param   : (char *) hs_cli_ver: handshake client version
 * @return  : (int) success:0 or error_code
 */
INISAFENET_INT_API INL_SetClientVer( net_ctx *ctx, char *hs_cli_ver);

/**
 * @brief   : handshake 요청할 server cert type 을 설정.
 * @param   : (net_ctx *) ctx: 세션정보 구조체 (input)
 * @param   : (char *) type : 요청할 server cert type. ("CERT"/"KEY") (input)
 * @return  : (int) success:0 or error_code
 */
INISAFENET_INT_API INL_Set_SCert_Type_Req( net_ctx *ctx, char *type);
/**
 * @brief	:
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (char *) file_path: 세션키파일을 읽은 스트링 (input)
 * @param	: (char *) password: 세션키파일 복호화 하기 위한 패스워드 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Set_Skey_IV_File(net_ctx *ctx, char *file_path, char *password);

/**
 * @brief	:
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (int) use_flag: 세션키를 해쉬하여 사용할 것인지 여부.
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Set_Hashed_Key_Use(net_ctx *ctx, int use_flag);

/**
 * @brief	: 파일로부터 세션키+IV 읽어 ctx 구조체에 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (char *) key_string: 세션키파일을 읽은 스트링 (input)
 * @param	: (char *) password: 세션키파일 복호화 하기 위한 패스워드 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Load_Session_Key(net_ctx *ctx, char *key_string, int key_string_len, char *password, int password_len);

/**
 * @brief   : 암호화된 세션키를 복호화할 비밀번호 설정
 * @param   :
 * (net_ctx *) ctx: 세션정보 구조체
 * @param   : (unsigned char *) passwd :encrypted Session key password (input)
 * @param   : (int) passwdlen: length of 'passwd' (input)
 * @return  : (int) 성공=0 또는 에러코드
*/
INISAFENET_INT_API INL_Set_Encrypt_Skey_Passwd(net_ctx *ctx, unsigned char *passwd, int passwdlen);


/**
 * @brief	: Hex값으로 표준 출력
 * @param	:(FILE) out: stdout,stderr,FILE...
 * @param	:(char *) content: value
 * @param	:(int) len: length of value
 * @return	:(void)
 */
INISAFENET_VOID_API INL_HexaDump(FILE *out, char *content, int len);

/**
 * @brief	: 메모리 할당된 포인터를 해제
 * @param	:(unsigned char *) p: NET모듈에서 malloc했던 포인터
 * @return	:(void)
 */
INISAFENET_VOID_API INL_Free_Buf(unsigned char *p);

/**
 * @brief   : Free allocated pointer
 * @param   :(unsigned char *) p: pointer
 * @param   :(int ) len: len byte clear
 * @return  :(void)
 */
INISAFENET_VOID_API INL_Free(unsigned char *p, int len);

/**
 * @brief	: 개인키로 데이터 암호화하여 서명
 * @param	:(net_ctx *) ctx: 세션정보 구조체
 * @param	:(unsigned char *) in: 서명하기 위한 데이터
 * @param	:(int) inl: 데이터의 길이
 * @param	:(unsigned char **) out: 서명된 데이터 (return)
 * @param	:(int *) outl: 서명된 데이터의 길이 (return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_I_Sign(net_ctx *ctx, unsigned char *in, int inl, unsigned char** out, int *outl);

/**
 * @brief	: 공개키로 서명된 데이터 확인
 * @param	:(net_ctx *) ctx: 세션정보 구조체
 * @param	:(unsigned char *) org_data: 서명 전 원본 데이터
 * @param	:(int) org_data_len: 서명 전 원본 데이터의 길이
 * @param	:(unsigned char *) sig_data: 서명 된 데이터 (return)
 * @param	:(int *) sig_data_len: 서명 된 데이터의 길이 (return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_I_VerifySign(net_ctx *ctx, unsigned char *org_data, int org_data_len, unsigned char *sig_data, int sig_data_len);

/**
 * @brief	: ctx구조체에 base64인코딩시 linefeed삽입 여부 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (int) flag (0:삭제, 1:삽입)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Set_Base64flag( net_ctx *ctx, int flag );

/**
 * @brief	: ctx구조체에 서버 인증서 스트링 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) svr_cert: 서버 인증서 스트링(input)
 * @param	: (int) svr_cert: 서버 인증서 스트링의 길이 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_SetServerCert(net_ctx *ctx, char *svr_cert, int certlen);

/**
 * @brief	: ctx구조체에 클라이언트 인증서 스트링 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) 클라이언트 인증서 스트링 (input)
 * @param	: (int) certlen: 클라이언트 인증서 스트링의 길이 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_SetClientCert(net_ctx *ctx, char *cli_cert, int certlen);

/**
 * @brief	: ctx구조체에 CA 인증서 스트링 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) ca_cert: CA 인증서 스트링(input)
 * @param	: (int) certlen: CA 인증서 스트링의 길이 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_SetCACert(net_ctx *ctx, char *ca_cert, int certlen);

/**
 * @brief	: IssuerDN value set.
 * @param	: (net_ctx *) ctx: ctx structure
 * @param	: (char *) issuerdn (input)
 * @return	: (int) success:0 or error_code
 */
INISAFENET_INT_API INL_SetIssuerDN(net_ctx *ctx, char *issuerdn);

/**
 * @brief	: ctx구조체에 개인키 스트링 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) 개인키 스트링 (input)
 * @param	: (int) keylen: 개인키 스트링의 길이 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_SetPrivKey(net_ctx *ctx, unsigned char *privkey, int keylen);

/**
 * @brief	: 세션키 생성
 * @param	: (unsigned char *) sessionkey : 세션키[16] (return)
 * @return	: (void)
 */
INISAFENET_VOID_API INL_gen_sessionkey(unsigned char *sessionkey);

/**
 * @brief	: 세션키 생성하여 공개키로 암호화
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char **) encskey :encrypted Session key (return)
 * @param	: (int) encskey: length of 'encskey' (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Encrypt_Skey(net_ctx *ctx, unsigned char **encskey, int *encskeylen);

/**
 * @brief	: 개인키로 세션키 복호화
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char **) encskey :encrypted Session key (return)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Decrypt_Skey(net_ctx *ctx, unsigned char *encskey);

/**
 * @brief	: 압축->암호화->base128 encoding
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) in : text (input)
 * @param	: (int) inl: length of 'in' (input)
 * @param	: (unsigned char **) out: encrypt result value (return)
 * @param	: (int *) outl: length of 'out' (return)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Encrypt_Data(net_ctx *ctx, unsigned char *in, int inl, unsigned char** out, int *outl);

/**
 * @brief	: base128 decoding -> 복호화 -> 압축해제
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) in : text (input)
 * @param	: (int) inl: length of 'in' (input)
 * @param	: (unsigned char **) out: decrypt result value (return)
 * @param	: (int *) outl: length of 'out' (return)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Decrypt_Data(net_ctx *ctx, unsigned char *in, int inl, unsigned char** out, int *outl);

/**
 * @brief	: (공개키로 암호화된 세션키+압축후 암호화된 데이터) 생성
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) in : text (input)
 * @param	: (int) inl: length of 'in' (input)
 * @param	: (unsigned char **) out: encrypt result value (return)
 * @param	: (int *) outl: length of 'out' (return)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Encrypt_Ext(net_ctx *ctx, unsigned char *in, int inl, unsigned char** out, int *outl);

/**
 * @brief	: (개인키로 복호화된 세션키+복호화후 압축해제 된 데이터) 추출
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) in : text (input)
 * @param	: (int) inl: length of 'in' (input)
 * @param	: (unsigned char **) out: decrypt result value (return)
 * @param	: (int *) outl: length of 'out' (return)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Decrypt_Ext(net_ctx *ctx, unsigned char *in, int inl, unsigned char** out, int *outl);

/**
 * @brief	: 세션키 생성 후 공개키로 암호화, 암호문은 평문길이 만큼 패딩
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (int) datalen : loop count (input)
 * @param	: (unsigned char **) encskey: encrypted session key (return)
 * @param	: (int *) encskeylen: length of 'encskey' (return)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Encrypt_Skey_FTP(net_ctx* ctx, int datalen, unsigned char** encskey, int* encskeylen );

/**
 * @brief	: 개인키로 복호화 하여 세션키 추출
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) encskey: encrypted session key (input)
 * @param	: (int *) encskeylen: length of 'encskey' (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Decrypt_Skey_FTP(net_ctx* ctx, unsigned char* encskey, int encskeylen);

/**
 * @brief	: 파일에서 평문 읽어 암호화 한 후 파일에 암호문 기록
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (char *) infile: Read file path (input)
 * @param	: (int *) outfile: Save the file path (input)
 * @param	: (int *) outcnt: outfile line (return)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Encrypt_FTP(net_ctx *ctx, char *infile, char *outfile, long *outcnt);

/**
 * @brief	: 파일에서 암호문 읽어 복호화 한 후 파일에 평문 기록
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (char *) infile: Read file path (input)
 * @param	: (int *) outfile: Save the file path (input)
 * @param	: (int *) outcnt: outfile line (return)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Decrypt_FTP(net_ctx *ctx, char *infile, char *outfile, long *outcnt);

/**
 * @brief	: 대칭키 알고리즘에서 OFB모드 일경우 암호화 하는 함수
 * 			  - encrypt를 두번 한 경우 평문이 노출되는 경우 방지
 * @param	:(net_ctx *) ctx: 세션정보 구조체
 * @param	:(unsigned char *) indata: plain text
 * @param	:(int) indatalen: length of plain text
 * @param	:(unsigned char **) outdata: cipher text (return)
 * @param	:(int *) outdatalen: length of cipher text (return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Mask_Encrypt(net_ctx *ctx, unsigned char *indata, int indatalen, unsigned char** outdata, int *outdatalen);

/**
 * @brief	:대칭키 알고리즘에서 OFB모드 일경우 복호화 하는 함수
 * 			  - encrypt를 두번 한 경우 평문이 노출되는 경우 방지
 * @param	:(net_ctx *) ctx: 세션정보 구조체
 * @param	:(unsigned char *) indata: cipher text
 * @param	:(int) indatalen: length of cipher text
 * @param	:(unsigned char **) outdata: plain text (return)
 * @param	:(int *) outdatalen: length of plain text (return)
 * @return	:(int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Mask_Decrypt(net_ctx *ctx, unsigned char *indata, int indatalen, unsigned char** outdata, int *outdatalen);

/**
 * @brief	: 구조체로부터 세션키를 추출하여 반환
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) s_key: session-key value. buffer size have to larger than 16.(return)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Get_Session_Key(net_ctx *ctx, unsigned char *s_key);

/**
 * @brief	: 메시지 해쉬값을 반환
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) s_key: session-key value. buffer size have to larger than 16.(return)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_Message_Digest(char *hash_alg ,unsigned char *in, int inl, unsigned char **hash_data, int *hash_len);

/**
 * @brief	: 구조체로부터 세션키를 추출하여 반환
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (unsigned char *) s_key: session-key value. buffer size have to larger than 16.(return)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_HMAC(char *hmac_alg, unsigned char *in, unsigned int inlen, unsigned char *key, unsigned int keylen, unsigned char **out, unsigned int *outlen );

/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_VOID_API INL_Pass_Verify_Module();

#ifdef NIS_CRYPTO_PRODUCT_LOG
/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_Mini_Log_Init(char *path);

/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_VOID_API INL_Mini_Log_Close();
#endif

/**
 *  @brief  : INISAFE Net NTP AE±aE­
 *  @param  : (char *) ntp_ip: NTP server ip (default 적용시 NULL )
 *  @param  : (int) ntp_port : NTP server port (default 적용시 0)
 *  @return : (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_NTP_Init(char *ntp_ip, int ntp_port);

/**
 *  @brief  : INISAFE Net NTP Close
 *  @return : (void)
 */
INISAFENET_VOID_API INL_NTP_Close(void);

/**
 * @brief	: ctx구조체에 무결성 검증 옵션 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (char *) integrity_check : 무결성 검증 Flag (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_SetIntegrityCheck( net_ctx *ctx, char *integrity_check );

/**
 * @brief	: ctx구조체에 랜덤 패딩 길이 설정
 * @param	: (net_ctx *) ctx: 세션정보 구조체
 * @param	: (char *) ranpad_len : 랜던 패딩 길이 (input)
 * @return	: (int) 성공=0 또는 에러코드
 */
INISAFENET_INT_API INL_SetRandomPaddingLen( net_ctx *ctx, int ranpad_len );

/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_Copy_Ctx(net_ctx *to_ctx, net_ctx *from_ctx, int lock_flag);

/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_SetKeyID(net_ctx *ctx, int keytype, char *kid, int kid_len );

/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_SetPubKeyWithHSM(net_ctx *ctx);

/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_SetPrivKeyWithHSM(net_ctx *ctx);

/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_GetSymmKeyWithHSM(net_ctx *ctx);


/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_Check_Renew_Date(int renew_term, time_t last_time);

/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_ReNewSymmKeyWithHSM(net_ctx *ctx);

/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_Exchange_Pubkey_REQ( net_ctx *ctx, unsigned char **out, int *outl);

/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_Exchange_Pubkey_REP( net_ctx *ctx, unsigned char *in, int inl, unsigned char **out, int *outl);

/**
 * @brief	: 
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_Exchange_Set_Pubkey( net_ctx *ctx, unsigned char *in, int inl);

/**
 * @brief	: Check and update
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_CheckKeyExpInitCtx(char *out_update_flag);

/**
 * @brief	: Check and update
 * @param	: 
 * @return	: 
 */
INISAFENET_INT_API INL_CheckKeyExpInitCtx_Ex(net_ctx *ctx_init, char *out_update_flag);



#ifdef  __cplusplus
}
#endif /*#ifdef  __cplusplus*/

#endif /* INL_EXTERNAL_H_ */
