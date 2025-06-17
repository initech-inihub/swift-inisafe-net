/**
 *	@file	: INL_external.h
 *	@brief	  �Լ����� ����� �������
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
	/* VS2008 ���� ���������� �ʿ��� �� ������ VS2008������ ���� �Լ� ����� �����ؼ� ��� ���� */
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
 * @brief	��/��ȣȭ�� ���������� ���� �ִ� ����ü
 *			- ���� ���� �� �������Ͽ��� �ε�� ���� ����ü�� �Ҵ�
 *			- ���� ���� �� INL_Free_Ctx() �Ҵ�� �޸� ����
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
	
	/* advance blockcipher ��� ���� �߰� */
	int use_adv_blockcipher;
	int init_adv_enc;
	int init_adv_dec;
	unsigned char initd_enc_key[4400];
	int initd_enc_keylen;
	unsigned char initd_dec_key[4400];
	int initd_dec_keylen;

	char cert_type[4+1];

	/* paccel ���� ���� �߰� */
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
	int hsm_num; /* hsm ���� */
	ISP_ADDRESS hsm_address[INL_MAX_HSM_NUM]; /* hsm ip/port �������� */
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
    
	/* exchange adv ���� ����� secret key */
	unsigned char ex_salt[INL_SALT_SIZE+1];
	int ex_salt_len;

	/* exchange adv ���� ����� random */
	unsigned char ex_random[INL_RAND_LEN+1];

	/* Ű ���� �ֱ� */
	int key_renew_term;

	/* Ŭ���̾�Ʈ ������ ���� ��� ���� */
	int view_ccert;

	/*For Windows*/
#ifdef _WIN32
	char hsm_libpath[LEN_KEY_FILE+1];

	/*======================================================================================================
	 For COM�� ���, ���� Thread���� ���� ������ �����ϹǷ� Global ������ ����� ������ ������ �� �ִ�.
	   ����, net_ctx ����ü�� ����� �����ؼ� Global Context�� ���� �����Ͽ� ����ؾ� ������ ���� 
    ======================================================================================================*/
	CRITICAL_SECTION csGlobalContext; /* INL_Initialize���� �����ϴ� Global Context ������ �ϳ��� Thread�� ������ �� �ֵ��� ó���ϱ� ���� Critical Section*/
	CRITICAL_SECTION csCopyContext;	  /* Context ������ �� �ϳ��� Thread�� ������ �� �ֵ��� ó���ϱ� ���� Critical Section*/
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
extern CRITICAL_SECTION g_csFileAccess;    /* atlINISafeNet.cpp�� Global ������ ����� Critical Section ��ü�� �ٸ� �������� ����ϱ� ���ؼ� ���� */
#endif
    

/*** Function Declaration ***/
/**
 * @brief	: INISAFE Net�� ���� ��ǰ ������ ǥ�����
 * @param	:(void)
 * @return	:(void)
 */
INISAFENET_VOID_API INL_Get_Version(void);

/**
 * @brief	: ������ �����ڵ� ��ȯ
 * @param	:(void)
 * @return	:(int) �����ڵ�
 */
INISAFENET_INT_API INL_GetLastError(void);

/**
 * @brief	: �����ڵ忡 ���� ���ڿ� ��ȯ
 * @param	:(int) error_code: ���� �ڵ�
 * @return	:(char *) �����ڵ忡 �ش��ϴ� �����޽���
 */
INISAFENET_CHAR_API INL_Error_String(int error_code);

/**
 * @brief       : ��ȣ��� ��� ��带 ����� ���� ����
 *                (�����˰��� + ������˰��� ��� ����)
 * @param       :(void)
 * @return      :(void)
 */
INISAFENET_VOID_API INL_Change_Non_Proven(void);

/**
 * @brief	: INISAFE Net �α� �ʱ�ȭ
 *			- INL_Initialize ȣ��� conf_path ��� ���� �ʴ� ��쿡 ���.
 *			- ��, ȯ�漳�� ���� ������� �ʰ� �α� ����� ���� ���.
 * @param	:(char *) log_path: �α� ������ ������ ���丮
 * @param	:(int) log_level : 0: OFF(default) , 2: FATAL , 3: ERROR , 7: INFO , 8: DEBUG
 * @param	:(char) log_output : F(File), S(Stdout)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Log_Init(char *log_path, int log_level, char log_output);

#ifndef INITECH_ASP
/**
 * @brief	: INISAFE Net ��� �ʱ�ȭ
 * 			  - ��ȣ ���̺귯�� �ε�
 * 			  - ���̼��� Ȯ�� (license_path �켱)
 * 			  - ��������ü �ʱ�ȭ
 * 			  - ���� ���Ͽ��� �Ķ���� �ε��Ͽ� ��������ü�� �Ҵ�
 *			  - �� �Լ��� ���α׷�/���� �� ó�� ������ �� �ѹ��� ȣ���Ͽ� ���
 *			  - �� �Լ��� ȣ�� �Ͽ����� ���α׷�/������ ���� �� �� INL_Clean()�� ȣ���ؾ���.
 *			  - INL_Clean()�� ȣ�� �� ��� �� �Լ��� �ݵ�� ȣ���ؾ���.
 * @param	:(int) type: CTX ���� (INL_external.h����)
 * @param	:(char *) conf_path: �������� ��� �� ���� ��
 * @param	:(char *) license_path: ���̼������� ��� �� ���� ��
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Initialize(int type, char *conf_path, char *license_path);
#else
/**
* @brief	: For COM�� ���� Global Context�� ����ϱ� ���� �ʿ��� ���� �۾� ����
* @param	: (CRITICAL_SECTION*) pCsInitialize: �Լ� �ȿ��� g_nCTXArrayCount ������ ���� ������ �ȵǵ��� ó���� �� ��� 
* @return	:(int) ����=0 �Ǵ� �����ڵ�
*/
INISAFENET_INT_API INL_Initialize_Array_Start(CRITICAL_SECTION *pCsInitialize);

/**
 * @brief	: ù��° �Ķ���ͷ� ������ index�� �ش��ϴ� Global Context�� �����ϰ� �ʱ�ȭ
 *            For COM������ INL_Initialize �Լ��� ������ ����Ѵ�. 
 * 			  - ��ȣ ���̺귯�� �ε�
 * 			  - ���̼��� Ȯ�� (license_path �켱)
 * 			  - Global Context �ʱ�ȭ
 * 			  - ���� ���Ͽ��� �Ķ���� �ε��Ͽ� ��������ü�� �Ҵ�
 *			  - �� �Լ��� ���α׷�/���� �� ó�� ������ �� �ѹ��� ȣ���Ͽ� ���
 *			  - �� �Լ��� ȣ�� �Ͽ����� ���α׷�/������ ���� �� �� INL_Clean()�� ȣ���ؾ���.
 *			  - INL_Clean_Ex()�� ȣ�� �� ��� �� �Լ��� �ݵ�� ȣ���ؾ���.
 * @param	:(int) ctx_index: Global Context �迭�� �����ϰ��� �ϴ� index ��ġ
 * @param	:(int) type: CTX ���� (INL_external.h����)
 * @param	:(char *) conf_path: �������� ��� �� ���� ��
 * @param	:(char *) license_path: ���̼������� ��� �� ���� ��
 * @param	:(net_ctx *) ctx_st: �������� ����ü
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Initialize_Array_Set(int ctx_index, int type, char *conf_path, char *license_path);

/**
* @brief	: Global Context �迭�� ������� �Ҵ�Ǿ����� ����  
* @return	:(int) success:0 or error_code
*/
INISAFENET_INT_API INL_Initialize_Array_End(CRITICAL_SECTION *pCsInitialize);
#endif

/**
 * @brief	: INISAFE Net ��� �ʱ�ȭ
 * 			  - ��ȣ ���̺귯�� �ε�
 * 			  - ���̼��� Ȯ�� (license_path �켱)
 * 			  - ��������ü �ʱ�ȭ
 * 			  - ���� ���Ͽ��� �Ķ���� �ε��Ͽ� ��������ü�� �Ҵ�
 *			  - �� �Լ��� ���α׷�/���� �� ó�� ������ �� �ѹ��� ȣ���Ͽ� ���
 *			  - �� �Լ��� ȣ�� �Ͽ����� ���α׷�/������ ���� �� �� INL_Clean()�� ȣ���ؾ���.
 *			  - INL_Clean_Ex()�� ȣ�� �� ��� �� �Լ��� �ݵ�� ȣ���ؾ���.
 * @param	:(int) type: CTX ���� (INL_external.h����)
 * @param	:(char *) conf_path: �������� ��� �� ���� ��
 * @param	:(char *) license_path: ���̼������� ��� �� ���� ��
 * @param	:(net_ctx *) ctx_st: �������� ����ü
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Initialize_Ex(int type, char *conf_path, char *license_path, net_ctx *ctx);

#ifndef INITECH_ASP
/**
 * @brief	: �ε�� ��ȣ ���̺귯�� ����, �α� ���� ���� ����, ��������ü �ʱ�ȭ
 * 			  - �� �Լ��� ���α׷�/���� �� ����� �� �ݵ�� ȣ���ؾ���.
 * 			  - �� �Լ��� ȣ���� ��� INL_Initialize()���� �ٽ� �����ؾ���.
 * @param	:(void)
 * @return	:(void)
 */
INISAFENET_VOID_API INL_Clean(void);
#else
/**
 * @brief	: Global Context �迭�� ������ �ִ� ������ ��� �����Ѵ�.
 * 			  - �� �Լ��� asp ���������� ���� ȣ�� �� �� �ֵ��� �������� �ʴ´�.
 * 			  - �� �Լ��� com ����� Unload�� �� ��� ���ο��� ȣ���Ѵ�.
 * @param	:(void)
 * @return	:(void)
 */
INISAFENET_VOID_API INL_Clean_Array(void);
#endif

/**
 * @brief	: �ε�� ��ȣ ���̺귯�� ����, �α� ���� ���� ����, ��������ü �ʱ�ȭ
 * 			  - �� �Լ��� ���α׷�/���� �� ����� �� �ݵ�� ȣ���ؾ���.
 * 			  - �� �Լ��� ȣ���� ��� INL_Initialize()���� �ٽ� �����ؾ���.
 * @param	:(net_ctx *) ctx_st: �������� ����ü
 * @param	:(void)
 * @return	:(void)
 */
INISAFENET_VOID_API INL_Clean_Ex(net_ctx *ctx);

#ifndef INITECH_ASP
/**
 * @brief	: ���� ����ü �����Ϳ� �޸𸮸� �Ҵ��Ͽ� ��������ü�� �ִ� ���� ����.
 * 			  - �� �Լ��� ���� ������ ���� ȣ�� �Ͽ� ���.
 * 			  - �� �Լ��� ȣ���Ͽ� ������ ������ �����ϴ� ��� �ݵ�� INL_Free_Ctx()�� ȣ���ؾ���.
 * @param	:(int) type: CTX type
 * @param	:(net_ctx **) ctx_st: �������� ����ü(return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_New_Ctx(int type, net_ctx **ctx);
#else
/**
 * @brief	: ù��° �Ķ���ͷ� ������ index ���� ����Ͽ� Global Context �迭���� ������ ���� ����
 * 			  - �� �Լ��� ���� ������ ���� ȣ�� �Ͽ� ���.
 * 			  - �� �Լ��� ȣ���Ͽ� ������ ������ �����ϴ� ��� �ݵ�� INL_Free_Ctx()�� ȣ���ؾ���.
 * @param	:(int) ctx_index: Global Context �迭���� �����ϰ��� �ϴ� ���� ��Ÿ���� index
 * @param	:(int) type: CTX type
 * @param	:(net_ctx **) ctx_st: �������� ����ü(return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_New_Ctx_From_Array(int ctx_index, int type, net_ctx **ctx);
#endif

/**
 * @brief	: ���� ����ü �����Ϳ� �޸𸮸� �Ҵ��Ͽ� ��������ü�� �ִ� ���� ����.
 * 			  - �� �Լ��� ���� ������ ���� ȣ�� �Ͽ� ���.
 * 			  - �� �Լ��� ȣ���Ͽ� ������ ������ �����ϴ� ��� �ݵ�� INL_Free_Ctx()�� ȣ���ؾ���.
 * @param	:(int) type: CTX type
 * @param	:(net_ctx **) ctx_st: �������� ����ü(return)
 * @param	:(net_ctx **) ctx_st: �ʱ�ȭ�� �������� ����ü
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_New_Ctx_Ex(int type, net_ctx **ctx, net_ctx *ctx_init);

/**
 * written by j.k.h 2019.02.19
 * @brief	: �޸��Ҵ�� ����ü�� �������(������)�� �Ҵ�� �޸� ����
 * 			  - net_ctx�� ���������� ������ ��� INL_Free_Ctx ��� �� �Լ��� ȣ���ؾ� �� 
 * 			  ( KT �����ȣȭ ���� �� ��û���� - net_ctx�� ���������� �����Ͽ� ����Ϸ� �ϳ�
 * 			    ���� INL_Free_Ctx �Լ��� free�� ȣ���ϹǷ� ���������� ����� �� ������ 
 *              �ش� �Լ��� ȣ������ ���� ��쿡�� leak�� �߻���)
 * @param	:(net_ctx *) ctx: �������� ����ü(return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Clean_Ctx(net_ctx *ctx);

/**
 * modified by j.k.h: 2019.02.19
 * @brief	: �޸��Ҵ�� ����ü�� �޸� ����
 * 			  - INL_New_Ctx()�Լ��� ������ ������ �����ϴ� ��� �ݵ�� �� �Լ��� ȣ���ؾ���.
 * @param	:(net_ctx *) ctx: �������� ����ü(return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Free_Ctx(net_ctx *ctx);

#ifndef INITECH_ASP
/**
 * @brief	: ��ȣȭ �Լ�
 * 			  - EXT_EXCHGKEY_CTX�� ������ ��� CTX_TYPE�� �� �Լ��� ��ȣȭ
 * @param	:(net_ctx *) ctx: �������� ����ü
 * @param	:(unsigned char *) pt: ��ȣȭ�� ��
 * @param	:(int) pt_len: ���� ����
 * @param	:(unsigned char **) ct: ��ȣ�� (return)
 * @param	:(int *) ct_len: ��ȣ���� ���� (return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Encrypt(net_ctx *ctx, unsigned char *pt, int pt_len, unsigned char **ct, int *ct_len);
#else
/**
 * @brief	: ������ Global Context�� ����Ͽ� ��ȣȭ�ϴ� �Լ�
 * 			  - EXT_EXCHGKEY_CTX�� ������ ��� CTX_TYPE�� �� �Լ��� ��ȣȭ
 * @param	:(int) ctx_index: �迭���� ���ϴ� Global Context�� ã�� ���� index
 * @param	:(net_ctx *) ctx: �������� ����ü
 * @param	:(unsigned char *) pt: ��ȣȭ�� ��
 * @param	:(int) pt_len: ���� ����
 * @param	:(unsigned char **) ct: ��ȣ�� (return)
 * @param	:(int *) ct_len: ��ȣ���� ���� (return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Encrypt_Array(int ctx_index, net_ctx *ctx, unsigned char *pt, int pt_len, unsigned char **ct, int *ct_len);
#endif

/**
 * @brief	: ��ȣȭ �Լ�
 * 			  - EXT_EXCHGKEY_CTX�� ������ ��� CTX_TYPE�� �� �Լ��� ��ȣȭ
 * @param	:(net_ctx *) ctx: �������� ����ü
 * @param	:(unsigned char *) pt: ��ȣȭ�� ��
 * @param	:(int) pt_len: ���� ����
 * @param	:(unsigned char **) ct: ��ȣ�� (return)
 * @param	:(int *) ct_len: ��ȣ���� ���� (return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Encrypt_Ex(net_ctx *ctx, net_ctx *ctx_init, unsigned char *pt, int pt_len, unsigned char **ct, int *ct_len);

#ifndef INITECH_ASP
/**
 * @brief	: ��ȣȭ �Լ�
 * 			  - EXT_EXCHGKEY_CTX�� ������ ��� CTX_TYPE�� �� �Լ��� ��ȣȭ
 * @param	:(net_ctx *) ctx: �������� ����ü
 * @param	:(unsigned char *) ct: ��ȣȭ�� ��ȣ��
 * @param	:(int) ct_len: ��ȣ���� ����
 * @param	:(unsigned char **) pt: ��ȣȭ�� �� (return)
 * @param	:(int *) pt_len: ���� ���� (return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Decrypt(net_ctx *ctx, unsigned char *ct, int ct_len, unsigned char **pt, int *pt_len);
#else
/**
 * @brief	: ù��° �Ķ���ͷ� ���� index�� ����Ͽ� �迭���� ���ϴ� Global Context�� ã�Ƽ� ��ȣȭ�� �õ��ϴ� �Լ�
 * 			  - EXT_EXCHGKEY_CTX�� ������ ��� CTX_TYPE�� �� �Լ��� ��ȣȭ
 * @param	:(net_ctx *) ctx: �������� ����ü
 * @param	:(unsigned char *) ct: ��ȣȭ�� ��ȣ��
 * @param	:(int) ct_len: ��ȣ���� ����
 * @param	:(unsigned char **) pt: ��ȣȭ�� �� (return)
 * @param	:(int *) pt_len: ���� ���� (return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Decrypt_Array(int ctx_index, net_ctx *ctx, unsigned char *ct, int ct_len, unsigned char **pt, int *pt_len);
#endif

/**
 * @brief	: ��ȣȭ �Լ�
 * 			  - EXT_EXCHGKEY_CTX�� ������ ��� CTX_TYPE�� �� �Լ��� ��ȣȭ
 * @param	:(net_ctx *) ctx: �������� ����ü
 * @param	:(unsigned char *) ct: ��ȣȭ�� ��ȣ��
 * @param	:(int) ct_len: ��ȣ���� ����
 * @param	:(unsigned char **) pt: ��ȣȭ�� �� (return)
 * @param	:(int *) pt_len: ���� ���� (return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
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
 * 			  - client�� server���� random �� �˰��� ��ȯ
 * @param	:(net_ctx *)ctx: �������� ����ü
 * @param	:(char *)in: CLIENT_CTX => NULL
 *                       SERVER_CTX => Ŭ���̾�Ʈ�κ��� ���� INL_Handshake_Init(CLIENT)�� ��� �޽���
 * @param	:(int) inl: CLIENT_CTX =>  0
 *                      SERVER_CTX => 'in'������ ����� �������� ����
 * @param	:(unsigned char **)out: HANDSHAKE_INIT ����(return)
 * @param	:(int *)outl:HANDSHAKE_INIT ������ ����(return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Handshake_Init(net_ctx *ctx, unsigned char *in, int in_len, unsigned char **out, int *out_len);
#else
/**
 * @brief	: ù��° �Ķ���ͷ� ������ index�� ����Ͽ� �迭���� Global Contex�� ã�Ƽ� Handshake �ʱ�ȭ
 * 			  - client�� server���� random �� �˰��� ��ȯ
 * @param	:(net_ctx *)ctx: �������� ����ü
 * @param	:(char *)in: CLIENT_CTX => NULL
 *                       SERVER_CTX => Ŭ���̾�Ʈ�κ��� ���� INL_Handshake_Init(CLIENT)�� ��� �޽���
 * @param	:(int) inl: CLIENT_CTX =>  0
 *                      SERVER_CTX => 'in'������ ����� �������� ����
 * @param	:(unsigned char **)out: HANDSHAKE_INIT ����(return)
 * @param	:(int *)outl:HANDSHAKE_INIT ������ ����(return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API  INL_Handshake_Init_Array(int ctx_index, net_ctx *ctx, unsigned char *in, int inl, unsigned char **out, int* outl);
#endif

/**
 * @brief	: INIT_HANDSHAKE
 * 			  - client�� server���� random �� �˰��� ��ȯ
 * @param	:(net_ctx *)ctx: �������� ����ü
 * @param	:(char *)in: CLIENT_CTX => NULL
 *                       SERVER_CTX => Ŭ���̾�Ʈ�κ��� ���� INL_Handshake_Init(CLIENT)�� ��� �޽���
 * @param	:(int) inl: CLIENT_CTX =>  0
 *                      SERVER_CTX => 'in'������ ����� �������� ����
 * @param	:(unsigned char **)out: HANDSHAKE_INIT ����(return)
 * @param	:(int *)outl:HANDSHAKE_INIT ������ ����(return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Handshake_Init_Ex(net_ctx *ctx, net_ctx *ctx_init, unsigned char *in, int in_len, unsigned char **out, int *out_len);

#ifndef INITECH_ASP
/**
 * @brief	: UPDATE_HANDSHAKE
 * 			  - ����Ű ��ȯ �� Ȯ��
 * @param	:(net_ctx *)ctx: �������� ����ü
 * @param	:(char *)in: CLIENT_CTX => �����κ��� ���� INL_Handshake_Init(SERVER)�� ��� �޽���
 *                       SERVER_CTX => Ŭ���̾�Ʈ�� ���� ���� INL_Handshake_Update(CLIENT)�� ��� �޽���
 * @param	:(int) inl: 'in'������ ����� �������� ����
 * @param	:(unsigned char **)out: HANDSHAKE_UPDATE ����(return)
 * @param	:(int *)outl:HANDSHAKE_UPDATE ������ ����(return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Handshake_Update(net_ctx *ctx, unsigned char *in, int in_len, unsigned char **out, int *out_len);
#else
/**
 * @brief	: ù��° �Ķ���ͷ� index ���� �޾Ƽ� ���ϴ� Global Context�� ã�Ƽ� Handshake Update ó��
 * 			  - ����Ű ��ȯ �� Ȯ��
 * @param	:(int)ctx_index: ã���� �ϴ� Global Context�� ��Ÿ���� index
 * @param	:(net_ctx *)ctx: �������� ����ü
 * @param	:(char *)in: CLIENT_CTX => �����κ��� ���� INL_Handshake_Init(SERVER)�� ��� �޽���
 *                       SERVER_CTX => Ŭ���̾�Ʈ�� ���� ���� INL_Handshake_Update(CLIENT)�� ��� �޽���
 * @param	:(int) inl: 'in'������ ����� �������� ����
 * @param	:(unsigned char **)out: HANDSHAKE_UPDATE ����(return)
 * @param	:(int *)outl:HANDSHAKE_UPDATE ������ ����(return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API  INL_Handshake_Update_Array(int ctx_index, net_ctx* ctx, unsigned char* in, int inl, unsigned char** out, int* outl);
#endif

/**
 * @brief	: UPDATE_HANDSHAKE
 * 			  - ����Ű ��ȯ �� Ȯ��
 * @param	:(net_ctx *)ctx: �������� ����ü
 * @param	:(char *)in: CLIENT_CTX => �����κ��� ���� INL_Handshake_Init(SERVER)�� ��� �޽���
 *                       SERVER_CTX => Ŭ���̾�Ʈ�� ���� ���� INL_Handshake_Update(CLIENT)�� ��� �޽���
 * @param	:(int) inl: 'in'������ ����� �������� ����
 * @param	:(unsigned char **)out: HANDSHAKE_UPDATE ����(return)
 * @param	:(int *)outl:HANDSHAKE_UPDATE ������ ����(return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Handshake_Update_Ex(net_ctx *ctx, net_ctx *ctx_init, unsigned char *in, int in_len, unsigned char **out, int *out_len);

/**
 * @brief	: FINAL_HANDSHAKE
 * 			  - ��ȯ�� ����Ű�� ���ø޽��� ��/��ȣȭ Ȯ��
 * @param	:(net_ctx *)ctx: �������� ����ü
 * @param	:(char *)in: CLIENT_CTX => �����κ��� ���� INL_Handshake_Update(SERVER)�� ��� �޽���
 *                       SERVER_CTX => Ŭ���̾�Ʈ�� ���� ���� INL_Handshake_Final(CLIENT)�� ��� �޽���
 * @param	:(int) inl: 'in'������ ����� �������� ����
 * @param	:(unsigned char **)out: CLIENT_CTX => HANDSHAKE_FINAL ����(return)
 *                                  SERVER_CTX => NULL
 * @param	:(int *)outl: CLIENT_CTX => HANDSHAKE_FINAL ������ ����(return)
 * 						  SERVER_CTX => 0
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Handshake_Final(net_ctx *ctx, unsigned char *in, int in_len, unsigned char **out, int *out_len);

/**
 * @brief	: ctx����ü�� encoding flag ����
 * @param	:(net_ctx *) ctx: �������� ����ü
 * @param	:(char *) enc_flag: ���ڵ� �÷��� (0000|0001|0010|0011)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Set_Encode_Flag(net_ctx *ctx, char *enc_flag);


/**
 * @brief	: ctx����ü�� IV ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) iv (input)
 * @param	: (int) iv_len: 'iv'�� ���� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Set_IV(net_ctx *ctx, unsigned char *iv, int iv_len);

/**
 * @brief	: ctx����ü�� ����Ű ���� �ؽ� �˰��� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) DigestName: �ؽ� �˰��� (input)
 * @param	: (int) HA_len: 'DigestName'������ ���� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Set_Hash_Algorithm(net_ctx *ctx, char *DigestName, int HA_len);

/**
 * @brief	: ctx����ü�� ����Ű ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) key: ����Ű (input)
 * @param	: (int) keylen: ����Ű ���� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Set_Session_Key(net_ctx *ctx, unsigned char *key, int keylen);

/**
 * @brief	: ctx����ü�� ��ĪŰ ��ȣȭ �˰��� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (char *) ciphername: ��ȣ �˰���+��� (input)
 * @param	: (int) len: length of 'ciphername' (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Set_Crypto_Algorithm( net_ctx *ctx, char *ciphername, int len );

/**
 * @brief	: ���Ϸκ��� ���� ������ ��Ʈ�� �о� ctx����ü�� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (char *) svr_cert_path: ���� ������ ���+���ϸ� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_SetServerCertFile(net_ctx *ctx, char *svr_cert_path);

/**
 * @brief	: ���Ϸκ��� Ŭ���̾�Ʈ ������ ��Ʈ�� �о� ctx����ü�� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (char *) cli_cert_path: Ŭ���̾�Ʈ ������ ���+���ϸ� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_SetClientCertFile(net_ctx *ctx, char *cli_cert_path);

/**
 * @brief	: ���Ϸκ��� ����Ű ��Ʈ�� �о� ctx����ü�� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (char *) privkey_path: ����Ű ���� ���+���ϸ� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_SetPrivKeyFile(net_ctx *ctx, char *privkey_path);

/**
 * @brief	: ctx����ü�� ��ȣȭ�� ����Ű �н����� ��Ʈ�� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (char *) EncPkeyPass: ��ȣȭ�� ����Ű �н����� ��Ʈ��(input)
 * @param	: (int) passlen: ��ȣȭ�� ����Ű �н������� ���� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_SetPrivKeyPass( net_ctx *ctx, char *EncPkeyPass, int passlen );

/**
 * @brief	: ctx����ü�� �Է¹��� ����Ű �н����带 ��ȣȭ �Ͽ� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (char *) pkeyPass: ��ȣȭ���� ���� ����Ű �н����� ��Ʈ��(input)
 * @param	: (int) passlen: ����Ű �н������� ���� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_SetPrivKeyPasswd( net_ctx *ctx, char *pkeyPass, int passlen );


/**
 * @brief   : handshake ���ڵ� �÷��׸� ctx����ü�� ����
 * @param   : (net_ctx *) ctx: �������� ����ü
 * @param   : (char *) hs_enc: �ڵ彦��ũ ���ڵ� �÷��� (input)
 * @return  : (int) success:0 or error_code
 */
INISAFENET_INT_API INL_SetHSEncFlag( net_ctx *ctx, char *hs_encflag );



/**
 * @brief   : handshake Ŭ���̾�Ʈ ������ ctx ����ü�� ����
 * @param   : (net_ctx *) ctx: �������� ����ü
 * @param   : (char *) hs_cli_ver: handshake client version
 * @return  : (int) success:0 or error_code
 */
INISAFENET_INT_API INL_SetClientVer( net_ctx *ctx, char *hs_cli_ver);

/**
 * @brief   : handshake ��û�� server cert type �� ����.
 * @param   : (net_ctx *) ctx: �������� ����ü (input)
 * @param   : (char *) type : ��û�� server cert type. ("CERT"/"KEY") (input)
 * @return  : (int) success:0 or error_code
 */
INISAFENET_INT_API INL_Set_SCert_Type_Req( net_ctx *ctx, char *type);
/**
 * @brief	:
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (char *) file_path: ����Ű������ ���� ��Ʈ�� (input)
 * @param	: (char *) password: ����Ű���� ��ȣȭ �ϱ� ���� �н����� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Set_Skey_IV_File(net_ctx *ctx, char *file_path, char *password);

/**
 * @brief	:
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (int) use_flag: ����Ű�� �ؽ��Ͽ� ����� ������ ����.
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Set_Hashed_Key_Use(net_ctx *ctx, int use_flag);

/**
 * @brief	: ���Ϸκ��� ����Ű+IV �о� ctx ����ü�� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (char *) key_string: ����Ű������ ���� ��Ʈ�� (input)
 * @param	: (char *) password: ����Ű���� ��ȣȭ �ϱ� ���� �н����� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Load_Session_Key(net_ctx *ctx, char *key_string, int key_string_len, char *password, int password_len);

/**
 * @brief   : ��ȣȭ�� ����Ű�� ��ȣȭ�� ��й�ȣ ����
 * @param   :
 * (net_ctx *) ctx: �������� ����ü
 * @param   : (unsigned char *) passwd :encrypted Session key password (input)
 * @param   : (int) passwdlen: length of 'passwd' (input)
 * @return  : (int) ����=0 �Ǵ� �����ڵ�
*/
INISAFENET_INT_API INL_Set_Encrypt_Skey_Passwd(net_ctx *ctx, unsigned char *passwd, int passwdlen);


/**
 * @brief	: Hex������ ǥ�� ���
 * @param	:(FILE) out: stdout,stderr,FILE...
 * @param	:(char *) content: value
 * @param	:(int) len: length of value
 * @return	:(void)
 */
INISAFENET_VOID_API INL_HexaDump(FILE *out, char *content, int len);

/**
 * @brief	: �޸� �Ҵ�� �����͸� ����
 * @param	:(unsigned char *) p: NET��⿡�� malloc�ߴ� ������
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
 * @brief	: ����Ű�� ������ ��ȣȭ�Ͽ� ����
 * @param	:(net_ctx *) ctx: �������� ����ü
 * @param	:(unsigned char *) in: �����ϱ� ���� ������
 * @param	:(int) inl: �������� ����
 * @param	:(unsigned char **) out: ����� ������ (return)
 * @param	:(int *) outl: ����� �������� ���� (return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_I_Sign(net_ctx *ctx, unsigned char *in, int inl, unsigned char** out, int *outl);

/**
 * @brief	: ����Ű�� ����� ������ Ȯ��
 * @param	:(net_ctx *) ctx: �������� ����ü
 * @param	:(unsigned char *) org_data: ���� �� ���� ������
 * @param	:(int) org_data_len: ���� �� ���� �������� ����
 * @param	:(unsigned char *) sig_data: ���� �� ������ (return)
 * @param	:(int *) sig_data_len: ���� �� �������� ���� (return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_I_VerifySign(net_ctx *ctx, unsigned char *org_data, int org_data_len, unsigned char *sig_data, int sig_data_len);

/**
 * @brief	: ctx����ü�� base64���ڵ��� linefeed���� ���� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (int) flag (0:����, 1:����)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Set_Base64flag( net_ctx *ctx, int flag );

/**
 * @brief	: ctx����ü�� ���� ������ ��Ʈ�� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) svr_cert: ���� ������ ��Ʈ��(input)
 * @param	: (int) svr_cert: ���� ������ ��Ʈ���� ���� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_SetServerCert(net_ctx *ctx, char *svr_cert, int certlen);

/**
 * @brief	: ctx����ü�� Ŭ���̾�Ʈ ������ ��Ʈ�� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) Ŭ���̾�Ʈ ������ ��Ʈ�� (input)
 * @param	: (int) certlen: Ŭ���̾�Ʈ ������ ��Ʈ���� ���� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_SetClientCert(net_ctx *ctx, char *cli_cert, int certlen);

/**
 * @brief	: ctx����ü�� CA ������ ��Ʈ�� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) ca_cert: CA ������ ��Ʈ��(input)
 * @param	: (int) certlen: CA ������ ��Ʈ���� ���� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
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
 * @brief	: ctx����ü�� ����Ű ��Ʈ�� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) ����Ű ��Ʈ�� (input)
 * @param	: (int) keylen: ����Ű ��Ʈ���� ���� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_SetPrivKey(net_ctx *ctx, unsigned char *privkey, int keylen);

/**
 * @brief	: ����Ű ����
 * @param	: (unsigned char *) sessionkey : ����Ű[16] (return)
 * @return	: (void)
 */
INISAFENET_VOID_API INL_gen_sessionkey(unsigned char *sessionkey);

/**
 * @brief	: ����Ű �����Ͽ� ����Ű�� ��ȣȭ
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char **) encskey :encrypted Session key (return)
 * @param	: (int) encskey: length of 'encskey' (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Encrypt_Skey(net_ctx *ctx, unsigned char **encskey, int *encskeylen);

/**
 * @brief	: ����Ű�� ����Ű ��ȣȭ
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char **) encskey :encrypted Session key (return)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Decrypt_Skey(net_ctx *ctx, unsigned char *encskey);

/**
 * @brief	: ����->��ȣȭ->base128 encoding
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) in : text (input)
 * @param	: (int) inl: length of 'in' (input)
 * @param	: (unsigned char **) out: encrypt result value (return)
 * @param	: (int *) outl: length of 'out' (return)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Encrypt_Data(net_ctx *ctx, unsigned char *in, int inl, unsigned char** out, int *outl);

/**
 * @brief	: base128 decoding -> ��ȣȭ -> ��������
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) in : text (input)
 * @param	: (int) inl: length of 'in' (input)
 * @param	: (unsigned char **) out: decrypt result value (return)
 * @param	: (int *) outl: length of 'out' (return)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Decrypt_Data(net_ctx *ctx, unsigned char *in, int inl, unsigned char** out, int *outl);

/**
 * @brief	: (����Ű�� ��ȣȭ�� ����Ű+������ ��ȣȭ�� ������) ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) in : text (input)
 * @param	: (int) inl: length of 'in' (input)
 * @param	: (unsigned char **) out: encrypt result value (return)
 * @param	: (int *) outl: length of 'out' (return)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Encrypt_Ext(net_ctx *ctx, unsigned char *in, int inl, unsigned char** out, int *outl);

/**
 * @brief	: (����Ű�� ��ȣȭ�� ����Ű+��ȣȭ�� �������� �� ������) ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) in : text (input)
 * @param	: (int) inl: length of 'in' (input)
 * @param	: (unsigned char **) out: decrypt result value (return)
 * @param	: (int *) outl: length of 'out' (return)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Decrypt_Ext(net_ctx *ctx, unsigned char *in, int inl, unsigned char** out, int *outl);

/**
 * @brief	: ����Ű ���� �� ����Ű�� ��ȣȭ, ��ȣ���� �򹮱��� ��ŭ �е�
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (int) datalen : loop count (input)
 * @param	: (unsigned char **) encskey: encrypted session key (return)
 * @param	: (int *) encskeylen: length of 'encskey' (return)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Encrypt_Skey_FTP(net_ctx* ctx, int datalen, unsigned char** encskey, int* encskeylen );

/**
 * @brief	: ����Ű�� ��ȣȭ �Ͽ� ����Ű ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) encskey: encrypted session key (input)
 * @param	: (int *) encskeylen: length of 'encskey' (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Decrypt_Skey_FTP(net_ctx* ctx, unsigned char* encskey, int encskeylen);

/**
 * @brief	: ���Ͽ��� �� �о� ��ȣȭ �� �� ���Ͽ� ��ȣ�� ���
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (char *) infile: Read file path (input)
 * @param	: (int *) outfile: Save the file path (input)
 * @param	: (int *) outcnt: outfile line (return)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Encrypt_FTP(net_ctx *ctx, char *infile, char *outfile, long *outcnt);

/**
 * @brief	: ���Ͽ��� ��ȣ�� �о� ��ȣȭ �� �� ���Ͽ� �� ���
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (char *) infile: Read file path (input)
 * @param	: (int *) outfile: Save the file path (input)
 * @param	: (int *) outcnt: outfile line (return)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Decrypt_FTP(net_ctx *ctx, char *infile, char *outfile, long *outcnt);

/**
 * @brief	: ��ĪŰ �˰��򿡼� OFB��� �ϰ�� ��ȣȭ �ϴ� �Լ�
 * 			  - encrypt�� �ι� �� ��� ���� ����Ǵ� ��� ����
 * @param	:(net_ctx *) ctx: �������� ����ü
 * @param	:(unsigned char *) indata: plain text
 * @param	:(int) indatalen: length of plain text
 * @param	:(unsigned char **) outdata: cipher text (return)
 * @param	:(int *) outdatalen: length of cipher text (return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Mask_Encrypt(net_ctx *ctx, unsigned char *indata, int indatalen, unsigned char** outdata, int *outdatalen);

/**
 * @brief	:��ĪŰ �˰��򿡼� OFB��� �ϰ�� ��ȣȭ �ϴ� �Լ�
 * 			  - encrypt�� �ι� �� ��� ���� ����Ǵ� ��� ����
 * @param	:(net_ctx *) ctx: �������� ����ü
 * @param	:(unsigned char *) indata: cipher text
 * @param	:(int) indatalen: length of cipher text
 * @param	:(unsigned char **) outdata: plain text (return)
 * @param	:(int *) outdatalen: length of plain text (return)
 * @return	:(int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Mask_Decrypt(net_ctx *ctx, unsigned char *indata, int indatalen, unsigned char** outdata, int *outdatalen);

/**
 * @brief	: ����ü�κ��� ����Ű�� �����Ͽ� ��ȯ
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) s_key: session-key value. buffer size have to larger than 16.(return)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Get_Session_Key(net_ctx *ctx, unsigned char *s_key);

/**
 * @brief	: �޽��� �ؽ����� ��ȯ
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) s_key: session-key value. buffer size have to larger than 16.(return)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_Message_Digest(char *hash_alg ,unsigned char *in, int inl, unsigned char **hash_data, int *hash_len);

/**
 * @brief	: ����ü�κ��� ����Ű�� �����Ͽ� ��ȯ
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (unsigned char *) s_key: session-key value. buffer size have to larger than 16.(return)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
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
 *  @brief  : INISAFE Net NTP AE��aE��
 *  @param  : (char *) ntp_ip: NTP server ip (default ����� NULL )
 *  @param  : (int) ntp_port : NTP server port (default ����� 0)
 *  @return : (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_NTP_Init(char *ntp_ip, int ntp_port);

/**
 *  @brief  : INISAFE Net NTP Close
 *  @return : (void)
 */
INISAFENET_VOID_API INL_NTP_Close(void);

/**
 * @brief	: ctx����ü�� ���Ἲ ���� �ɼ� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (char *) integrity_check : ���Ἲ ���� Flag (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
 */
INISAFENET_INT_API INL_SetIntegrityCheck( net_ctx *ctx, char *integrity_check );

/**
 * @brief	: ctx����ü�� ���� �е� ���� ����
 * @param	: (net_ctx *) ctx: �������� ����ü
 * @param	: (char *) ranpad_len : ���� �е� ���� (input)
 * @return	: (int) ����=0 �Ǵ� �����ڵ�
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
