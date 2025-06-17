#ifndef _ICLLOG_H_
#define _ICLLOG_H_

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

#if defined(WIN32) || defined(_WIN32_WCE)
#else
#include <pthread.h>
#endif

/*
 *	Log Level
 *		0:emergency,
 * 		1: alert,
 *		2: critical,
 *		3: error,
 *		4: warning,
 *		5: normal,
 *		6: notice,
 *		7: infomation,
 *		8: debug
 */

#define EMERGENCY 0
#define ALERT 1
#define CRITICAL 2
#define INITECH_LOG_ERROR 3
#define WARNING 4
#define NORMAL 5
#define NOTICE 6
#define INFORMATION 7
#ifndef WINCE
#define DEBUG 8
#endif

#define ICL_OFF			0
#define ICL_FATAL			2
#define ICL_ERROR			3
#define ICL_NORMAL			5
#define ICL_INFORM		7
#define ICL_DEBUG			8

#define ICL_FL 	__FILE__,__LINE__

typedef struct _LOGINFO
{
    char logpath[256];
    char filename[256];
    int loglevel;
    char outmode;
}LOGINFO;

#ifndef _WIN32_LOADLOBRARY_CORE_
INISAFECORE_API int		ICL_LogInit(char *path, char *name, int level);
INISAFECORE_API int		ICL_Log_Init(char *path, char *name, int level, char outmode);
INISAFECORE_API void	ICL_Log(int level, char *file, int line, char *format, ...);
INISAFECORE_API void	ICL_Log_HEXA(int level, char *file, int line, char *msgname, unsigned char *content, int len);
INISAFECORE_API void	ICL_setLogLevel(int level);
INISAFECORE_API void	ICL_LogClose(void);

INISAFECORE_API int		ICL_LockInit(void);
INISAFECORE_API void	ICL_LockWait(int fd);
INISAFECORE_API void	ICL_LockRelease(int fd);
INISAFECORE_API void	ICL_LockClear(int fd);

INISAFECORE_API void	ICL_String_free(char* indata);

/* OLD FUNCTION  v6 */
INISAFECORE_API void	ICL_log(int level, char *format, ...);

#else
INI_RET_LOADLIB_CORE(int, ICL_LogInit, (char *path, char *name, int level), (path,name,level), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Log_Init, (char *path, char *name, int level, char outmode), (path,name,level,outmode), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_Log, (int level, char *file, int line, char *format, ...), (level,file,line,format,...) );
INI_VOID_LOADLIB_CORE(void, ICL_Log_HEXA, (int level, char *file, int line, char *msgname, unsigned char *content, int len), (level,file,line,msgname,content,len) );
INI_VOID_LOADLIB_CORE(void, ICL_setLogLevel, (int level), (level) );
INI_VOID_LOADLIB_CORE(void, ICL_LogClose, (void), () );
INI_RET_LOADLIB_CORE(int, ICL_LockInit, (void), (), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_LockWait, (int fd), (fd) );
INI_VOID_LOADLIB_CORE(void, ICL_LockRelease, (int fd), (fd) );
INI_VOID_LOADLIB_CORE(void, ICL_LockClear, (int fd), (fd) );
INI_VOID_LOADLIB_CORE(void, ICL_String_free, (char* indata), (indata) );
INI_VOID_LOADLIB_CORE(void, ICL_log, (int level, char *format, ...), (level,format,...) );
#endif

#ifdef NIS_CRYPTO_PRODUCT_LOG
	int ICL_Mini_Log_Init(char *path);
	void ICL_Mini_Log(char *format, ...);
	void ICL_Mini_Log_Hexa(char *msgname, unsigned char *content, int len); 
	void ICL_Mini_Log_Close(); 
#endif 

#ifdef  __cplusplus
}
#endif

#endif

