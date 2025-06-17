#ifndef _QDECODER_H
#define _QDECODER_H

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

#include <time.h>
#ifndef _WINDOWS
#include <pthread.h>
#endif

typedef struct Entry Entry;
struct Entry{
  char *name;
  char *value;
  struct Entry *next;
};


typedef struct Cgienv Cgienv;
struct Cgienv{
  char *auth_type;
  char *content_length;
  char *content_type;
  char *document_root;
  char *gateway_interface;
  char *http_accept;
  char *http_cookie;
  char *http_user_agent;
  char *query_string;
  char *remote_addr;
  char *remote_host;
  char *remote_user;
  char *remote_port;
  char *request_method;
  char *script_name;
  char *script_filename;
  char *server_name;
  char *server_protocol;
  char *server_port;
  char *server_software;
  char *server_admin;

  /*** Extended Information ***/
  int  year, mon, day, hour, min, sec;
};
/*
int       qDecoder(void);
char      *qValue(char *name);
int       qiValue(char *name);
void      qPrint(void);
void      qFree(void);
Entry     *qfDecoder(char *filename);
char      *qfValue(Entry *first, char *name);
void      qfPrint(Entry *first);
void      qfFree(Entry *first);
int       qcDecoder(void);
char      *qcValue(char *name);
void      qcPrint(void);
void      qcFree(void);
void      qSetCookie(char *name, char *value, int exp_days, char *domain, char *path, char *secure);
char      *qURLencode(char *str);
void      qURLdecode(char *str);
void      qContentType(char *mimetype);
int       qPrintf(int mode, char *format, ...);
void      qPuts(int mode, char *buf);
void      qError(char *format, ...);
void      qErrorLog(char *filename);
void      qErrorContact(char *msg);
void      qCgienv(Cgienv *env);
struct tm *qGetTime(void);
time_t    qGetGMTTime(char *gmt, time_t plus_sec);
int       qCheckFile(char *filename);
int       qSendFile(char *filename);
int       qReadCounter(char *filename);
int       qSaveCounter(char *filename, int number);
int       qUpdateCounter(char *filename);
int       qCheckEmail(char *email);
int       qCheckURL(char *url);
char      *qRemoveSpace(char *str);
int       qStr09AZaz(char *str);
*/

#ifndef _WIN32_LOADLOBRARY_CORE_
INISAFECORE_API int ICL_CGIQueryDecoder(void);
INISAFECORE_API char *ICL_CGIQueryFindValue(char *name);
INISAFECORE_API int ICL_CGIQueryFindValue2Int(char *name);
INISAFECORE_API void ICL_CGIQueryEntryPrint(char *fn);
INISAFECORE_API void ICL_CGIQuery(char *out, char *in);
INISAFECORE_API void ICL_CGIQueryPrintAllEntries(void);
INISAFECORE_API void ICL_CGIQueryFreeEntries(void);
INISAFECORE_API Entry *ICL_CGIFileDecoder(char *filename);
INISAFECORE_API char *ICL_CGIFileFindValue(Entry *first, char *name);
INISAFECORE_API void ICL_CGIFilePrintEntries(Entry *first);
INISAFECORE_API void ICL_CGIFileFreeEntries(Entry *first);
INISAFECORE_API int ICL_CGICookieAnayzer(void);
INISAFECORE_API char *ICL_CGICookieFindValue(char *name);
INISAFECORE_API void ICL_CGICookiePrintEntries(void);
INISAFECORE_API void ICL_CGICookieFreeEntries(void);
INISAFECORE_API void ICL_CGISetCookie(char *name, char *value, int exp_days, char *domain, char *path, char *secure);
INISAFECORE_API void ICL_CGIPrintContentType (char *mimetype);
INISAFECORE_API int ICL_CGIPrintfMessage(int mode, char *format, ...);
INISAFECORE_API void ICL_CGIPuts(int mode, char *buf);
INISAFECORE_API void ICL_CGIError(char *format, ...);
INISAFECORE_API void ICL_CGIErrorLog(char *filename);
INISAFECORE_API void ICL_CGIErrorContact(char *msg);
INISAFECORE_API void ICL_CGIEnv(Cgienv *env);
INISAFECORE_API struct tm *ICL_CGIGetTime(void);
INISAFECORE_API time_t ICL_CGIGetGMTTime(char *gmt, time_t plus_sec);
INISAFECORE_API int ICL_CGICheckFile(char *filename);
INISAFECORE_API int ICL_CGIPrintFileStdOut(char *filename);
INISAFECORE_API int ICL_CGIReadCounter(char *filename);
INISAFECORE_API int ICL_CGISaveCounter(char *filename, int number);
INISAFECORE_API int ICL_CGIUpdateCounter(char *filename);
INISAFECORE_API int ICL_CGICheckEmail(char *email);
INISAFECORE_API int ICL_CGIURLCheck(char *url);
INISAFECORE_API char *ICL_CGISpaceRemover(char *str);
INISAFECORE_API int ICL_CGICheckStr09AZaz(char *str);
#else
INI_RET_LOADLIB_CORE(int, ICL_CGIQueryDecoder, (void), (), -10000);
INI_RET_LOADLIB_CORE(char*, ICL_CGIQueryFindValue, (char *name), (name), NULL);
INI_RET_LOADLIB_CORE(int, ICL_CGIQueryFindValue2Int, (char *name), (name), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_CGIQueryEntryPrint, (char *fn), (fn) );
INI_VOID_LOADLIB_CORE(void, ICL_CGIQuery, (char *out, char *in), (out,in) );
INI_VOID_LOADLIB_CORE(void, ICL_CGIQueryPrintAllEntries, (void), () );
INI_VOID_LOADLIB_CORE(void, ICL_CGIQueryFreeEntries, (void), () );
INI_RET_LOADLIB_CORE(Entry*, ICL_CGIFileDecoder, (char *filename), (filename), NULL);
INI_RET_LOADLIB_CORE(char*, ICL_CGIFileFindValue, (Entry *first, char *name), (first,name), NULL);
INI_VOID_LOADLIB_CORE(void, ICL_CGIFilePrintEntries, (Entry *first), (first) );
INI_VOID_LOADLIB_CORE(void, ICL_CGIFileFreeEntries, (Entry *first), (first) );
INI_RET_LOADLIB_CORE(int, ICL_CGICookieAnayzer, (void), (), -10000);
INI_RET_LOADLIB_CORE(char*, ICL_CGICookieFindValue, (char *name), (name), NULL);
INI_VOID_LOADLIB_CORE(void, ICL_CGICookiePrintEntries, (void), () );
INI_VOID_LOADLIB_CORE(void, ICL_CGICookieFreeEntries, (void), () );
INI_VOID_LOADLIB_CORE(void, ICL_CGISetCookie, (char *name, char *value, int exp_days, char *domain, char *path, char *secure), (name,value,exp_days,domain,path,secure) );
INI_VOID_LOADLIB_CORE(void, ICL_CGIPrintContentType, (char *mimetype), (mimetype) );
INI_RET_LOADLIB_CORE(int, ICL_CGIPrintfMessage, (int mode, char *format, ...), (mode,format,...), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_CGIPuts, (int mode, char *buf), (mode,buf) );
INI_VOID_LOADLIB_CORE(void, ICL_CGIError, (char *format, ...), (format,...) );
INI_VOID_LOADLIB_CORE(void, ICL_CGIErrorLog, (char *filename), (filename) );
INI_VOID_LOADLIB_CORE(void, ICL_CGIErrorContact, (char *msg), (msg) );
INI_VOID_LOADLIB_CORE(void, ICL_CGIEnv, (Cgienv *env), (env) );
INI_RET_LOADLIB_CORE(struct tm*, ICL_CGIGetTime, (void), (), NULL);
INI_RET_LOADLIB_CORE(time_t, ICL_CGIGetGMTTime, (char *gmt, time_t plus_sec), (gmt,plus_sec), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CGICheckFile, (char *filename), (filename), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CGIPrintFileStdOut, (char *filename), (filename), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CGIReadCounter, (char *filename), (filename), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CGISaveCounter, (char *filename, int number), (filename,number), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CGIUpdateCounter, (char *filename), (filename), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CGICheckEmail, (char *email), (email), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CGIURLCheck, (char *url), (url), -10000);
INI_RET_LOADLIB_CORE(char*, ICL_CGISpaceRemover, (char *str), (str), NULL);
INI_RET_LOADLIB_CORE(int, ICL_CGICheckStr09AZaz, (char *str), (str), -10000);
#endif


#ifdef  __cplusplus
}
#endif

#endif
