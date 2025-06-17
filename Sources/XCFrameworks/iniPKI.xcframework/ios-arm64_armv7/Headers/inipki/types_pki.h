#ifndef __INIPKI_TYPES_H__
#define __INIPKI_TYPES_H__

#include <inicrypto/types.h>

#if defined(WIN32) || defined(_WIN32) || defined(_WIN32_WCE) || defined(_INI_BADA) || defined(iOS)
#include <time.h>
#else
#include "config.h"
#endif

#include "asn1.h"

#if (_MSC_VER >= 1400) && defined(_WIN32) && !defined(_WIN32_WCE) && !defined(_INI_BADA)

#define istrcpy(strDest, sizeInBytes, strSource)				strcpy_s(strDest, sizeInBytes, strSource)
#define istrncpy(strDest, sizeInBytes, strSource, count)		strncpy_s(strDest, sizeInBytes, strSource, count)	
#define istrtok(strToken, strDelimit, context)					strtok_s(strToken, strDelimit, context)
#define isprintf(buffer, sizeOfBuffer, format, ...)				sprintf_s(buffer, sizeOfBuffer, format, __VA_ARGS__ )	
#define igmtime(_tm, time)										{_tm = new_ASN1_TIME(); gmtime_s(_tm, time);}
#define ilocaltime(_tm, time)									{_tm = new_ASN1_TIME(); localtime_s(_tm, time);}
#define ifopen(pFile, filename, mode)							fopen_s(pFile, filename, mode)
#define	ifree_time(x)											if((x)) { free_ASN1_TIME((x)); x = NULL; }

#else

#define istrcpy(strDest, sizeInBytes, strSource)				strncpy(strDest, strSource, sizeInBytes)
#define istrncpy(strDest, sizeInBytes, strSource, count)		strncpy(strDest, strSource, count)
#define isprintf(buffer, sizeOfBuffer, format , ...)			sprintf(buffer, format , __VA_ARGS__)	
#if defined(_WIN32_WCE) || defined(WIN32)
#define igmtime(_tm, time)										_tm = new_ASN1_TIME(); (_tm = gmtime(time)) == NULL ? -1 : 0
#define ilocaltime(_tm, time)									(_tm = localtime(time)) == NULL ? -1 : 0
#define	ifree_time(x)
#define istrtok(strToken, strDelimit, context)					strtok(strToken, strDelimit); *context = NULL;
#else
#define istrtok(strToken, strDelimit, context)					strtok_r(strToken, strDelimit, context);
#define igmtime(_tm, time)										{_tm = new_ASN1_TIME(); gmtime_r(time, _tm);}
#define ilocaltime(_tm, time)									{_tm = new_ASN1_TIME(); localtime_r(time, _tm);}
#define	ifree_time(x)											if((x)) { free_ASN1_TIME((x)); x = NULL; }
#endif
#define ifopen(pFile, filename, mode)							(*pFile = fopen(filename, mode)) == NULL ? -1 : 0
	
#endif /*_WIN32*/




#endif /*INIPKI_TYPES_H*/
