#ifndef _INC_TIME_H_
#define _INC_TIME_H_

#if defined(_WIN32_WCE)

#include <ctype.h>
#ifdef __cplusplus
extern 	 "C" {
#endif

#ifndef _TM_DEFINED
#define _TM_DEFINED
struct tm {
        int tm_sec;     /* seconds after the minute - [0,59] */
        int tm_min;     /* minutes after the hour - [0,59] */
        int tm_hour;    /* hours since midnight - [0,23] */
        int tm_mday;    /* day of the month - [1,31] */
        int tm_mon;     /* months since January - [0,11] */
        int tm_year;    /* years since 1900 */
        int tm_wday;    /* days since Sunday - [0,6] */
        int tm_yday;    /* days since January 1 - [0,365] */
        int tm_isdst;   /* daylight savings time flag */
        };
#endif /* _TM_DEFINED */

extern long	_timezone;
/*
long        AFXAPI wce_GetMessageTime();
time_t      AFXAPI wce_mktime(struct tm* );
struct tm * AFXAPI wce_localtime(const time_t *);
char*       AFXAPI wce_ctime(const time_t* );
time_t		AFXAPI wce_time(time_t *);
*/

time_t _make_time_t (struct tm *tb, int ultflag);
time_t      mktime(struct tm* );
struct tm * localtime(const time_t *);
struct tm * gmtime(const time_t *);
char*       ctime(const time_t* );
time_t		time(time_t *);

#ifdef __cplusplus
}
#endif

#endif	/* defined(_WIN32_WCE) */

#endif	/* _INC_TIME_H_ */

