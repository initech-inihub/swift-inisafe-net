#include <time.h> 

#ifndef TIME64_H 
# define TIME64_H 

#define INT_64_T long long 
/*
#define HAS_GMTIME_R 
#define HAS_LOCALTIME_R 
*/

/* Set our custom types */ 
typedef INT_64_T Int64; 
typedef Int64 time64_t; 
typedef Int64 Year; 


/* A copy of the tm struct but with a 64 bit year */ 
struct TM64 { 
	int tm_sec; 
	int tm_min; 
	int tm_hour; 
	int tm_mday; 
	int tm_mon; 
	Year tm_year; 
	int tm_wday; 
	int tm_yday; 
	int tm_isdst; 
	
#ifdef HAS_TM_TM_GMTOFF 
	long tm_gmtoff; 
#endif 
	
#ifdef HAS_TM_TM_ZONE 
	char *tm_zone; 
#endif 
}; 


/* Decide which tm struct to use */ 
#ifdef USE_TM64 
#define TM TM64 
#else 
#define TM tm 
#endif 


/* Declare public functions */ 
struct TM *gmtime64_r (const time64_t *, struct TM *); 
struct TM *localtime64_r (const time64_t *, struct TM *); 
struct TM *gmtime64 (const time64_t *); 
struct TM *localtime64 (const time64_t *); 

char *asctime64 (const struct TM *); 
char *asctime64_r (const struct TM *, char *); 

char *ctime64 (const time64_t*); 
char *ctime64_r (const time64_t*, char*); 

time64_t timegm64 (const struct TM *); 
time64_t mktime64 (const struct TM *); 
time64_t timelocal64 (const struct TM *); 

double difftime64(time64_t time1, time64_t time0);

void copy_TM_to_tm(const struct TM *src, struct tm *dest);
void copy_tm_to_TM(const struct tm *src, struct TM *dest);

/* Not everyone has gm/localtime_r(), provide a replacement */ 
#ifdef HAS_LOCALTIME_R 
# define LOCALTIME_R(clock, result) localtime_r(clock, result) 
#else 
# define LOCALTIME_R(clock, result) fake_localtime_r(clock, result) 
#endif 
#ifdef HAS_GMTIME_R 
# define GMTIME_R(clock, result) gmtime_r(clock, result) 
#else 
# define GMTIME_R(clock, result) fake_gmtime_r(clock, result) 
#endif 


#endif 

