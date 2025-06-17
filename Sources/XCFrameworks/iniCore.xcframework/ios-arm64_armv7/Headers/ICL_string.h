#ifndef __STRING_H__
#define __STRING_H__

#include <stdio.h>

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

#ifndef _WINDOWS
#include <pthread.h>
#endif


#ifndef _WIN32_LOADLOBRARY_CORE_
/*string*/
INISAFECORE_API char* ICL_StrTrim(char* str);
INISAFECORE_API char ICL_Hex2Char(char hex_up, char hex_low);
INISAFECORE_API int ICL_Asc2Bin(int c);
INISAFECORE_API char* ICL_StrMid(char *a_pIn, int a_iBegin, int a_iCnt);
/* do not use this function!!! no safe!*/
INISAFECORE_API char *ICL_strtok(char *s1, const char *s2, char **s3);	
INISAFECORE_API char * ICL_replace(char *data, char *org, char *rep);
/* 사용하지 말것 : 정상 동작 안됨 */
INISAFECORE_API int ICL_convert_version_int(char *ver);
/* memset, free, set NULL */
INISAFECORE_API void ICL_Free(void *p, int len);			
/*void ICL_Free_Out(unsigned char *p);*/		/* free, set NULL */


/**
 * @brief	: check Version string (current - low)
 * @param	: (char *)current_version	: minimum inicore version string "x.x.x"
 * @param	: (char *)low_version		: minimum inicore version string "x.x.x"
 * @return	: (int) > 0 : cur_ver > low_ver
 *                  = 0 : cur_ver = low_ver 
 *                  < 0 : cur_ver < low_ver 
 */
INISAFECORE_API int ICL_CMP_Version(char *cur_ver, char *low_ver);

/**
 * @brief	: check requested minimum version
 * @param	: (char *)crypto_ver	: minimum inicrypto version string "x.x.x"
 * @param	: (char *)pki_ver		: minimum inipki version string "x.x.x"
 * @param	: (char *)core_ver	: minimum inicore version string "x.x.x"
 * @return	: (int) success=0, error=error code
 */
INISAFECORE_API int ICL_Check_Version(char *crypto_ver, char *pki_ver, char *core_ver);


/**
 * @brief	: org_str에서 sep를 기준으로 문자열을 잘라 res_str에 넣어 반환 한다. (no trim)
 * @param	: (int) start_ix		: org_str에서 검색을 시작할 index (처음엔 0, 그 다음부턴 이 함수를 호출한 뒤 return값을 할당)
 * @param	: (char *) org_str	: 원본 문자열
 * @param	: (int) org_len		: 원본 문자열의 총 길이
 * @param	: (char) sep			: separator. org_str에서 문자열을 구분할 기준 문자
 * @param	: (char *) res_str	: org_str에서 strart_ix에서부터 sep기준으로 잘라 처음 나오는 문자열 (return)
 * @param	: (int *) res_len		: res_str의 길이
 * @return	: (int)				: org_str에서 res_str를 추출한 다음의 index (다음 ICL_str_token호출 할 때의 start_ix로 그대로 이용하면 됨)
 */
INISAFECORE_API int ICL_str_token(int start_ix, char *org_str, int org_len, char sep, char *res_str, int *res_len);

INISAFECORE_API void ICL_HexaDump(FILE *out, unsigned char *content, int len);

/**
  @remark	: 입력문자열의 시작(좌측) ws 문자들을 제거한다.
  @param	:[in] (char *) instr: Input String
  @param	:[in] (char *) ws: 구분자
  @return	:(char *) 입력 문자열 내의 좌측 ws 가 아닌 시작 위치.
  @par 주의사항
		return 문자열은 입력 문자열 내의 주소값이므로 return 된 포인터를 free 해서는 안된다.
		마찬가지로 입력 문자열을 free 하면 return 된 문자열을 사용할 수 없다.
		입력 문자열 free 후에 return 문자열 사용을 위해서는 별도의 복사가 필요하다.
  @author dh999
*/
INISAFECORE_API char *ICL_ltrim (char *instr, char *ws) ;

/**
  @remark	: 파일을 읽어 내용을 반환한다.
  @param	:[in] (char *) filename: 파일명
  @param	:[out] (unsigned char *) out: 파일내용 stream
  @param	:[out] (int *) outlen: 파일 길이
  @return	:(int) ICL_OK: 성공, 그외: Error Code
  @par 주의사항
		사용이 완료된 out 변수는 반드시 free 해줘야 한다.
  @author dh999
*/
INISAFECORE_API int ICL_Read_File(char *filename, unsigned char **out, int *outlen);

/**
  @remark	: byte array 내용을 파일명에 기록한다.
  @param	:[in] (unsigned char *) in : 저장될 파일 내용
  @param	:[in] (int) inlen: in 길이
  @param	:[in] (char *) filename: 파일명
  @return	:(int) ICL_OK: 성공, 그외: Error Code
  @par 주의사항
  @author dh999
*/
INISAFECORE_API int ICL_Write_File(unsigned char *in, int inlen, char *filename);

/**
  @remark	: String 시간을 받아서 time_t 로 리턴한다.
  @param	:[in] (char *) strtime : 입력 시간 문자열.
  @return	:(time_t) > 0 : 성공(time_t 값)., 0 , -1 : 실패
  @par 주의사항
       입력 strtime 의 형식은 YYYYMMDDhhmmss 여야 함.
  @author dh999
*/
INISAFECORE_API time_t ICL_Str_to_Time(const char *strtime);

/**
  @remark	: hexa 스트링 2개를 입력 받아 비교 한다.
  @param	:[in] (char *) hex1 : 입력 hexa 문자열1.
  @param	:[in] (char *) hex2 : 입력 hexa 문자열2.
  @return	:(int) > 0 : hex1 이 hex2 보다 크다, < 0 : hex1이 hex2 보다 작다, = 0 : 같다.
  @par 주의사항
       입력 hexa 스트링의 형식은 다음과 같은 형식들이 올 수 있다.
	   0xAA 0xBB 0xCC
	   12 AB A3 BB
	   12:00:13:A0:
	   0xAABCDDEF
	   AB12AACCEE
  @author dh999
*/
INISAFECORE_API int ICL_cmp_HEX_STR(char *hex1, char *hex2);


/**
@remark	: localtime string 값으로 받아 gmtime 스트링 값으로 리턴한다.
@param	:[in] (char *) localtime string %04d%02d%02d%02d%02d%02d
@return	:[out] (char*) gmtime string  %04d%02d%02d%02d%02d%02d

*/
INISAFECORE_API int ICL_GM2LocalTime(const char *in, char *out);

/**
@remark	: localtime string 값으로 받아 gmtime 스트링 값으로 리턴한다.
@param	:[in] (char *) localtime string %04d%02d%02d%02d%02d%02d
@return	:[out] (char*) gmtime string  %04d%02d%02d%02d%02d%02d

*/
INISAFECORE_API int ICL_Verify_CertTime(int bServerCert,const char *in_before, const char *in_after, long issuerSpan, long expireSpan);
INISAFECORE_API int ICL_Local2GMTime(const char *in, char *out);
INISAFECORE_API int ICL_IsValidDate(const char *in_before, const char *in_after);
INISAFECORE_API int ICL_IsValidDate2(const char *in_before, const char *in_after, long lServerTimeCap);

INISAFECORE_API char* ICL_stristr(const char *string,const char *strSearch);

INISAFECORE_API char* ICL_str_tokenizer(char* str, char* src, const char* sep) ;

INISAFECORE_API int ICL_Parse_String_By_Name(char *str, char *sep, char *name, char **value);

/**
 * @brief  : HEXA String을 Intiger로 변환
 * @param  : [IN] char* s                 [ HEXA String ,'0xAFCD' or 'AFCD' ]
 */
INISAFECORE_API int ICL_hexa2i(char* s);
INISAFECORE_API long ICL_hexa2L(char* s);

#else
INI_RET_LOADLIB_CORE(char*, ICL_StrTrim, (char* str), (str), NULL);
INI_RET_LOADLIB_CORE(char, ICL_Hex2Char, (char hex_up, char hex_low), (hex_up,hex_low), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Asc2Bin, (int c), (c), -10000);
INI_RET_LOADLIB_CORE(char*, ICL_StrMid, (char *a_pIn, int a_iBegin, int a_iCnt), (a_pIn,a_iBegin,a_iCnt), NULL);
INI_RET_LOADLIB_CORE(char*, ICL_strtok, (char *s1, const char *s2, char **s3), (s1,s2,s3), NULL);
INI_RET_LOADLIB_CORE(char*, ICL_replace, (char *data, char *org, char *rep), (data,org,rep), NULL);
INI_RET_LOADLIB_CORE(int, ICL_convert_version_int, (char *ver), (ver), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_Free, (void *p, int len), (p,len) );
INI_RET_LOADLIB_CORE(int, ICL_CMP_Version, (char *cur_ver, char *low_ver), (cur_ver,low_ver), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Check_Version, (char *crypto_ver, char *pki_ver, char *core_ver), (crypto_ver,pki_ver,core_ver), -10000);
INI_RET_LOADLIB_CORE(int, ICL_str_token, (int start_ix, char *org_str, int org_len, char sep, char *res_str, int *res_len), (start_ix,org_str,org_len,sep,res_str,res_len), -10000);
INI_VOID_LOADLIB_CORE(void, ICL_HexaDump, (FILE *out, unsigned char *content, int len), (out,content,len) );
INI_RET_LOADLIB_CORE(char*, ICL_ltrim, (char *instr, char *ws), (instr,ws), NULL);
INI_RET_LOADLIB_CORE(int, ICL_Read_File, (char *filename, unsigned char **out, int *outlen), (filename,out,outlen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Write_File, (unsigned char *in, int inlen, char *filename), (in,inlen,filename), -10000);
INI_RET_LOADLIB_CORE(time_t, ICL_Str_to_Time, (const char *strtime), (strtime), -10000);
INI_RET_LOADLIB_CORE(int, ICL_cmp_HEX_STR, (char *hex1, char *hex2), (hex1,hex2), -10000);
INI_RET_LOADLIB_CORE(int, ICL_GM2LocalTime, (const char *in, char *out), (in,out), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Verify_CertTime, (int bServerCert,const char *in_before, const char *in_after, long issuerSpan, long expireSpan), (bServerCert,in_before,in_after,issuerSpan,expireSpan), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Local2GMTime, (const char *in, char *out), (in,out), -10000);
INI_RET_LOADLIB_CORE(int, ICL_IsValidDate, (const char *in_before, const char *in_after), (in_before,in_after), -10000);
INI_RET_LOADLIB_CORE(int, ICL_IsValidDate2, (const char *in_before, const char *in_after, long lServerTimeCap), (in_before,in_after,lServerTimeCap), -10000);
INI_RET_LOADLIB_CORE(char*, ICL_stristr, (const char *string,const char *strSearch), (string,strSearch), NULL);
INI_RET_LOADLIB_CORE(char*, ICL_str_tokenizer, (char* str, char* src, const char* sep), (str,src,sep), NULL);
#endif

/* for 버젼 dep check */
int ICL_str_cmp_Version(char *cur_ver, char *low_ver);
int ICL_str_get_int_tok(char *in, char *sep, int i);


#ifdef  __cplusplus
}
#endif

#endif
