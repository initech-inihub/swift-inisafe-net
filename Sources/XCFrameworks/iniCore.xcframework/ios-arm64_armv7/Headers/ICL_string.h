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
/* ������� ���� : ���� ���� �ȵ� */
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
 * @brief	: org_str���� sep�� �������� ���ڿ��� �߶� res_str�� �־� ��ȯ �Ѵ�. (no trim)
 * @param	: (int) start_ix		: org_str���� �˻��� ������ index (ó���� 0, �� �������� �� �Լ��� ȣ���� �� return���� �Ҵ�)
 * @param	: (char *) org_str	: ���� ���ڿ�
 * @param	: (int) org_len		: ���� ���ڿ��� �� ����
 * @param	: (char) sep			: separator. org_str���� ���ڿ��� ������ ���� ����
 * @param	: (char *) res_str	: org_str���� strart_ix�������� sep�������� �߶� ó�� ������ ���ڿ� (return)
 * @param	: (int *) res_len		: res_str�� ����
 * @return	: (int)				: org_str���� res_str�� ������ ������ index (���� ICL_str_tokenȣ�� �� ���� start_ix�� �״�� �̿��ϸ� ��)
 */
INISAFECORE_API int ICL_str_token(int start_ix, char *org_str, int org_len, char sep, char *res_str, int *res_len);

INISAFECORE_API void ICL_HexaDump(FILE *out, unsigned char *content, int len);

/**
  @remark	: �Է¹��ڿ��� ����(����) ws ���ڵ��� �����Ѵ�.
  @param	:[in] (char *) instr: Input String
  @param	:[in] (char *) ws: ������
  @return	:(char *) �Է� ���ڿ� ���� ���� ws �� �ƴ� ���� ��ġ.
  @par ���ǻ���
		return ���ڿ��� �Է� ���ڿ� ���� �ּҰ��̹Ƿ� return �� �����͸� free �ؼ��� �ȵȴ�.
		���������� �Է� ���ڿ��� free �ϸ� return �� ���ڿ��� ����� �� ����.
		�Է� ���ڿ� free �Ŀ� return ���ڿ� ����� ���ؼ��� ������ ���簡 �ʿ��ϴ�.
  @author dh999
*/
INISAFECORE_API char *ICL_ltrim (char *instr, char *ws) ;

/**
  @remark	: ������ �о� ������ ��ȯ�Ѵ�.
  @param	:[in] (char *) filename: ���ϸ�
  @param	:[out] (unsigned char *) out: ���ϳ��� stream
  @param	:[out] (int *) outlen: ���� ����
  @return	:(int) ICL_OK: ����, �׿�: Error Code
  @par ���ǻ���
		����� �Ϸ�� out ������ �ݵ�� free ����� �Ѵ�.
  @author dh999
*/
INISAFECORE_API int ICL_Read_File(char *filename, unsigned char **out, int *outlen);

/**
  @remark	: byte array ������ ���ϸ� ����Ѵ�.
  @param	:[in] (unsigned char *) in : ����� ���� ����
  @param	:[in] (int) inlen: in ����
  @param	:[in] (char *) filename: ���ϸ�
  @return	:(int) ICL_OK: ����, �׿�: Error Code
  @par ���ǻ���
  @author dh999
*/
INISAFECORE_API int ICL_Write_File(unsigned char *in, int inlen, char *filename);

/**
  @remark	: String �ð��� �޾Ƽ� time_t �� �����Ѵ�.
  @param	:[in] (char *) strtime : �Է� �ð� ���ڿ�.
  @return	:(time_t) > 0 : ����(time_t ��)., 0 , -1 : ����
  @par ���ǻ���
       �Է� strtime �� ������ YYYYMMDDhhmmss ���� ��.
  @author dh999
*/
INISAFECORE_API time_t ICL_Str_to_Time(const char *strtime);

/**
  @remark	: hexa ��Ʈ�� 2���� �Է� �޾� �� �Ѵ�.
  @param	:[in] (char *) hex1 : �Է� hexa ���ڿ�1.
  @param	:[in] (char *) hex2 : �Է� hexa ���ڿ�2.
  @return	:(int) > 0 : hex1 �� hex2 ���� ũ��, < 0 : hex1�� hex2 ���� �۴�, = 0 : ����.
  @par ���ǻ���
       �Է� hexa ��Ʈ���� ������ ������ ���� ���ĵ��� �� �� �ִ�.
	   0xAA 0xBB 0xCC
	   12 AB A3 BB
	   12:00:13:A0:
	   0xAABCDDEF
	   AB12AACCEE
  @author dh999
*/
INISAFECORE_API int ICL_cmp_HEX_STR(char *hex1, char *hex2);


/**
@remark	: localtime string ������ �޾� gmtime ��Ʈ�� ������ �����Ѵ�.
@param	:[in] (char *) localtime string %04d%02d%02d%02d%02d%02d
@return	:[out] (char*) gmtime string  %04d%02d%02d%02d%02d%02d

*/
INISAFECORE_API int ICL_GM2LocalTime(const char *in, char *out);

/**
@remark	: localtime string ������ �޾� gmtime ��Ʈ�� ������ �����Ѵ�.
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
 * @brief  : HEXA String�� Intiger�� ��ȯ
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

/* for ���� dep check */
int ICL_str_cmp_Version(char *cur_ver, char *low_ver);
int ICL_str_get_int_tok(char *in, char *sep, int i);


#ifdef  __cplusplus
}
#endif

#endif
