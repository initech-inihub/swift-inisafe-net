/**
 *	@file	: ICL_encode.h
 *	@brief	: Base64, Base128, URL encoding/decoding 함수들
 *	@section	CREATEINFO	Create
 *		- author	: Myungkyu Jung (myungkyu.jung@initech.com)
 *		- create	: 2009. 9. 21
 *  @section	MODIFYINFO	History
 *		- 2009. 9. 21/Myungkyu Jung : create file
 */

#ifndef ICL_ENCODE_H_
#define ICL_ENCODE_H_

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

#define DEFAULT_LF_BYTE		64

#ifndef _WIN32_LOADLOBRARY_CORE_
/* Functions ********************************************/
/**
 * @brief	: Base64 encoding. using INICrypto_v5
 * @param	:(unsigned char *) data: data to encode
 * @param	:(int) dataLen: length of data
 * @param	:(char **) base64: encoded data with BASE-64 (return)
 * @param	:(int) mode: insert linefeed flag at every 64byte.  (0=no linefeed, 1=insert linefeed)
 * @return	:(int) success=encoded data length, error=0
 */
INISAFECORE_API int ICL_Base64_Encode(unsigned char *data, int dataLen, char **base64, int mode);


INISAFECORE_API int ICL_Base64_Encode_F(unsigned char *data, int dataLen, char *base64, int mode);

/**
 * @brief	: Base64 encoding. using INICrypto_v5
 * @param	:(unsigned char *) data: data to encode
 * @param	:(int) dataLen: length of data
 * @param	:(char **) out: encoded data with BASE-64 (return)
 * @param	:(int) lf_byte: linefeed를 각 라인에 몇바이트마다 넣을 건지를 나타내는 기준 값.
 * @return	:(int) success=encoded data length, error=0
 */
INISAFECORE_API int ICL_Base64_Encode_LF(unsigned char *data, int dataLen, char **out, int lf_byte);

/**
 * @brief	: Base64 decoding. using INICrypto_v5 (ICL_Base64_Encode_LF()로 인코딩된 데이터도 이 함수로 디코딩 수행)
 * @param	:(char *) base64: data to decode
 * @param	:(int) base64Len: length of base64
 * @param	:(unsigned char **) output: decoded data with BASE-64 (return)
 * @return	:(int) success=encoded data length, error=0
 */
INISAFECORE_API int ICL_Base64_Decode(char *base64, int base64Len, unsigned char **output);


INISAFECORE_API int ICL_Base64_Decode_F(char *base64, int base64Len, unsigned char *output);


int ICL_encode_Base64(const unsigned char *data, int dataLen, unsigned char *base64);
int ICL_decode_Base64(const unsigned char *base64, int base64Len, unsigned char *output);

/**
 * @brief	: URL encoding.
 * @param	:(unsigned char *) in: data to encode
 * @param	:(int) inlen: length of data
 * @param	:(char *) out: encoded data with URL_encoding. (minimum buffer size=inlen*3+1) (return)
 * @param	:(int *) outlen: length of out (return)
 * @return	:(int) success=0, error=erroc_code
 */
INISAFECORE_API int ICL_URL_Encode(unsigned char *in, int inlen, char *out, int *outlen);

/**
 * @brief	: URL decoding.
 * @param	:(unsigned char *) indata: data to decode
 * @param	:(int) inlen: length of data
 * @param	:(char *) outdata: encoded data with URL_encoding. (minimum buffer size=inlen+1). (return)
 * @param	:(int *) outlen: length of outdata (return)
 * @return	:(int) success=0, error=erroc_code
 */
INISAFECORE_API int ICL_URL_Decode(char *indata, int inlen, unsigned char *outdata, int *outlen);

/**
 * @brief	: Base-128 encoding.
 * @param	:(unsigned char *) in: data to encode
 * @param	:(int) inl: length of in
 * @param	:(int) msg_len: buffer size to encode
 * @param	:(unsigned char **) out: encoded data (return)
 * @return	:(int) success=encoded data length, error=-1
 */
INISAFECORE_API int ICL_Base128_Encode(const unsigned char *in, int inl, int msg_len, unsigned char **out);

/**
 * @brief	: Base-128 decoding.
 * @param	:(unsigned char *) in: data to decode
 * @param	:(int) inl: length of in
 * @param	:(unsigned char **) out: decoded data (return)
 * @return	:(int) success=encoded data length, error=-1
 */
INISAFECORE_API int ICL_Base128_Decode(const unsigned char *in, int inl, unsigned char **out);

/* 기존에 사용하던 함수이름 보존 */
/**
 * @brief	: 기존에 사용하던 함수. (보관용이므로 사용금지)
 */
INISAFECORE_API int ICL_Base128Encoding(const unsigned char *in, int inl, int msg_len, unsigned char **out);
/**
 * @brief	: 기존에 사용하던 함수. (보관용이므로 사용금지)
 */
INISAFECORE_API int ICL_Base128Decoding(const unsigned char *in, int inl, unsigned char **out);

/* ICL_URLEncode()함수에서 strlen(str)을 호출하기 때문에 *str에 0x00이 중간에 있는 경우  오작동 할 수 있는 버그가 존재함. */
/**
 * @brief	: 기존에 사용하던 함수. (보관용이므로 사용금지)
 */
INISAFECORE_API char *ICL_URLEncode(char *str);	/*사용 금지*/
/**
 * @brief	: 기존에 사용하던 함수. (보관용이므로 사용금지)
 */
INISAFECORE_API int ICL_URLDecode(char *indata);
#else
INI_RET_LOADLIB_CORE(int, ICL_Base64_Encode, (unsigned char *data, int dataLen, char **base64, int mode), (data,dataLen,base64,mode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Base64_Encode_F, (unsigned char *data, int dataLen, char *base64, int mode), (data,dataLen,base64,mode), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Base64_Encode_LF, (unsigned char *data, int dataLen, char **out, int lf_byte), (data,dataLen,out,lf_byte), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Base64_Decode, (char *base64, int base64Len, unsigned char **output), (base64,base64Len,output), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Base64_Decode_F, (char *base64, int base64Len, unsigned char *output), (base64,base64Len,output), -10000);
INI_RET_LOADLIB_CORE(int, ICL_URL_Encode, (unsigned char *in, int inlen, char *out, int *outlen), (in,inlen,out,outlen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_URL_Decode, (char *indata, int inlen, unsigned char *outdata, int *outlen), (indata,inlen,outdata,outlen), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Base128_Encode, (const unsigned char *in, int inl, int msg_len, unsigned char **out), (in,inl,msg_len,out), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Base128_Decode, (const unsigned char *in, int inl, unsigned char **out), (in,inl,out), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Base128Encoding, (const unsigned char *in, int inl, int msg_len, unsigned char **out), (in,inl,msg_len,out), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Base128Decoding, (const unsigned char *in, int inl, unsigned char **out), (in,inl,out), -10000);
INI_RET_LOADLIB_CORE(char*, ICL_URLEncode, (char *str), (str), NULL);
INI_RET_LOADLIB_CORE(int, ICL_URLDecode, (char *indata), (indata), -10000);
#endif

#ifdef  __cplusplus
}
#endif

#endif /* ICL_ENCODE_H_ */
