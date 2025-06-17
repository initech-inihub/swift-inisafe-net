/*!
* \file utils.h
* \brief Utility Functions과 Macro 정의
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_UTILS_H
#define HEADER_UTILS_H

#include <stdlib.h>

#include "foundation.h"

/*!
* \brief
* 4Byte배열을 4Byte값으로 바꾸는 매크로\n
* ex) char c[4] -> int c
* \param os
* 4Byte배열의 포인터
* \returns
* 4Byte값
*/
# define ISC_OS2I(os) (((uint32)(os)[0] << 24) ^ ((uint32)(os)[1] << 16) ^ ((uint32)(os)[2] <<  8) ^ ((uint32)(os)[3]))

/*!
* \brief
* 4Byte값을 4Byte배열로 바꾸는 매크로\n
* ex) int i -> char c[4]
* \param os
* 4Byte배열의 포인터
* \param i
* 4Byte값을 가진 변수
*/
# define ISC_I2OS(os, i) { (os)[0] = (uint8)((i) >> 24); (os)[1] = (uint8)((i) >> 16); (os)[2] = (uint8)((i) >>  8); (os)[3] = (uint8)(i); }

/*!
* \brief
* 8Byte배열을 8Byte값으로 바꾸는 매크로\n
* ex) char c[8] -> long long c
* \param os
* 8Byte배열의 포인터
* \returns
* 8Byte변수 값
*/
# define ISC_OS2L(os) (((uint32)(os)[0] << 56) ^ ((uint32)(os)[1] << 48) ^ ((uint32)(os)[2] <<  40) ^ ((uint32)(os)[3] << 32) \
				^ ((uint32)(os)[4] << 24) ^ ((uint32)(os)[5] << 16) ^ ((uint32)(os)[6] << 8) ^ ((uint32)(os)[7]))

/*!
* \brief
* 8Byte값을 8Byte배열로 바꾸는 매크로\n
* ex) long long i -> char c[8]
* \param os
* 8Byte배열의 포인터
* \param i
* 8Byte값을 가진 변수
*/
# define ISC_L2OS(os, i) {(os)[0] = (uint8)((i) >> 56); (os)[1] = (uint8)((i) >> 48); (os)[2] = (uint8)((i) >>  40); \
				(os)[3] = (uint8)((i) >> 32); (os)[4] = (uint8)((i) >> 24); (os)[5] = (uint8)((i) >> 16); \
				(os)[6] = (uint8)((i) >> 8); (os)[7] = (uint8)(i);}

/*!
* \brief
* 끝에서 n번째 Byte 값을 추출하는 매크로\n
* 인덱스는 0부터 시작
* \param x
* 값을 추출 할 변수
* \param n
* 인덱스 n
* \returns
* 추출된 값
*/
#define ISC_BYTE(x, n) (((x) >> (8 * (n))) & 255)

/*!
* \brief
* 4Byte 변수의 bit배열을 역으로 바꾸는 매크로\n
* ex) 10100011 -> 11000101
* \param x
* 값을 바꿀 변수
* \returns
* 바뀐 값
*/
#define ISC_SWAP(x) (ISC_ROLc(x, 8) & 0x00ff00ff | ISC_RORc(x, 8) & 0xff00ff00)

/*!
* \brief
* 두 변수 값을 XOR 연산하는 매크로
* \param x
* 변수 x
* \param y
* 변수 y
* \returns
* XOR 연산 결과 값
*/
#define ISC_XOR(x,y)		(x^y)

/*!
* \brief
* 두 변수 값을 AND 연산하는 매크로
* \param x
* 변수 x
* \param y
* 변수 y
* \returns
* AND 연산 결과 값
*/
#define ISC_AND(x,y)		(x&y)

/*!
* \brief
* 두 변수 값을 OR 연산하는 매크로
* \param x
* 변수 x
* \param y
* 변수 y
* \returns
* OR 연산 결과 값
*/
#define ISC_OR(x,y)			(x|y)

#ifdef WIN32
/*!
* \brief
* 4Byte변수 값을  y만큼 Left Circular Shift하는 매크로
* \param x
* 값을 바꿀 변수
* \param y
* shift 변수
* \returns
* Left Circular Shift 결과 값
*/
#define ISC_ROLc(x, y)    _lrotl((x), (y))

/*!
* \brief
* 4Byte변수 값을  y만큼 Right Circular Shift하는 매크로
* \param x
* 값을 바꿀 변수
* \param y
* shift 변수
* \returns
* Right Circular Shift 결과 값
*/
#define ISC_RORc(x, y)    _lrotr((x), (y))

#define ISC_ROTL64(x,r)	_rotl64(x,r)
#define ISC_ROTR64(x,r)	_rotr64(x,r)

#else

#define ISC_ROLc(x, y) ((((uint32)(x)<<(uint32)((y)&31)) | (((uint32)(x)&0xFFFFFFFFU)>>(uint32)(32-((y)&31)))) & 0xFFFFFFFFU)
#define ISC_RORc(x, y) (((((uint32)(x)&0xFFFFFFFFU)>>(uint32)((y)&31)) | ((uint32)(x)<<(uint32)(32-((y)&31)))) & 0xFFFFFFFFU)
#define ISC_ROTL64(x,r)	((x) << (r)) | ((x) >> (64-r))
#define ISC_ROTR64(x,r)	((x) >> (r)) | ((x) << (64-r))

#endif

/*!
* \brief
* ISC_ROLc(x, y)와 동일한 기능
*/
#define ISC_ROTL(x, y) ISC_ROLc(x, y)

/*!
* \brief
* ISC_RORc(x, y)와 동일한 기능
*/
#define ISC_ROTR(x,r) ISC_RORc(x,r)
#define ISC_RORL(x, y) ISC_RORc(x, y)


/*!
* \brief
* 두 값 중에서 큰 값을 구하는 매크로
* \param x
* 변수 x
* \param y
* 변수 y
* \returns
* 큰 값
*/
#ifdef MAX
#undef MAX
#endif
#define ISC_MAX(x, y) ( ((x)>(y))?(x):(y) )

/*!
* \brief
* 두 값 중에서 작은 값을 구하는 매크로
* \param x
* 변수 x
* \param y
* 변수 y
* \returns
* 작은 값
*/
#ifdef MIN
#undef MIN
#endif
#define ISC_MIN(x, y) ( ((x)<(y))?(x):(y) )

#define ISC_UPPER_STRING(x) (
#ifdef __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* File을 바이너리 데이터로 변환하는 함수
* \param pFName
* File 이름 문자열의 포인터, Ex)"D:\\test.der"
* \param buffer
* 바이너리를 저장할 버퍼의 이중 포인터
* \returns
* -# 변환된 바이너리의 길이(Byte) : 성공
* -# -1 : 실패
*/
ISC_INTERNAL int isc_File_To_Binary(const char *pFName, unsigned char **buffer);

/*!
* \brief
* 바이너리 데이터를 File로 변환하는 함수
* \param buffer
* 바이너리 데이터의 포인터
* \param offset
* 바이너리를 쓰기 시작할 File의 Offset
* \param length
* 바이너리의 길이(Byte)
* \param fileName
* File 이름 문자열의 포인터, Ex)"D:\\test.der"
* \returns
* -# 파일에 쓰여진 길이 : 성공
* -# -1 : 실패
*/
ISC_INTERNAL int isc_Binary_To_File(unsigned char *buffer, int offset, int length, const char *fileName);


/*!
* \brief
* Byte 배열을 16진수 형태로 출력하는 함수 (문자열 끝 개행)
* \param octet
* 출력할 배열의 포인터
* \param len
* 배열의 길이
*/
ISC_INTERNAL void isc_Print_HEX(const uint8 *octet, int len);

/*!
* \brief
* Byte 배열을 16진수 형태로 출력하는 함수 (출력값이 없더라도 무조건 개행)
* \param octet
* 출력할 배열의 포인터
* \param len
* 배열의 길이
*/
ISC_INTERNAL void isc_Print_HEX_Nl(const uint8 *octet, int len);

/*!
* \brief
* Byte 배열을 16진수 형태로 출력하는 함수 (개행 없음)
* \param octet
* 출력할 배열의 포인터
* \param len
* 배열의 길이
*/
ISC_INTERNAL void isc_Print_HEX_No_Nl(const uint8 *octet, int len);

/*!
* \brief
* Byte 배열을 16진수 형태로 반환하는 함수
* \param octet
* 출력할 배열의 포인터
* \param len
* 배열의 길이
* \returns
* 16진수 형태의 문자열 (외부에서 메모리 해제 필요 [ISC_MEM_FREE])
*/
ISC_INTERNAL char* isc_Dump_HEX(const uint8 *octet, int len);

ISC_INTERNAL char* isc_Dump_HEX_Ex(const uint8 *octet, int len);

ISC_INTERNAL float isc_check_operation_time(int flag);
    
#else

ISC_RET_LOADLIB_CRYPTO(int, isc_File_To_Binary, (const char *pFName, unsigned char **buffer), (pFName, buffer), 0 );
ISC_RET_LOADLIB_CRYPTO(int, isc_Binary_To_File, (unsigned char *buffer, int offset, int length, const char *fileName), (buffer, offset, length, fileName), 0 );
ISC_VOID_LOADLIB_CRYPTO(void, isc_Print_HEX, (const uint8 *octet, int len), (octet, len) );
ISC_VOID_LOADLIB_CRYPTO(void, isc_Print_HEX_Nl, (const uint8 *octet, int len), (octet, len) );
ISC_VOID_LOADLIB_CRYPTO(void, isc_Print_HEX_No_Nl, (const uint8 *octet, int len), (octet, len) );
ISC_RET_LOADLIB_CRYPTO(char*, isc_Dump_HEX, (const uint8 *octet, int len), (octet, len), NULL );

#endif

#ifdef __cplusplus
}
#endif

#endif /* !HEADER_UTILS_H */
