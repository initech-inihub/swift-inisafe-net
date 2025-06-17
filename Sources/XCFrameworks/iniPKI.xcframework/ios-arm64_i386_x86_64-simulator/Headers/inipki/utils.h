/*!
* \file utils.h
* \brief Utility Functions과 Macro 정의
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#define HEADER_UTILS_H

#include <stdlib.h>

#include <inicrypto/foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
* \brief
* File을 바이너리 데이터로 변환하는 함수
* \param fileName
* File 이름 문자열의 포인터, Ex)"D:\\test.der"
* \param buffer
* 바이너리를 저장할 버퍼의 이중 포인터
* \returns
* -# 변환된 바이너리의 길이(Byte) : 성공
* -# -1 : 실패
*/
ISC_API int File_to_binary(const char *fileName, unsigned char **buffer);

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
ISC_API int binary_to_File(unsigned char *buffer, int offset, int length, const char *fileName);


/*!
* \brief
* Byte 배열을 16진수 형태로 출력하는 함수 (문자열 끝 개행)
* \param octet
* 출력할 배열의 포인터
* \param len
* 배열의 길이
*/
ISC_API void IPL_print_hex(const uint8 *octet, int len);

/*!
* \brief
* Byte 배열을 16진수 형태로 출력하는 함수 (출력값이 없더라도 무조건 개행)
* \param octet
* 출력할 배열의 포인터
* \param len
* 배열의 길이
*/
ISC_API void IPL_print_hex_nl(const uint8 *octet, int len);

/*!
* \brief
* Byte 배열을 16진수 형태로 출력하는 함수 (개행 없음)
* \param octet
* 출력할 배열의 포인터
* \param len
* 배열의 길이
*/
ISC_API void IPL_print_hex_no_nl(const uint8 *octet, int len);

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
ISC_API char* dump_hex(const uint8 *octet, int len);


#ifdef __cplusplus
}
#endif

