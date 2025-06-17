/*!
* \file mem.h
* \brief memory 
* \remarks
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_MEMORY_H
#define HEADER_MEMORY_H

#include <stdio.h>

#include "foundation.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#ifndef ISC_BADA
#include <memory.h>
#endif

/* 자체 Memory Allocator 사용(Debug 용)*/
#define ISC_MEM_CPY(s1,s2,n)				memcpy((s1),(s2),(n))
#define ISC_MEM_MOVE(s1,s2,n)				memmove((s1),(s2),(n))
#define ISC_MEM_SET(s1,c,n)					memset((s1),(c),(n))
#define ISC_MEM_CMP(s1,s2,n)				memcmp((s1),(s2),(n))
#define ISC_MEM_ALLOC(x)					ISC_Malloc(x, __FILE__, __LINE__)
#define ISC_MEM_CALLOC(x,s)					ISC_Calloc(x, s, __FILE__, __LINE__)
#define ISC_MEM_FREE(x)						ISC_Free(x, __FILE__, __LINE__) 
#define ISC_MEM_REALLOC(x,newsize)			ISC_Realloc(x,newsize,__FILE__,__LINE__)
#define ISC_MEM_FREE_EX(x,s)				ISC_Free_Ex(x,s,__FILE__,__LINE__)  /*memset memfree*/ 

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
 * 디버깅용 메모리 할당
 * \param size
 * 할당 사이즈
 * \param file
 * 호출하는 파일
 * \param line
 * 호출하는 라인
 * \return
 * 할당된 void 포인터
*/
ISC_API void *ISC_Malloc(size_t size, const char *file, int line);

/*!
* \brief
 * 디버깅용 메모리 할당 및 메모리 0 으로 초기화 (calloc) * 
 * \param num
 * 할당 메모리 갯수
 * \param size
 * 할당 메모리 크기
 * \param file
 * 호출하는 파일
 * \param line
 * 호출하는 라인
 * \return
 * 할당된 void 포인터
*/
ISC_API void *ISC_Calloc(size_t num, size_t size, const char *file, int line);

/*!
* \brief
 * 디버깅용 메모리 해제 
 * \param x
 * 해제할 포인터
 * \param file
 * 호출하는 파일
 * \param line
 * 호출하는 라인
*/
ISC_API void ISC_Free(void *x, const char *file, int line);

/*!
* \brief
 * 디버깅용 메모리 재할당
 * \param x
 * 재할당할 메모리 포인터
 * \param newsize
 * 새로운 사이즈
 * \param file
 * 호출하는 파일
 * \param line
 * 호출하는 라인
*/
ISC_API void *ISC_Realloc(void *x, size_t newsize, const char *file, int line);

/*!
* \brief
 * 메모리 해제
 * \param x
 * 해제할 포인터
 * \param len
 * 해제할 메모리 사이즈
 */
ISC_API void ISC_Free_Ex(void *x, int len, const char *file, int line); /* 외부에서 사용할 수 있도록 추가한 함수 */



ISC_API void ini_stats(void);

#else
ISC_RET_LOADLIB_CRYPTO(void*, ISC_Malloc, (size_t size, const char *file, int line), (size, file, line), NULL );
ISC_RET_LOADLIB_CRYPTO(void*, ISC_Calloc, (size_t num, size_t size, const char *file, int line), (num, size, file, line), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free, (void *x, const char *file, int line), (x, file, line));
ISC_RET_LOADLIB_CRYPTO(void*, ISC_Realloc, (void *x, size_t newsize, const char *file, int line), (x, newsize, file, line), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_Ex, (void *x, int len), (x, len));

#endif

#ifdef __cplusplus
}
#endif

#endif /* !HEADER_MEMORY_H */

