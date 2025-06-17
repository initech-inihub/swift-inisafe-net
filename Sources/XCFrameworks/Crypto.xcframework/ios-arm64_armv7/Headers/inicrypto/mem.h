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

/* ��ü Memory Allocator ���(Debug ��)*/
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
 * ������ �޸� �Ҵ�
 * \param size
 * �Ҵ� ������
 * \param file
 * ȣ���ϴ� ����
 * \param line
 * ȣ���ϴ� ����
 * \return
 * �Ҵ�� void ������
*/
ISC_API void *ISC_Malloc(size_t size, const char *file, int line);

/*!
* \brief
 * ������ �޸� �Ҵ� �� �޸� 0 ���� �ʱ�ȭ (calloc) * 
 * \param num
 * �Ҵ� �޸� ����
 * \param size
 * �Ҵ� �޸� ũ��
 * \param file
 * ȣ���ϴ� ����
 * \param line
 * ȣ���ϴ� ����
 * \return
 * �Ҵ�� void ������
*/
ISC_API void *ISC_Calloc(size_t num, size_t size, const char *file, int line);

/*!
* \brief
 * ������ �޸� ���� 
 * \param x
 * ������ ������
 * \param file
 * ȣ���ϴ� ����
 * \param line
 * ȣ���ϴ� ����
*/
ISC_API void ISC_Free(void *x, const char *file, int line);

/*!
* \brief
 * ������ �޸� ���Ҵ�
 * \param x
 * ���Ҵ��� �޸� ������
 * \param newsize
 * ���ο� ������
 * \param file
 * ȣ���ϴ� ����
 * \param line
 * ȣ���ϴ� ����
*/
ISC_API void *ISC_Realloc(void *x, size_t newsize, const char *file, int line);

/*!
* \brief
 * �޸� ����
 * \param x
 * ������ ������
 * \param len
 * ������ �޸� ������
 */
ISC_API void ISC_Free_Ex(void *x, int len, const char *file, int line); /* �ܺο��� ����� �� �ֵ��� �߰��� �Լ� */



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

