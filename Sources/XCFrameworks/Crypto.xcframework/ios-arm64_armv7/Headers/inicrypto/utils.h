/*!
* \file utils.h
* \brief Utility Functions�� Macro ����
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_UTILS_H
#define HEADER_UTILS_H

#include <stdlib.h>

#include "foundation.h"

/*!
* \brief
* 4Byte�迭�� 4Byte������ �ٲٴ� ��ũ��\n
* ex) char c[4] -> int c
* \param os
* 4Byte�迭�� ������
* \returns
* 4Byte��
*/
# define ISC_OS2I(os) (((uint32)(os)[0] << 24) ^ ((uint32)(os)[1] << 16) ^ ((uint32)(os)[2] <<  8) ^ ((uint32)(os)[3]))

/*!
* \brief
* 4Byte���� 4Byte�迭�� �ٲٴ� ��ũ��\n
* ex) int i -> char c[4]
* \param os
* 4Byte�迭�� ������
* \param i
* 4Byte���� ���� ����
*/
# define ISC_I2OS(os, i) { (os)[0] = (uint8)((i) >> 24); (os)[1] = (uint8)((i) >> 16); (os)[2] = (uint8)((i) >>  8); (os)[3] = (uint8)(i); }

/*!
* \brief
* 8Byte�迭�� 8Byte������ �ٲٴ� ��ũ��\n
* ex) char c[8] -> long long c
* \param os
* 8Byte�迭�� ������
* \returns
* 8Byte���� ��
*/
# define ISC_OS2L(os) (((uint32)(os)[0] << 56) ^ ((uint32)(os)[1] << 48) ^ ((uint32)(os)[2] <<  40) ^ ((uint32)(os)[3] << 32) \
				^ ((uint32)(os)[4] << 24) ^ ((uint32)(os)[5] << 16) ^ ((uint32)(os)[6] << 8) ^ ((uint32)(os)[7]))

/*!
* \brief
* 8Byte���� 8Byte�迭�� �ٲٴ� ��ũ��\n
* ex) long long i -> char c[8]
* \param os
* 8Byte�迭�� ������
* \param i
* 8Byte���� ���� ����
*/
# define ISC_L2OS(os, i) {(os)[0] = (uint8)((i) >> 56); (os)[1] = (uint8)((i) >> 48); (os)[2] = (uint8)((i) >>  40); \
				(os)[3] = (uint8)((i) >> 32); (os)[4] = (uint8)((i) >> 24); (os)[5] = (uint8)((i) >> 16); \
				(os)[6] = (uint8)((i) >> 8); (os)[7] = (uint8)(i);}

/*!
* \brief
* ������ n��° Byte ���� �����ϴ� ��ũ��\n
* �ε����� 0���� ����
* \param x
* ���� ���� �� ����
* \param n
* �ε��� n
* \returns
* ����� ��
*/
#define ISC_BYTE(x, n) (((x) >> (8 * (n))) & 255)

/*!
* \brief
* 4Byte ������ bit�迭�� ������ �ٲٴ� ��ũ��\n
* ex) 10100011 -> 11000101
* \param x
* ���� �ٲ� ����
* \returns
* �ٲ� ��
*/
#define ISC_SWAP(x) (ISC_ROLc(x, 8) & 0x00ff00ff | ISC_RORc(x, 8) & 0xff00ff00)

/*!
* \brief
* �� ���� ���� XOR �����ϴ� ��ũ��
* \param x
* ���� x
* \param y
* ���� y
* \returns
* XOR ���� ��� ��
*/
#define ISC_XOR(x,y)		(x^y)

/*!
* \brief
* �� ���� ���� AND �����ϴ� ��ũ��
* \param x
* ���� x
* \param y
* ���� y
* \returns
* AND ���� ��� ��
*/
#define ISC_AND(x,y)		(x&y)

/*!
* \brief
* �� ���� ���� OR �����ϴ� ��ũ��
* \param x
* ���� x
* \param y
* ���� y
* \returns
* OR ���� ��� ��
*/
#define ISC_OR(x,y)			(x|y)

#ifdef WIN32
/*!
* \brief
* 4Byte���� ����  y��ŭ Left Circular Shift�ϴ� ��ũ��
* \param x
* ���� �ٲ� ����
* \param y
* shift ����
* \returns
* Left Circular Shift ��� ��
*/
#define ISC_ROLc(x, y)    _lrotl((x), (y))

/*!
* \brief
* 4Byte���� ����  y��ŭ Right Circular Shift�ϴ� ��ũ��
* \param x
* ���� �ٲ� ����
* \param y
* shift ����
* \returns
* Right Circular Shift ��� ��
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
* ISC_ROLc(x, y)�� ������ ���
*/
#define ISC_ROTL(x, y) ISC_ROLc(x, y)

/*!
* \brief
* ISC_RORc(x, y)�� ������ ���
*/
#define ISC_ROTR(x,r) ISC_RORc(x,r)
#define ISC_RORL(x, y) ISC_RORc(x, y)


/*!
* \brief
* �� �� �߿��� ū ���� ���ϴ� ��ũ��
* \param x
* ���� x
* \param y
* ���� y
* \returns
* ū ��
*/
#ifdef MAX
#undef MAX
#endif
#define ISC_MAX(x, y) ( ((x)>(y))?(x):(y) )

/*!
* \brief
* �� �� �߿��� ���� ���� ���ϴ� ��ũ��
* \param x
* ���� x
* \param y
* ���� y
* \returns
* ���� ��
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
* File�� ���̳ʸ� �����ͷ� ��ȯ�ϴ� �Լ�
* \param pFName
* File �̸� ���ڿ��� ������, Ex)"D:\\test.der"
* \param buffer
* ���̳ʸ��� ������ ������ ���� ������
* \returns
* -# ��ȯ�� ���̳ʸ��� ����(Byte) : ����
* -# -1 : ����
*/
ISC_INTERNAL int isc_File_To_Binary(const char *pFName, unsigned char **buffer);

/*!
* \brief
* ���̳ʸ� �����͸� File�� ��ȯ�ϴ� �Լ�
* \param buffer
* ���̳ʸ� �������� ������
* \param offset
* ���̳ʸ��� ���� ������ File�� Offset
* \param length
* ���̳ʸ��� ����(Byte)
* \param fileName
* File �̸� ���ڿ��� ������, Ex)"D:\\test.der"
* \returns
* -# ���Ͽ� ������ ���� : ����
* -# -1 : ����
*/
ISC_INTERNAL int isc_Binary_To_File(unsigned char *buffer, int offset, int length, const char *fileName);


/*!
* \brief
* Byte �迭�� 16���� ���·� ����ϴ� �Լ� (���ڿ� �� ����)
* \param octet
* ����� �迭�� ������
* \param len
* �迭�� ����
*/
ISC_INTERNAL void isc_Print_HEX(const uint8 *octet, int len);

/*!
* \brief
* Byte �迭�� 16���� ���·� ����ϴ� �Լ� (��°��� ������ ������ ����)
* \param octet
* ����� �迭�� ������
* \param len
* �迭�� ����
*/
ISC_INTERNAL void isc_Print_HEX_Nl(const uint8 *octet, int len);

/*!
* \brief
* Byte �迭�� 16���� ���·� ����ϴ� �Լ� (���� ����)
* \param octet
* ����� �迭�� ������
* \param len
* �迭�� ����
*/
ISC_INTERNAL void isc_Print_HEX_No_Nl(const uint8 *octet, int len);

/*!
* \brief
* Byte �迭�� 16���� ���·� ��ȯ�ϴ� �Լ�
* \param octet
* ����� �迭�� ������
* \param len
* �迭�� ����
* \returns
* 16���� ������ ���ڿ� (�ܺο��� �޸� ���� �ʿ� [ISC_MEM_FREE])
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
