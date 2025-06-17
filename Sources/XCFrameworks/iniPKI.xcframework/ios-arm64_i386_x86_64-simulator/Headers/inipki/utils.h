/*!
* \file utils.h
* \brief Utility Functions�� Macro ����
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
* File�� ���̳ʸ� �����ͷ� ��ȯ�ϴ� �Լ�
* \param fileName
* File �̸� ���ڿ��� ������, Ex)"D:\\test.der"
* \param buffer
* ���̳ʸ��� ������ ������ ���� ������
* \returns
* -# ��ȯ�� ���̳ʸ��� ����(Byte) : ����
* -# -1 : ����
*/
ISC_API int File_to_binary(const char *fileName, unsigned char **buffer);

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
ISC_API int binary_to_File(unsigned char *buffer, int offset, int length, const char *fileName);


/*!
* \brief
* Byte �迭�� 16���� ���·� ����ϴ� �Լ� (���ڿ� �� ����)
* \param octet
* ����� �迭�� ������
* \param len
* �迭�� ����
*/
ISC_API void IPL_print_hex(const uint8 *octet, int len);

/*!
* \brief
* Byte �迭�� 16���� ���·� ����ϴ� �Լ� (��°��� ������ ������ ����)
* \param octet
* ����� �迭�� ������
* \param len
* �迭�� ����
*/
ISC_API void IPL_print_hex_nl(const uint8 *octet, int len);

/*!
* \brief
* Byte �迭�� 16���� ���·� ����ϴ� �Լ� (���� ����)
* \param octet
* ����� �迭�� ������
* \param len
* �迭�� ����
*/
ISC_API void IPL_print_hex_no_nl(const uint8 *octet, int len);

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
ISC_API char* dump_hex(const uint8 *octet, int len);


#ifdef __cplusplus
}
#endif

