/*!
* \file asn1.h
* \brief ASN.1 BER,DER Encoder/Decoder
* Abstract Syntax Notation One
* Basic Encoding Rules
* Distinguished Encoding Rules
* \remarks
* ASN.1 BER,DER ���� ����ü �� �Լ� ���� ��� ����
* ITU-T X.690 ������ �������� �ۼ��Ǿ���
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_ASN1_H
#define HEADER_ASN1_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <time.h>

#include <inicrypto/foundation.h>
#include <inicrypto/biginteger.h>

#define UNIVERSAL					0x00	/*!< Universal Class Tag*/
#define APPLICATION					0x40	/*!< Application Class Tag*/ 
#define CONTEXT_SPECIFIC			0x80	/*!< Context-specific Class Tag*/
#define PRIVATE						0xC0	/*!< Private Class Tag*/
	
#define PRIMITIVE					0x00	/*!< Primitive Type*/
#define CONSTRUCTED					0x20	/*!< Constructed Type*/

/* P = Primitive, C = Constructed */
#define EOC_TYPE   					0x00	/*!< End-of-contents*/
#define BOOLEAN_TYPE				0x01	/*!< BOOLEAN(P)*/
#define INTEGER_TYPE				0x02	/*!< INTEGER(P)*/
#define BIT_STRING_TYPE				0x03	/*!< BIT STRING(P/C)*/
#define OCTET_STRING_TYPE			0x04	/*!< OCTET STRING(P/C)*/
#define NULL_TYPE					0x05	/*!< NULL(P)*/
#define OBJECT_IDENTIFIER_TYPE		0x06	/*!< OBJECT IDENTIFIER(P)*/
#define ENUMERATED_TYPE				0x0A	/*!< ENUMERATED(P)*/	
#define UTF8_STRING_TYPE			0x0C	/*!< UTF8String(P/C)*/
#define SEQUENCE_TYPE				0x10	/*!< SEQUENCE(C)*/

/* 
 * SEQUENCE_OF ���� ���� 0x10�� SEQUENCE�� ������
 * ���� üũ ������ ���� �Ͽ��� 
 */
#define SEQUENCE_OF_TYPE			0x30	/*!< SEQUENCE OF(C)*/ 
#define SET_TYPE					0x11	/*!< SET(C)*/
/* 
 * SET_OF ���� ���� 0x11�� SET�� ������
 * ���� üũ ������ ���� �Ͽ��� 
 */
#define SET_OF_TYPE					0x31	/*!< SET OF(C)*/ 
#define PRINTABLE_STRING_TYPE		0x13	/*!< PrintableString(P/C)*/
#define T61_STRING_TYPE				0x14	/*!< T61String(P/C)*/
#define IA5_STRING_TYPE				0x16	/*!< IA5String(P/C)*/
#define UTC_TIME_TYPE				0x17	/*!< UTCTime(P/C)*/
#define GENERALIZED_TIME_TYPE		0x18	/*!< GeneralizedTime(P/C)*/
#define VISIBLE_STRING_TYPE			0x1A	/*!< VisibleString(P/C)*/
#define	ISO646_STRING_TYPE			0x1A	/*!< ISO646String(P/C)*/
#define BMP_STRING_TYPE				0x1E	/*!< BMPString(P/C)*/

#define ASN1_STRING_TYPE			0x20	/*!< ASN1�� ��� Type�� ����Ŵ*/
#define STRING_SEQUENCE_TYPE		0x21	/*!< Constructed�� ������ String Type(for BER)*/

#define SHORT_FORM					0x00	/*!< Short Form(���� 0 ~ 127)*/
#define LONG_FORM					0x01	/*!< Long Form(���� 128 �̻�)*/
#define INDEFINITE_FORM				0x02	/*!< Indefinite Form(���� ���� ����, for BER)*/

/* UTC_TIME_TYPE���� ���̴� ����� */
#define UTC_TIME_FORM				0x00	/*!< Universal Time Coordinated Form*/
#define LOCAL_TIME_FORM				0x00	/*!< Local Time Form*/
#define GMT_TIME_FORM				0x01	/*!< Greenwich Mean Time Form*/

#define YYMMDDhhmmZ					0x00	/*!< YY(��)MM(��)DD(��)hh(��)mm(��)Z(GMT)*/
#define YYMMDDhhmm_hhmm				0x01	/*!< YY(��)MM(��)DD(��)hh(��)mm(��)+,-hh(��)mm(��)*/
#define YYMMDDhhmmssZ				0x02	/*!< YY(��)MM(��)DD(��)hh(��)mm(��)ss(��)Z(GMT)*/
#define YYMMDDhhmmss_hhmm			0x03	/*!< YY(��)MM(��)DD(��)hh(��)mm(��)ss(��)+,-hh(��)mm(��)*/

#define YYYYMMDDhhmmZ				0x10	/*!< YYYY(��)MM(��)DD(��)hh(��)mm(��)Z(GMT)*/
#define YYYYMMDDhhmm_hhmm			0x11	/*!< YYYY(��)MM(��)DD(��)hh(��)mm(��)+,-hh(��)mm(��)*/
#define YYYYMMDDhhmmssZ				0x12	/*!< YYYY(��)MM(��)DD(��)hh(��)mm(��)ss(��)Z(GMT)*/
#define YYYYMMDDhhmmss_hhmm			0x13	/*!< YYYY(��)MM(��)DD(��)hh(��)mm(��)ss(��)+,-hh(��)mm(��)*/

#define ASN1_TRUE	0xFF
#define ASN1_FALSE	0x00

#ifdef  __cplusplus
extern "C" {
#endif


#ifdef WIN32
#undef OBJECT_IDENTIFIER
#undef INTEGER
#undef UTC_TIME
#endif

/*!
* \brief
* ASN.1 Encoding�� ����� �����ϴ� ����ü
*/
typedef struct ASN1_UNIT_structure {
	uint8 *Tag;		/*!< Identifier octets(Tag)�� ������*/
	uint8 *Length;	/*!< Length octets�� ������*/
	uint8 *Value;	/*!< Contents octets(Value)�� ������*/
	uint8 *EOC;		/*!< End-of-contents octets(for Indefinite Form)�� ������*/
} ASN1_UNIT;

/*!
* \brief
* ASN1_STRING�� ������ ��� ����ü
*/
typedef struct asn1_string_structure {
	int type;		/*!< ����ִ� Data�� Type*/	
	uint8 *data;	/*!< Data�� ����Ű�� ������*/
	int length;		/*!< Data�� ����*/
	int opt;		/*!< Option : Unused Bit(for BIT_STRING_TYPE), Time Type(for UTC_TIME_TYPE)*/
} ASN1_STRING;

/*!
* \brief
* STRING_SEQUENCE(Constructed String)�� ������ ��� ����ü
* \remarks
* ANS1_UNIT ����ü ������
*/
typedef ASN1_UNIT STRING_SEQUENCE;

/*!
* \brief
* ASN1_TIME�� ������ ��� ����ü
* \remarks
* time.h�� tm ����ü ������
*/
typedef struct tm ASN1_TIME;

/*!
* \brief
* BOOLEAN Ÿ��
* \remarks
* unsigned char Ÿ�� ������
*/
typedef uint8 BOOLEAN;

/*!
* \brief
* INTEGER�� ������ ��� ����ü
* \remarks
* ISC_BIGINT ����ü ������
*/
typedef ISC_BIGINT INTEGER;

/*!
* \brief
* BIT_STRING�� ������ ��� ����ü
* \remarks
* ASN1_STRING ����ü ������
*/
typedef ASN1_STRING BIT_STRING;

/*!
* \brief
* OCTET_STRING�� ������ ��� ����ü
* \remarks
* ASN1_STRING ����ü ������
*/
typedef ASN1_STRING OCTET_STRING;

/*!
* \brief
* NULL Ÿ��
* \remarks
* int Ÿ�� ������
*/
typedef int NULL_VALUE;

/*!
* \brief
* OBJECT_IDENTIFIER�� ������ ��� ����ü
* \remarks
* ASN1_STRING ����ü ������
*/
typedef ASN1_STRING OBJECT_IDENTIFIER;

/*!
* \brief
* ENUMERATED�� ������ ��� ����ü
* \remarks
* ISC_BIGINT ����ü ������
*/
typedef ISC_BIGINT ENUMERATED;

/*!
* \brief
* UTF8_STRING�� ������ ��� ����ü
* \remarks
* ASN1_STRING ����ü ������
*/
typedef ASN1_STRING UTF8_STRING;

/*!
* \brief
* SEQUENCE�� ������ ��� ����ü
* \remarks
* ASN1_UNIT ����ü ������
*/
typedef ASN1_UNIT SEQUENCE;

/*!
* \brief
* SEQUENCE_OF�� ������ ��� ����ü
* \remarks
* ASN1_UNIT ����ü ������
*/
typedef ASN1_UNIT SEQUENCE_OF;

/*!
* \brief
* SET�� ������ ��� ����ü
* \remarks
* ASN1_UNIT ����ü ������
*/
typedef ASN1_UNIT SET;

/*!
* \brief
* SET_OF�� ������ ��� ����ü
* \remarks
* ASN1_UNIT ����ü ������
*/
typedef ASN1_UNIT SET_OF;

/*!
* \brief
* PRINTABLE_STRING�� ������ ��� ����ü
* \remarks
* ASN1_STRING ����ü ������
*/
typedef ASN1_STRING PRINTABLE_STRING;

/*!
* \brief
* T61_STRING�� ������ ��� ����ü
* \remarks
* ASN1_STRING ����ü ������
*/
typedef ASN1_STRING T61_STRING;

/*!
* \brief
* IA5_STRING�� ������ ��� ����ü
* \remarks
* ASN1_STRING ����ü ������
*/
typedef ASN1_STRING IA5_STRING;

/*!
* \brief
* UTC_TIME�� ������ ��� ����ü
* \remarks
* ASN1_STRING ����ü ������
*/
typedef ASN1_STRING UTC_TIME;

/*!
* \brief
* GENERALIZED_TIME�� ������ ��� ����ü
* \remarks
* ASN1_STRING ����ü ������
*/
typedef ASN1_STRING GENERALIZED_TIME;

/*!
* \brief
* BMP_STRING�� ������ ��� ����ü
* \remarks
* ASN1_STRING ����ü ������
*/
typedef ASN1_STRING BMP_STRING;


typedef ISC_STATUS (*PWRITE_FUNC)(void *p_st, SEQUENCE **seq);
typedef ISC_STATUS (*PREAD_FUNC)(SEQUENCE *seq, void *structure);

#ifndef WIN_INI_LOADLIBRARY_PKI

/************************************************
*												*
*		ASN.1(Abstract Syntax Notation One)		*
*												*
************************************************/
/*!
* \brief
* ASN1_UNIT ����ü�� �����ϴ� �Լ�
* \returns
* ������ ASN1_UNIT ����ü�� ������
*/
ISC_API ASN1_UNIT *new_ASN1_UNIT(void);

/*!
* \brief
* ASN1_UNIT ����ü�� �޸� ���� �Լ�
* \param asn1Unit
* �޸𸮸� ������ ASN1_UNIT ����ü�� ������
*/
ISC_API void free_ASN1_UNIT(ASN1_UNIT *asn1Unit);

/*!
* \brief
* ASN1_UNIT ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param asn1Unit
* ���� �ʱ�ȭ �� ASN1_UNIT ����ü�� ������
*/
ISC_API void clean_ASN1_UNIT(ASN1_UNIT *asn1Unit);

/*!
* \brief
* ASN1_UNIT ����ü�� �����ϴ� �Լ�
* \param asn1Unit
* ������ ���� ASN1_UNIT ����ü�� ������
* \returns
* ����� ASN1_UNIT ����ü�� ������
*/
ISC_API ASN1_UNIT * dup_ASN1_UNIT(ASN1_UNIT *asn1Unit);

/*!
* \brief
* ASN1_STRING ����ü�� �����ϴ� �Լ�
* \returns
* ������ ASN1_STRING ����ü�� ������
*/
ISC_API ASN1_STRING *new_ASN1_STRING(void);

/*!
* \brief
* ASN1_STRING ����ü�� �޸� ���� �Լ�
* \param asn1String
* �޸𸮸� ������ ASN1_STRING ����ü�� ������
*/
ISC_API void free_ASN1_STRING(ASN1_STRING *asn1String);

/*!
* \brief
* ASN1_STRING ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param asn1String
* ���� �ʱ�ȭ �� ASN1_STRING ����ü�� ������
*/
ISC_API void clean_ASN1_STRING(ASN1_STRING *asn1String);

/*!
* \brief
* ASN1_STRING ����ü�� ���� �����ϴ� �Լ�
* \param asn1String
* ���� ������ ASN1_STRING ����ü�� ������
* \param type
* ASN1_STRING Data�� Ÿ��
* \param data
* ������ Data�� ������
* \param dLen
* ������ Data�� ����
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SET_ASN1_STRING_VALUE^ISC_ERR_NULL_INPUT : �Է°��� NULL�� ���
*/
ISC_API ISC_STATUS set_ASN1_STRING_value(ASN1_STRING *asn1String, int type, const uint8* data, int dLen);

/*!
* \brief
* ASN1_STRING ����ü�� SEQUENCE ����ü�� ��ȯ�ϴ� �Լ�
* \param asn1String
* ��ȯ�� ASN1_STRING ����ü�� ������
* \param seq
* SEQUENCE ����ü�� ���� ������
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ASN1_STRING_TO_SEQ^ISC_ERR_NULL_INPUT : �Է°��� NULL�� ���
* -# LOCATION^F_ASN1_STRING_TO_SEQ^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS ASN1_STRING_to_Seq(ASN1_STRING *asn1String, SEQUENCE **seq);

/*!
* \brief
* ASN1_STRING ����ü�� �����ϴ� �Լ�
* \param asn1String
* ������ ���� ASN1_STRING ����ü�� ������
* \returns
* ����� ASN1_STRING ����ü�� ������
*/
ISC_API ASN1_STRING* dup_ASN1_STRING(ASN1_STRING *asn1String);

/*!
* \brief
* ASN1_STRING ����ü�� ���� ���ϴ� �Լ�
* \param a
* ����
* \param b
* �񱳴��
* \returns
* �� ���(0 = equal)
*/
ISC_API int cmp_ASN1_STRING(ASN1_STRING *a, ASN1_STRING *b);

/*!
* \brief
* ASN1_TIME ����ü�� �����ϴ� �Լ�
* \returns
* ������ ASN1_TIME ����ü�� ������
*/
ISC_API ASN1_TIME *new_ASN1_TIME(void);

/*!
* \brief
* ���ڿ��� ASN1_TIME ����ü�� ��ȯ�ϴ� �Լ�
* ���ڿ� ���� = YYYY-MM-DD,hh:mm:ss
* Ex) 2008-12-25,23:24:35
* \param data
* �ð������� ��� �ִ� ���ڿ��� ������
* \returns
* ��ȯ�� ASN1_TIME ����ü�� ������
*/

ISC_API ASN1_TIME *charToASN1_TIME(const char *data);
/*!
* \brief
* ASN1_TIME ����ü�� �޸� ���� �Լ�
* \param asn1Time
* �޸𸮸� ������ ASN1_TIME ����ü�� ������
*/
ISC_API void free_ASN1_TIME(ASN1_TIME *asn1Time);
/*!
* \brief
* ASN1_TIME ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param asn1Time
* ���� �ʱ�ȭ �� ASN1_TIME ����ü�� ������
*/
ISC_API void clean_ASN1_TIME(ASN1_TIME *asn1Time);
/*!
* \brief
* ASN1_TIME�� ���� üũ�ϴ� �Լ�
* \param asn1Time
* ASN1_TIME ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CHECK_ASN1_TIME^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ���� 
* \remarks
* ��(Month)�� ���� : 0(1��) ~ 11(12��)
* ��(Hour)�� ���� : 0(����) ~ 23(11PM)
*/
ISC_API ISC_STATUS check_ASN1_TIME(ASN1_TIME asn1Time);
/*!
* \brief
* ASN1_TIME ����ü�� �����ϴ� �Լ�
* \param asn1Time
* ������ ���� ASN1_TIME ����ü�� ������
* \returns
* ����� ASN1_TIME ����ü�� ������
*/
ISC_API ASN1_TIME* dup_ASN1_TIME(ASN1_TIME *asn1Time); 
/*!
* \brief
* ����ð��� ASN1_TIME ����ü �������� ���ϴ� �Լ�
* \returns
* ����ð��� �����ϰ� �ִ� ASN1_TIME ����ü�� ������
*/
/*ISC_API ASN1_TIME *getCurrentTime(void);*//* delete*/
/*!
* \brief
* ����ð��� ASN1_TIME ����ü �������� ���ϴ� �Լ�
* \returns
* ����ð�(Local time)�� �����ϰ� �ִ� ASN1_TIME ����ü�� ������
*/
ISC_API ASN1_TIME *getCurrentLocalTime(void);
/*!
* \brief
* ����ð��� ASN1_TIME ����ü �������� ���ϴ� �Լ�
* \returns
* ����ð�(GM time)�� �����ϰ� �ִ� ASN1_TIME ����ü�� ������
*/
ISC_API ASN1_TIME *getCurrentGMTime(void);

/*!
* \brief
* ASN1_UNIT�� Length octets�� ũ�⸦ ���ϴ� �Լ�
* \param lengthOctet
* ASN1_UNIT�� Length octets�� ������
* \returns
* ASN1_UNIT�� Length octets�� ũ��(Byte)
*/
ISC_API int getASN1LengthSize(uint8 *lengthOctet);

/*!
* \brief
* ASN1_UNIT�� Contents octets�� ���̸� ���ϴ� �Լ�
* \param asn1Unit
* ASN1_UNIT�� ������
* \returns
* -# ASN1_UNIT�� Contents octets�� ����(Byte) : ����
* -# -1 : ����
*/
ISC_API int getASN1ValueLength(ASN1_UNIT *asn1Unit);

/*!
* \brief
* ASN1_UNIT�� Contents octets�� ���̸� ���ϴ� �Լ�(from Length octets)
* \param lengthOctet
* ASN1_UNIT�� Length octets�� ������
* \returns
* -# ASN1_UNIT�� Contents octets�� ����(Byte) : ����
* -# -1 : ����
*/
ISC_API int getASN1ValueLengthFromLO(uint8 *lengthOctet);

/*!
* \brief
* Indefinite Form ������ ASN1_UNIT�� Contents octets�� ���̸� ���ϴ� �Լ�
* \param contentsOctet
* ASN1_UNIT�� Contents octets�� ������
* \returns
* -# ASN1_UNIT�� Contents octets�� ����(Byte) : ����
* -# -1 : ����
*/
ISC_API int getASN1IndefiniteValueLength(uint8 *contentsOctet);

/*!
* \brief
* ������ Ascii String ���̸� ���ϴ� �Լ�
* \param number
* ������ ���� �����ϰ� �ִ� ����
* \returns
* Ascii String���� ��ȯ ���� ���� ����
*/
ISC_API int getAsciiStringLength(int number);

/*!
* \brief
* SEQUENCE ����ü�� �ڽ��� ������ ���ϴ� �Լ�
* \param sequence
* SEQUENCE ����ü�� ������
* \returns
* SEQUENCE ����ü�� �ڽ��� ����
*/
ISC_API int getSequenceChildNum(SEQUENCE *sequence);

/*!
* \brief
* SEQUENCE ����ü�� index��° �ִ� �ڽ��� Ÿ���� ���ϴ� �Լ�
* \param sequence
* SEQUENCE ����ü�� ������
* \param index
* SEQUENCE ����ü �ڽ��� index
* \returns
* -# SEQUENCE ����ü�� index��° �ִ� �ڽ��� Ÿ�� : ����
* -# -1 : ����
*/
ISC_API int getChildType(SEQUENCE *sequence, int index);

/*!
* \brief
* ASN1_UNIT�� Length Form�� ���ϴ� �Լ�
* \param type
* ASN1_UNIT�� Ÿ��
* \param valueLen
* ASN1_UNIT�� Contents octets�� ����
* \returns
* ASN1_UNIT�� Length Form
*/
ISC_API int getASN1LengthForm(int type, int valueLen);

/************************************************
*												*
*		CP949(Code Page 949, Windows ���ڿ�)		*
*												*
************************************************/ 
/*!
* \brief
* CP949(Windows)������ ���ڿ��� Unicode���·� ��ȯ�ϴ� �Լ�
* \param byte1
* ���ڿ��� ù ��° ����Ʈ
* \param byte2
* ���ڿ��� �� ��° ����Ʈ
* \returns
* ��ȯ�� Unicode ��
*/
ISC_API uint16 cp949ToUnicode(uint8 byte1, uint8 byte2);

/*!
* \brief
* CP949(Windows)������ ���ڿ��� UTF8(Unicode Transformation Format 8)���·� ��ȯ�ϴ� �Լ�
* \param data
* ���ڿ��� ������
* \param utf8
* UTF8 ���ڿ��� ������ ������ ���� ������
* \returns
* ��ȯ�� UTF8���ڿ��� ����
*/
ISC_API int cp949ToUTF8(const char *data, uint8 **utf8);

/*!
* \brief
* CP949(Windows)������ ���ڿ��� BMP(Basic Multilingual Plane)���·� ��ȯ�ϴ� �Լ�
* \param data
* ���ڿ��� ������
* \param bmp
* BMP ���ڿ��� ������ ������ ���� ������
* \returns
* ��ȯ�� BMP���ڿ��� ����
*/
ISC_API int cp949ToBMP(const char *data, uint8 **bmp);

/*!
* \brief
* Unicode�� CP949(Windows)������ ���ڿ��� ��ȯ�ϴ� �Լ�
* \param unicode
* Unicode���� �����ϰ� �ִ� ����
* \returns
* ��ȯ�� CP949���ڿ��� ������
*/
ISC_API uint8 *unicodeToCP949(long unicode);

/*!
* \brief
* UTF8_STRING ����ü�� CP949(Windows)������ ���ڿ��� ��ȯ�ϴ� �Լ�
* \param utf8String
* UTF8_STRING ����ü�� ������
* \param cp949
* CP949 ���ڿ��� ������ ������ ���� ������
* \returns
* ��ȯ�� CP949���ڿ��� ����
*/
ISC_API int utf8ToCP949(UTF8_STRING *utf8String, uint8 **cp949);

/*!
* \brief
* BMP_STRING ����ü�� CP949(Windows)������ ���ڿ��� ��ȯ�ϴ� �Լ�
* \param bmpString
* BMP_STRING ����ü�� ������
* \param cp949
* CP949 ���ڿ��� ������ ������ ���� ������
* \returns
* ��ȯ�� CP949���ڿ��� ����
*/
ISC_API int bmpToCP949(BMP_STRING *bmpString, uint8 **cp949);

/*!
* \brief
* Ascii������ ���ڿ��� Unicode�� ��ȯ�ϴ� �Լ�
* \param asc
* Ascii���ڿ��� ������
* \param asclen
* Ascii���ڿ��� ����
* \param uni
* Unicode�� ������ ������ ���� ������
* \param unilen
* Unicode�� ���̸� ������ ������ ������
* \returns
* ��ȯ�� Unicode�� ������
*/
ISC_API uint8 *ascTouni(const char *asc, int asclen, uint8 **uni, int *unilen);

/*!
* \brief
* Unicode�� Ascii������ ���ڿ��� ��ȯ�ϴ� �Լ�
* \param uni
* Unicode�� ������
* \param unilen
* Unicode�� ����
* \returns
* ��ȯ�� Ascii���ڿ��� ������
*/
ISC_API char *uniToasc(uint8 *uni, int unilen);


/************************************************
*												*
*	  UTC_TIME(Universal Time, Coordinated)		*
*												*
************************************************/
/*!
* \brief
* UTC_TIME ����ü�� ASN1_TIME ����ü ���·� ��ȯ�ϴ� �Լ�
* \param utcTime
* UTC_TIME ����ü�� ������
* \returns
* ��ȯ�� ASN1_TIME ����ü�� ������
*/
ISC_API ASN1_TIME *utcTimeToASN1_TIME(UTC_TIME *utcTime);

/*!
* \brief
* �ΰ��� UTC_TIME ����ü�� �ð��� ���ϴ� �Լ�
* \param utcTime1
* ù ��° UTC_TIME ����ü�� ������
* \param utcTime2
* �� ��° UTC_TIME ����ü�� ������
* \returns
* -# 1 : ù ��° UTC_TIME ����ü�� �ð��� ������ ���
* -# 0 : �� ����ü�� �ð��� ���� ���
* -# -1 : �� ��° UTC_TIME ����ü�� �ð��� ������ ���
*/
ISC_API int cmp_UTC_TIME(UTC_TIME *utcTime1, UTC_TIME *utcTime2);

/*!
* \brief
* UTC_TIME ����ü�� �ð��� ���ϴ� �Լ�
* \param utcTime
* UTC_TIME ����ü�� ���� ������
* \param seconds
* ���� �ð��� �� �ð�(���� : ��(seconds))
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_UTC_TIME^ISC_ERR_NULL_INPUT : �Է°��� NULL�� ���
* -# LOCATION^F_ADD_UTC_TIME^ISC_ERR_INVALID_OUTPUT : �߸��� ������� ���
*/
ISC_API ISC_STATUS add_UTC_TIME(UTC_TIME **utcTime, long seconds);


/********************************************************
*														*
*	  GENERALIZED_TIME(Universal Time, Coordinated)		*
*														*
*********************************************************/
/*!
* \brief
* GENERALIZED_TIME ����ü�� ASN1_TIME ����ü ���·� ��ȯ�ϴ� �Լ�
* \param generalizedTime
* GENERALIZED_TIME ����ü�� ������
* \returns
* ��ȯ�� ASN1_TIME ����ü�� ������
*/
ISC_API ASN1_TIME *generalizedTimeToASN1_TIME(GENERALIZED_TIME *generalizedTime);

/*!
* \brief
* �ΰ��� GENERALIZED_TIME ����ü�� �ð��� ���ϴ� �Լ�
* \param generalizedTime1
* ù ��° GENERALIZED_TIME ����ü�� ������
* \param generalizedTime2
* �� ��° GENERALIZED_TIME ����ü�� ������
* \returns
* -# 1 : ù ��° GENERALIZED_TIME ����ü�� �ð��� ������ ���
* -# 0 : �� ����ü�� �ð��� ���� ���
* -# -1 : �� ��° GENERALIZED_TIME ����ü�� �ð��� ������ ���
*/
ISC_API int cmp_GENERALIZED_TIME(GENERALIZED_TIME *generalizedTime1, GENERALIZED_TIME *generalizedTime2);

/*!
* \brief
* GENERALIZED_TIME ����ü�� �ð��� ���ϴ� �Լ�
* \param generalizedTime
* GENERALIZED_TIME ����ü�� ���� ������
* \param seconds
* ���� �ð��� �� �ð�(���� : ��(seconds))
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_GENERALIZED_TIME^ISC_ERR_NULL_INPUT : �Է°��� NULL�� ���
* -# LOCATION^F_ADD_GENERALIZED_TIME^ISC_ERR_INVALID_OUTPUT : �߸��� ������� ���
*/
ISC_API ISC_STATUS add_GENERALIZED_TIME(GENERALIZED_TIME **generalizedTime, long seconds);


/************************************************
*												*
*			BER(Basic Encoding Rules)			*
*												*
************************************************/
/*!
* \brief
* 2���� ���ڿ��κ��� BIT_STRING ����ü�� �����ϴ� �Լ�
* Ex) "01001000101111"
* \param data
* 2���� ���ڿ��� ������
* \param ����
* 2���� ���ڿ��� ����
* \returns
* ������ BIT_STIRNG ����ü�� ������
*/
ISC_API BIT_STRING *new_BIT_STRING(const char *data, int dataLen);

/*!
* \brief
* 16���� ���ڿ��κ��� BIT_STRING ����ü�� �����ϴ� �Լ�
* Ex) "AB01EF7"
* \param data
* 16���� ���ڿ��� ������
* \param dataLen
* 16���� ���ڿ��� ����
* \returns
* ������ BIT_STIRNG ����ü�� ������
*/
ISC_API BIT_STRING *hexToBIT_STRING(const char *data, int dataLen);

/*!
* \brief
* ���̳ʸ� �迭�κ��� BIT_STRING ����ü�� �����ϴ� �Լ�
* \param data
* ���̳ʸ� �迭�� ������
* \param dataLen
* ���̳ʸ� �迭�� ����(Byte)
* \returns
* ������ BIT_STIRNG ����ü�� ������
*/
ISC_API BIT_STRING *binaryToBIT_STRING(const uint8 *data, int dataLen);

/*!
* \brief
* BIT_STRING ����ü�� �е��� �ϴ� �Լ�
* \param bitString
* BIT_STRING ����ü�� ������
* \param paddingBits
* �е��� �� 2���� ���ڿ��� ������, Ex) "10111"
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_PAD_TO_BER_BIT_STRING^ERR_INVALID_ENCODE_INPUT : �߸��� �Է� �Ķ����
*/
ISC_API ISC_STATUS addPadToBERBitString(BIT_STRING *bitString, const char *paddingBits);

/*!
* \brief
* BIT_STRING ����ü�� �޸� ���� �Լ�
* \param bitString
* �޸𸮸� ������ BIT_STRING ����ü�� ������
*/
ISC_API void free_BIT_STRING(BIT_STRING *bitString);

/*!
* \brief
* BIT_STRING ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param bitString
* ���� �ʱ�ȭ �� BIT_STRING ����ü�� ������
*/
ISC_API void clean_BIT_STRING(BIT_STRING *bitString);

/*!
* \brief
* OCTET_STRING ����ü�� �����ϴ� �Լ�
* \param data
* ���̳ʸ� �������� ������
* \param dataLen
* �������� ����(Byte)
* \returns
* ������ OCTET_STRING ����ü�� ������
*/
ISC_API OCTET_STRING *new_OCTET_STRING(const uint8 *data, int dataLen);

/*!
* \brief
* OCTET_STRING ����ü�� �޸� ���� �Լ�
* \param octestString
* �޸𸮸� ������ OCTET_STRING ����ü�� ������
*/
ISC_API void free_OCTET_STRING(OCTET_STRING *octestString);

/*!
* \brief
* OCTET_STRING ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param octestString
* ���� �ʱ�ȭ �� OCTET_STRING ����ü�� ������
*/
ISC_API void clean_OCTET_STRING(OCTET_STRING *octestString);

/*!
* \brief
* OBJECT_IDENTIFIER ����ü�� �����ϴ� �Լ�
* \param data
* OID ���ڿ��� ������, Ex) "1.2.840.113549.1.7"
* \param dataLen
* OID ���ڿ��� ����
* \returns
* ������ OBJECT_IDENTIFIER ����ü�� ������
*/
ISC_API OBJECT_IDENTIFIER *new_OBJECT_IDENTIFIER(const char *data, int dataLen);

/*!
* \brief
* OBJECT_IDENTIFIER ����ü�� �޸� ���� �Լ�
* \param oId
* �޸𸮸� ������ OBJECT_IDENTIFIER ����ü�� ������
*/
ISC_API void free_OBJECT_IDENTIFIER(OBJECT_IDENTIFIER *oId);

/*!
* \brief
* OBJECT_IDENTIFIER ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param oId
* ���� �ʱ�ȭ �� OBJECT_IDENTIFIER ����ü�� ������
*/
ISC_API void clean_OBJECT_IDENTIFIER(OBJECT_IDENTIFIER *oId);

/*!
* \brief
* UTF8_STRING ����ü�� �����ϴ� �Լ�
* \param data
* ���̳ʸ� �������� ������
* \param dataLen
* �������� ����(Byte)
* \returns
* ������ UTF8_STRING ����ü�� ������
*/
ISC_API UTF8_STRING *new_UTF8_STRING(const uint8 *data, int dataLen);

/*!
* \brief
* UTF8_STRING ����ü�� �޸� ���� �Լ�
* \param utf8String
* �޸𸮸� ������ UTF8_STRING ����ü�� ������
*/
ISC_API void free_UTF8_STRING(UTF8_STRING *utf8String);

/*!
* \brief
* UTF8_STRING ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param utf8String
* ���� �ʱ�ȭ �� UTF8_STRING ����ü�� ������
*/
ISC_API void clean_UTF8_STRING(UTF8_STRING *utf8String);

/*!
* \brief
* PRINTABLE_STRING ����ü�� �����ϴ� �Լ�
* \param data
* ���ڿ��� ������
* \param length
* ���ڿ��� ����
* \returns
* ������ PRINTABLE_STRING ����ü�� ������
*/
ISC_API PRINTABLE_STRING *new_PRINTABLE_STRING(const char *data, int length);

/*!
* \brief
* PRINTABLE_STRING ����ü�� �޸� ���� �Լ�
* \param pString
* �޸𸮸� ������ PRINTABLE_STRING ����ü�� ������
*/
ISC_API void free_PRINTABLE_STRING(PRINTABLE_STRING *pString);

/*!
* \brief
* PRINTABLE_STRING ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param pString
* ���� �ʱ�ȭ �� PRINTABLE_STRING ����ü�� ������
*/
ISC_API void clean_PRINTABLE_STRING(PRINTABLE_STRING *pString);

/*!
* \brief
* T61_STRING ����ü�� �����ϴ� �Լ�
* \param data
* ���ڿ��� ������
* \returns
* ������ T61_STRING ����ü�� ������
*/
ISC_API T61_STRING *new_T61_STRING(const char *data, int dataLen);

/*!
* \brief
* T61_STRING ����ü�� �޸� ���� �Լ�
* \param pString
* �޸𸮸� ������ T61_STRING ����ü�� ������
*/
ISC_API void free_T61_STRING(T61_STRING *pString);

/*!
* \brief
* T61_STRING ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param pString
* ���� �ʱ�ȭ �� T61_STRING ����ü�� ������
*/
ISC_API void clean_T61_STRING(T61_STRING *pString);

/*!
* \brief
* IA5_STRING ����ü�� �����ϴ� �Լ�
* \param data
* IA5(International Alphabet 5) ���ڿ��� ������
* \param dataLen
* ���ڿ��� ����(Byte)
* \returns
* ������ IA5_STRING ����ü�� ������
*/
ISC_API IA5_STRING *new_IA5_STRING(const char *data, int dataLen);

/*!
* \brief
* IA5_STRING ����ü�� �޸� ���� �Լ�
* \param ia5String
* �޸𸮸� ������ IA5_STRING ����ü�� ������
*/
ISC_API void free_IA5_STRING(IA5_STRING *ia5String);

/*!
* \brief
* IA5_STRING ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param ia5String
* ���� �ʱ�ȭ �� IA5_STRING ����ü�� ������
*/
ISC_API void clean_IA5_STRING(IA5_STRING *ia5String);

/*!
* \brief
* UTC_TIME ����ü�� �����ϴ� �Լ�
* \param data
* �ð� ������ ����ִ� ���ڿ��� ������, Ex)"2008-12-25,23:11:20"
* \param time_form
* ������ �ð��� ����, Ex)YYMMDDhhmmZ
* \returns
* ������ UTC_TIME ����ü�� ������
*/
ISC_API UTC_TIME *new_UTC_TIME(const char *data, int time_form);

/*!
* \brief
* ASN1_TIME ����ü�� UTC_TIME ����ü�� ��ȯ�ϴ� �Լ�
* \param asn1Time
* ASN1_TIME ����ü�� ������
* \param time_form
* ������ �ð��� ����, Ex)YYMMDDhhmmZ
* \returns
* ������ UTC_TIME ����ü�� ������
*/
ISC_API UTC_TIME *asn1TimeToUTC_TIME(ASN1_TIME *asn1Time, int time_form);

/*!
* \brief
* ASN1_TIME �� ���� ����
* \param asn1Time1
* ASN1_TIME ����ü�� ������1
* \param asn1Time2
* ASN1_TIME ����ü�� ������2
* \returns
* ���� ���(asn1Time1 - asn1Time2);
*/
ISC_API int cmp_ASN1_TIME(ASN1_TIME *asn1Time1, ASN1_TIME *asn1Time2);

/*!
* \brief
* UTC_TIME ����ü�� �޸� ���� �Լ�
* \param utcTime
* �޸𸮸� ������ UTC_TIME ����ü�� ������
*/
ISC_API void free_UTC_TIME(UTC_TIME *utcTime);

/*!
* \brief
* UTC_TIME ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param utcTime
* ���� �ʱ�ȭ �� UTC_TIME ����ü�� ������
*/
ISC_API void clean_UTC_TIME(UTC_TIME *utcTime);

/*!
* \brief
* UTC_TIME ����ü�� �����ϴ� �Լ�
* \param from
* ������ ����
* \param to
* ����� ���(�޸� �Ҵ��ؼ� �ٰ�.)
*/
ISC_API ISC_STATUS copy_UTC_TIME(UTC_TIME *from, UTC_TIME *to);

/*!
* \brief
* GENERALIZED_TIME ����ü�� �����ϴ� �Լ�
* \param data
* �ð� ������ ����ִ� ���ڿ��� ������, Ex)"2008-12-25,23:11:20"
* \param time_form
* ������ �ð��� ����, Ex)YYMMDDhhmmZ
* \returns
* ������ GENERALIZED_TIME ����ü�� ������
*/
ISC_API GENERALIZED_TIME *new_GENERALIZED_TIME(const char *data, int time_form);

/*!
* \brief
* ASN1_TIME ����ü�� GENERALIZED_TIME ����ü�� ��ȯ�ϴ� �Լ�
* \param asn1Time
* ASN1_TIME ����ü�� ������
* \param time_form
* ������ �ð��� ����, Ex)YYMMDDhhmmZ
* \returns
* ������ GENERALIZED_TIME ����ü�� ������
*/
ISC_API GENERALIZED_TIME *asn1TimeToGENERALIZED_TIME(ASN1_TIME *asn1Time, int time_form);

/*!
* \brief
* GENERALIZED_TIME ����ü�� �޸� ���� �Լ�
* \param GENERALIZEDTime
* �޸𸮸� ������ GENERALIZED_TIME ����ü�� ������
*/
ISC_API void free_GENERALIZED_TIME(GENERALIZED_TIME *GENERALIZEDTime);

/*!
* \brief
* GENERALIZED_TIME ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param GENERALIZEDTime
* ���� �ʱ�ȭ �� GENERALIZED_TIME ����ü�� ������
*/
ISC_API void clean_GENERALIZED_TIME(GENERALIZED_TIME *GENERALIZEDTime);

/*!
* \brief
* GENERALIZED_TIME ����ü�� �����ϴ� �Լ�
* \param from
* ������ ����
* \param to
* ����� ���(�޸� �Ҵ��ؼ� �ٰ�.)
*/
ISC_API ISC_STATUS copy_GENERALIZED_TIME(GENERALIZED_TIME *from, GENERALIZED_TIME *to);


/*!
* \brief
* BMP_STRING ����ü�� �����ϴ� �Լ�
* \param data
* ���̳ʸ� �������� ������
* \param dataLen
* ���ڿ��� ����(Byte)
* \returns
* ������ BMP_STRING ����ü�� ������
*/
ISC_API BMP_STRING *new_BMP_STRING(const char *data, int dataLen);

/*!
* \brief
* BMP_STRING ����ü�� �޸� ���� �Լ�
* \param bmpString
* �޸𸮸� ������ BMP_STRING ����ü�� ������
*/
ISC_API void free_BMP_STRING(BMP_STRING *bmpString);

/*!
* \brief
* BMP_STRING ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param bmpString
* ���� �ʱ�ȭ �� BMP_STRING ����ü�� ������
*/
ISC_API void clean_BMP_STRING(BMP_STRING *bmpString);

/*!
* \brief
* Boolean ���� BER�� Encoding�ϴ� �Լ�
* \param asn1Unit
* Encoding ����� ������ ASN1_UNIT ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCODE_TO_BER_BOOLEAN^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS encodeToBERBoolean(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Integer ���� BER�� Encoding�ϴ� �Լ�
* \param asn1Unit
* Encoding ����� ������ ASN1_UNIT ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCODE_TO_BER_INTEGER^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS encodeToBERInteger(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Bit String ���� BER�� Encoding�ϴ� �Լ�
* \param asn1Unit
* Encoding ����� ������ ASN1_UNIT ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCODE_TO_BER_BIT_STRING^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS encodeToBERBitString(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Null ���� BER�� Encoding�ϴ� �Լ�
* \param asn1Unit
* Encoding ����� ������ ASN1_UNIT ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCODE_TO_BER_NULL^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS encodeToBERNull(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Object Identifier ���� BER�� Encoding�ϴ� �Լ�
* \param asn1Unit
* Encoding ����� ������ ASN1_UNIT ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCODE_TO_BER_OBJECT_IDENTIFIER^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS encodeToBERObjectIdentifier(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Utc Time ���� BER�� Encoding�ϴ� �Լ�
* \param asn1Unit
* Encoding ����� ������ ASN1_UNIT ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCODE_TO_BER_UTC_TIME^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS encodeToBERUTCTime(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* GENERALIZED Time ���� BER�� Encoding�ϴ� �Լ�
* \param asn1Unit
* Encoding ����� ������ ASN1_UNIT ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCODE_TO_BER_UTC_TIME^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS encodeToBERGENERALIZEDTime(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* ASN1 String ���� BER�� Encoding�ϴ� �Լ�
* \param asn1Unit
* Encoding ����� ������ ASN1_UNIT ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCODE_TO_BER_ASN1_STRING^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS encodeToBERASN1String(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* �����͸� BER�� Encoding�ϴ� �Լ�
* \param asn1Unit
* Encoding ����� ������ ASN1_UNIT ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCODE_TO_BER^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS encodeToBER(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* �����͸� Context-Specific ������ BER�� Encoding�ϴ� �Լ�
* \param asn1Unit
* Encoding ����� ������ ASN1_UNIT ����ü�� ������
* \param cs_id
* Context-Specific ID
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCODE_TO_BER_CS^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS encodeToBER_CS(ASN1_UNIT *asn1Unit, int cs_id, int type, void *value, int valueLen, int lengthForm);
    
/*!
 * \brief
 * �����͸� Context-Specific ������ BER�� Encoding�ϴ� �Լ�
 * \param asn1Unit
 * Encoding ����� ������ ASN1_UNIT ����ü�� ������
 * \param cs_id
 * Context-Specific ID
 * \param type
 * Encoding�� Type
 * \param value
 * �������� void�� ������
 * \param valueLen
 * �������� ����(Byte)
 * \param lengthForm
 * Encoding�� Length Form
 * \returns
 * -# ISC_SUCCESS : ����
 * -# LOCATION^F_ENCODE_TO_BER_CS^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
 */
ISC_API ISC_STATUS encodeToBER_CS_Scraping(ASN1_UNIT *asn1Unit, int cs_id, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* �����͸� SEQUENCE�� ������ �� BER�� Encoding�ϴ� �Լ�
* \param sequence
* Encoding ����� ������ SEQUENCE ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_TO_BER_SEQUENCE^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS addToBERSequence(SEQUENCE *sequence, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* �����͸� SEQUENCE OF�� ������ �� BER�� Encoding�ϴ� �Լ�
* \param sequenceOf
* Encoding ����� ������ SEQUENCE OF ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_TO_BER_SEQUENCE_OF^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS addToBERSequenceOf(SEQUENCE_OF *sequenceOf, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* �����͸� SET�� ������ �� BER�� Encoding�ϴ� �Լ�
* \param set
* Encoding ����� ������ SET ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_TO_BER_SET^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS addToBERSet(SET *set, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* �����͸� SET OF�� ������ �� BER�� Encoding�ϴ� �Լ�
* \param setOf
* Encoding ����� ������ SET OF ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_TO_BER_SET_OF^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS addToBERSetOf(SET_OF *setOf, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* �����͸� Context-Specific ������ SEQUENCE�� ������ �� BER�� Encoding�ϴ� �Լ�
* \param sequence
* Encoding ����� ������ SEQUENCE ����ü�� ������
* \param cs_id
* Context-Specific ID
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_TO_BER_SEQUENCE_CS^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS addToBERSequence_CS(SEQUENCE *sequence, int cs_id, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Encoding �� SEQUENCE ����ü�� Length Form�� �����ϴ� �Լ�
* \param sequence
* SEQUENCE ����ü�� ������
* \param lengthForm
* ������ Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SET_BER_LENGTH_FORM^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS setBERLengthForm(SEQUENCE *sequence, int lengthForm);

/*!
* \brief
* �����͸� STRING SEQUENCE�� ������ �� BER�� Encoding�ϴ� �Լ�
* \param stringSequence
* Encoding ����� ������ STRING SEQUENCE ����ü�� ������
* \param type
* Encoding�� String Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \param lengthForm
* Encoding�� Length Form
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_TO_BER_STRING_SEQUENCE^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS addToBERStringSequence(STRING_SEQUENCE *stringSequence, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Encoding�� �����͸� Boolean ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� BOOLEAN ������ ������
*/
ISC_API BOOLEAN *decodeToBERBoolean(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Integer ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� INTEGER ����ü�� ������
*/
ISC_API INTEGER *decodeToBERInteger(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Bit String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� BIT_STRING ����ü�� ������
*/
ISC_API BIT_STRING *decodeToBERBitString(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Octet String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� OCTET_STRING ����ü�� ������
*/
ISC_API OCTET_STRING *decodeToBEROctetString(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Null ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� NULL_VALUE ������ ������
*/
ISC_API NULL_VALUE *decodeToBERNull(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Object Identifier ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� OBJECT_IDENTIFIER ����ü�� ������
*/
ISC_API OBJECT_IDENTIFIER *decodeToBERObjectIdentifier(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Enumerated ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� ENUMERATED ����ü�� ������
*/
ISC_API ENUMERATED *decodeToBEREnumerated(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Utf8 String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� UTF8_STRING ����ü�� ������
*/
ISC_API UTF8_STRING *decodeToBERUTF8String(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Sequence ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� SEQUENCE ����ü�� ������
*/
ISC_API SEQUENCE *decodeToBERSequence(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Printable String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� PRINTABLE_STRING ����ü�� ������
*/
ISC_API PRINTABLE_STRING *decodeToBERPrintableString(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� T61 String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� T61_STRING ����ü�� ������
*/
ISC_API T61_STRING *decodeToBERT61String(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� IA5 String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� IA5_STRING ����ü�� ������
*/
ISC_API IA5_STRING *decodeToBERIA5String(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Utc Time ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� UTC_TIME ����ü�� ������
*/
ISC_API UTC_TIME *decodeToBERUTCTime(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Utc Time ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� GENERALIZED_TIME ����ü�� ������
*/
ISC_API GENERALIZED_TIME *decodeToBERGENERALIZEDTime(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Bmp String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� BMP_STRING ����ü�� ������
*/
ISC_API BMP_STRING *decodeToBERBMPString(uint8 *value);
/*!
* \brief
* Encoding�� �����͸� ASN1 String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� ASN1_STRING ����ü�� ������
*/
ISC_API ASN1_STRING *decodeToBERASN1String(uint8 *value);

/*!
* \brief
* ASN1_UNIT ����ü���� index��° �ڽ��� Decoding�ϴ� �Լ�
* \param asn1Unit
* ASN1_UNIT ����ü�� ������
* \param index
* Decoding�� �ڽ��� �ε���
* \param childType
* Decoding�� �ڽ��� Ÿ��
* \returns
* Decoding�� �ڽ��� void�� ������
*/
ISC_API void *getBERChildAt(ASN1_UNIT *asn1Unit, int index, int childType);
ISC_API void *getBERChildOffset(ASN1_UNIT *asn1Unit, int index, int childType, int* beforeOffset/*[in,out]*/);

/*!
* \brief
* ASN1_UNIT ����ü�� ����� �ִ� �Լ�
* \param asn1Unit
* ASN1_UNIT ����ü�� ������
*/
ISC_API void printBERData(ASN1_UNIT *asn1Unit);


/************************************************
*												*
*		DER(Distinguished Encoding Rules)		*
*												*
************************************************/
/*!
* \brief
* �����Ͱ� DER ���¿� �´��� üũ�ϴ� �Լ�
* \param type
* Encoding�� Ÿ��
* \param value
* �������� void�� ������
* \param valueLen
* �������� ���̸� ����Ű�� ������
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CHECK_DER^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS checkDER(int type, void *value, int *valueLen);

/*!
* \brief
* �����͸� DER�� Encoding�ϴ� �Լ�
* \param asn1Unit
* Encoding ����� ������ ASN1_UNIT ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCODE_TO_DER^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS encodeToDER(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen);

/*!
* \brief
* �����͸� Context-Specific ������ DER�� Encoding�ϴ� �Լ�
* \param asn1Unit
* Encoding ����� ������ ASN1_UNIT ����ü�� ������
* \param cs_id
* Context-Specific ID
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCODE_TO_DER_CS^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS encodeToDER_CS(ASN1_UNIT *asn1Unit, int cs_id, int type, void *value, int valueLen);
/*!
 * \brief
 * �����͸� Context-Specific ������ DER�� Encoding�ϴ� �Լ�
 * \param asn1Unit
 * Encoding ����� ������ ASN1_UNIT ����ü�� ������
 * \param cs_id
 * Context-Specific ID
 * \param type
 * Encoding�� Type
 * \param value
 * �������� void�� ������
 * \param valueLen
 * �������� ����(Byte)
 * \returns
 * -# ISC_SUCCESS : ����
 * -# LOCATION^F_ENCODE_TO_DER_CS^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
 */
ISC_API ISC_STATUS encodeToDER_CS_Scraping(ASN1_UNIT *asn1Unit, int cs_id, int type, void *value, int valueLen);
/*!
* \brief
* �����͸� SEQUENCE�� ������ �� DER�� Encoding�ϴ� �Լ�
* \param sequence
* Encoding ����� ������ SEQUENCE ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_TO_DER_SEQUENCE^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS addToDERSequence(SEQUENCE *sequence, int type, void *value, int valueLen);

/*!
* \brief
* �����͸� SEQUENCE OF�� ������ �� DER�� Encoding�ϴ� �Լ�
* \param sequenceOf
* Encoding ����� ������ SEQUENCE OF ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_TO_DER_SEQUENCE_OF^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS addToDERSequenceOf(SEQUENCE_OF *sequenceOf, int type, void *value, int valueLen);

/*!
* \brief
* �����͸� SET�� ������ �� DER�� Encoding�ϴ� �Լ�
* \param set
* Encoding ����� ������ SET ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_TO_DER_SET^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS addToDERSet(SET *set, int type, void *value, int valueLen);

/*!
* \brief
* �����͸� SET OF�� ������ �� DER�� Encoding�ϴ� �Լ�
* \param setOf
* Encoding ����� ������ SET OF ����ü�� ������
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_TO_DER_SET_OF^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS addToDERSetOf(SET_OF *setOf, int type, void *value, int valueLen);

/*!
* \brief
* �����͸� Context-Specific ������ SEQUENCE�� ������ �� DER�� Encoding�ϴ� �Լ�
* \param sequence
* Encoding ����� ������ SEQUENCE ����ü�� ������
* \param cs_id
* Context-Specific ID
* \param type
* Encoding�� Type
* \param value
* �������� void�� ������
* \param valueLen
* �������� ����(Byte)
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_TO_DER_SEQUENCE_CS^ERR_INVALID_ENCODE_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS addToDERSequence_CS(SEQUENCE *sequence, int cs_id, int type, void *value, int valueLen);

/*!
* \brief
* Encoding�� �����͸� Boolean ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� BOOLEAN ������ ������
*/
ISC_API BOOLEAN *decodeToDERBoolean(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Integer ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� INTEGER ����ü�� ������
*/
ISC_API INTEGER *decodeToDERInteger(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Bit String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� BIT_STRING ����ü�� ������
*/
ISC_API BIT_STRING *decodeToDERBitString(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Octet String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� OCTET_STRING ����ü�� ������
*/
ISC_API OCTET_STRING *decodeToDEROctetString(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Null ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� NULL_VALUE ������ ������
*/
ISC_API NULL_VALUE *decodeToDERNull(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Object Identifier ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� OBJECT_IDENTIFIER ����ü�� ������
*/
ISC_API OBJECT_IDENTIFIER *decodeToDERObjectIdentifier(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Enumerated ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� ENUMERATED ����ü�� ������
*/
ISC_API ENUMERATED *decodeToDEREnumerated(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Utf8 String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� UTF8_STRING ����ü�� ������
*/
ISC_API UTF8_STRING *decodeToDERUTF8String(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Sequence ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� SEQUENCE ����ü�� ������
*/
ISC_API SEQUENCE *decodeToDERSequence(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Printable String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� PRINTABLE_STRING ����ü�� ������
*/
ISC_API PRINTABLE_STRING *decodeToDERPrintableString(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� T61 String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� T61_STRING ����ü�� ������
*/
ISC_API T61_STRING *decodeToDERT61String(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� IA5 String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� IA5_STRING ����ü�� ������
*/
ISC_API IA5_STRING *decodeToDERIA5String(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Utc Time ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� UTC_TIME ����ü�� ������
*/
ISC_API UTC_TIME *decodeToDERUTCTime(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� GENERALIZED Time ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� GENERALIZED_TIME ����ü�� ������
*/
ISC_API GENERALIZED_TIME *decodeToDERGENERALIZEDTime(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� Bmp String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� BMP_STRING ����ü�� ������
*/
ISC_API BMP_STRING *decodeToDERBMPString(uint8 *value);

/*!
* \brief
* Encoding�� �����͸� ASN1 String ������ Decoding�ϴ� �Լ�
* \param value
* Encoding�� ���̳ʸ� �������� ������
* \returns
* Decoding�� ASN1_STRING ����ü�� ������
*/
ISC_API ASN1_STRING *decodeToDERASN1String(uint8 *value);

/*!
* \brief
* ASN1_UNIT ����ü���� beforeOffset �������� index��° �ڽ��� Decoding�ϴ� �Լ�
* \param asn1Unit
* ASN1_UNIT ����ü�� ������
* \param index
* Decoding�� �ڽ��� �ε���
* \param childType
* Decoding�� �ڽ��� Ÿ��
* \param beforeOffset
* Decoding�� offset�ּ�
* \returns
* Decoding�� �ڽ��� void�� ������
*/
ISC_API void *getBERChildOffset(ASN1_UNIT *asn1Unit, int index, int childType, int *beforeOffset/*[in,out]*/);

/*!
* \brief
* ASN1_UNIT ����ü���� index��° �ڽ��� Decoding�ϴ� �Լ�
* \param asn1Unit
* ASN1_UNIT ����ü�� ������
* \param index
* Decoding�� �ڽ��� �ε���
* \param childType
* Decoding�� �ڽ��� Ÿ��
* \returns
* Decoding�� �ڽ��� void�� ������
*/
ISC_API void *getDERChildAt(ASN1_UNIT *asn1Unit, int index, int childType);

/*!
* \brief
* ASN1_UNIT ����ü�� ����� �ִ� �Լ�
* \param asn1Unit
* ASN1_UNIT ����ü�� ������
*/
ISC_API void printDERData(ASN1_UNIT *asn1Unit);

/*!
* \brief
* HEX ���ڿ��� ASCII(���̳ʸ�) �迭�� �ٲ��ִ� �Լ�
* \param hex
* HEX ���ڿ��� ������
* \param hexLen
* HEX ���ڿ��� ����
* \param out
* ��µ� ASCII �迭�� ������
* \returns
* ��µ� ASCII �迭�� ����
*/
ISC_API int hexToASCII(uint8 *hex, int hexLen, uint8 *out);


/************************************************
*												*
*				I/O(Input/Output)				*
*												*
************************************************/

/*!
* \brief
* ASN1_UNIT ����ü�� ���̳ʸ� �����ͷ� ��ȯ�ϴ� �Լ�
* \param asn1Unit
* ASN1_UNIT ����ü�� ������
* \param data
* ���̳ʸ��� ������ ������ ���� ������
* \returns
* -# ��ȯ�� ���̳ʸ��� ����(Byte) : ����
* -# -1 : ����
*/
ISC_API int ASN1_to_binary(ASN1_UNIT *asn1Unit, uint8 **data);

/*!
* \brief
* ASN1_STRING ����ü�� ���̳ʸ� �����ͷ� ��ȯ�ϴ� �Լ�
* \param asn1Str
* ASN1_STRING ����ü�� ������
* \param data
* ���̳ʸ��� ������ ������ ���� ������
* \returns
* -# ��ȯ�� ���̳ʸ��� ����(Byte) : Success
* -# -1 : Fail
*/
ISC_API int ASN1_STRING_to_binary(ASN1_STRING *asn1Str, uint8 **data);

/*!
* \brief
* ASN1_UNIT ����ü�� File�� ��ȯ�ϴ� �Լ�
* \param asn1Unit
* ASN1_UNIT ����ü�� ������
* \param fileName
* File �̸� ���ڿ��� ������, Ex)"D:\\test.der"
* \returns
* -# ���Ͽ� ������ ���� : ����
* -# -1 : ����
*/
ISC_API int ASN1_to_FILE(ASN1_UNIT *asn1Unit, const char *fileName);

/*!
* \brief
* ���̳ʸ� �����ͷκ��� DER�� ���ڵ��� �����͸� �д� �Լ�
* \param st
* �����͸� ������ ����ü�� void�� ���� ������
* \param seq_to_st 
* SEQUENCE�� ����ü�� ��ȯ�ϴ� �Լ��� �̸� Ex)Seq_to_X509_CERT 
* \param derBytes
* DER�� ���ڵ��� ���̳ʸ��� ����Ű�� ������
* \returns
* -# ISC_SUCCESS : ����
* -# L_DER^ISC_ERR_READ_FROM_BINARY : �⺻ �����ڵ�
* -# L_DER^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ����
* -# seq_to_st �Լ��κ��� �߻��� ���� �ڵ�
*/
ISC_API ISC_STATUS readDER_from_Binary(void **st, PREAD_FUNC pReadFunc, uint8* derBytes);

/*!
* \brief
* ���Ϸκ��� DER�� ���ڵ��� �����͸� �д� �Լ�
* \param st
* �����͸� ������ ����ü�� void�� ���� ������
* \param seq_to_st 
* SEQUENCE�� ����ü�� ��ȯ�ϴ� �Լ��� �̸� Ex)Seq_to_X509_CERT 
* \param fileName
* File �̸� ���ڿ��� ������, Ex)"D:\\test.der"
* \returns
* -# ISC_SUCCESS : ����
* -# L_DER^ISC_ERR_READ_FROM_FILE : �⺻ �����ڵ�
* -# L_DER^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ����
* -# readDER_from_Binary �Լ��κ��� �߻��� ���� �ڵ�
*/
ISC_API ISC_STATUS readDER_from_File(void **st, PREAD_FUNC pReadFunc, const char* fileName);

/*!
* \brief
* ����ü�� DER�� ���ڵ��� �� ���̳ʸ��� ���� �Լ�
* \param st
* ����ü�� void�� ������
* \param st_to_seq 
* ����ü�� SEQUENCE�� ��ȯ�ϴ� �Լ��� �̸� Ex)X509_CERT_to_Seq
* \param derBytes
* ���̳ʸ��� ������ ������ ���� ������
* \returns
* -# ���ۿ� ������ ���� : ����
* -# -1 : ����
*/
ISC_API int writeDER_to_Binary(void *st, PWRITE_FUNC pWreteFunc, uint8** derBytes);

/*!
* \brief
* ����ü�� DER�� ���ڵ��� �� ���Ϸ� ���� �Լ�
* \param st
* ����ü�� void�� ������
* \param st_to_seq 
* ����ü�� SEQUENCE�� ��ȯ�ϴ� �Լ��� �̸� Ex)X509_CERT_to_Seq
* \param fileName
* File �̸� ���ڿ��� ������, Ex)"D:\\test.der"
* \returns
* -# ���ۿ� ������ ���� : ����
* -# -1 : ����
*/
ISC_API int writeDER_to_FILE(void *st, PWRITE_FUNC pWriteFunc, const char *fileName);

/*!
* \brief
* ���̳ʸ� �����ͷκ��� PEM���� ���ڵ��� �����͸� �д� �Լ�
* \param st
* �����͸� ������ ����ü�� void�� ���� ������
* \param seq_to_st 
* SEQUENCE�� ����ü�� ��ȯ�ϴ� �Լ��� �̸� Ex)Seq_to_X509_CERT 
* \param pemBytes
* PEM���� ���ڵ��� ���̳ʸ��� ����Ű�� ������
* \param pemLength
* PEM���� ���ڵ��� ���̳ʸ��� ����
* \returns
* -# ISC_SUCCESS : ����
* -# L_PEM^ISC_ERR_READ_FROM_BINARY : �⺻ �����ڵ�
* -# L_PEM^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ����
* -# seq_to_st �Լ��κ��� �߻��� ���� �ڵ�
*/
ISC_API ISC_STATUS readPEM_from_Binary(void **st, PREAD_FUNC pReadFunc, uint8* pemBytes, int pemLength);

/*!
* \brief
* ���Ϸκ��� PEM���� ���ڵ��� �����͸� �д� �Լ�
* \param st
* �����͸� ������ ����ü�� void�� ���� ������
* \param seq_to_st 
* SEQUENCE�� ����ü�� ��ȯ�ϴ� �Լ��� �̸� Ex)Seq_to_X509_CERT 
* \param fileName
* File �̸� ���ڿ��� ������, Ex)"D:\\test.pem"
* \returns
* -# ISC_SUCCESS : ����
* -# L_PEM^ISC_ERR_READ_FROM_FILE : �⺻ �����ڵ�
* -# L_PEM^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ����
* -# readPEM_from_Binary �Լ��κ��� �߻��� ���� �ڵ�
*/
ISC_API ISC_STATUS readPEM_from_File(void **st, PREAD_FUNC pReadFund, const char* fileName);

/*!
* \brief
* ����ü�� PEM���� ���ڵ��� �� ���̳ʸ��� ���� �Լ�
* \param st
* ����ü�� void�� ������
* \param st_to_seq 
* ����ü�� SEQUENCE�� ��ȯ�ϴ� �Լ��� �̸� Ex)X509_CERT_to_Seq
* \param pemStr
* PEM String Ex)"X509 CERTIFICATE"
* \param pemStrLen
* PEM String ���ڿ��� ����
* \param pemBytes
* ���̳ʸ��� ������ ������ ���� ������
* \returns
* -# ���ۿ� ������ ���� : ����
* -# -1 : ����
*/
ISC_API int writePEM_to_Binary(void *st, PWRITE_FUNC pWriteFunc, const char *pemStr, int pemStrLen, uint8** pemBytes);

/*!
* \brief
* ����ü�� PEM���� ���ڵ��� �� ���Ϸ� ���� �Լ�
* \param st
* ����ü�� void�� ������
* \param st_to_seq 
* ����ü�� SEQUENCE�� ��ȯ�ϴ� �Լ��� �̸� Ex)X509_CERT_to_Seq
* \param pemStr
* PEM String Ex)"X509 CERTIFICATE"
* \param pemStrLen
* PEM String ���ڿ��� ����
* \param fileName
* File �̸� ���ڿ��� ������, Ex)"D:\\test.pem"
* \returns
* -# ���ۿ� ������ ���� : ����
* -# -1 : ����
*/
ISC_API int writePEM_to_FILE(void *st, PWRITE_FUNC pWriteFunc, const char *pemStr, int pemStrLen, const char* fileName);

/*!
* \brief
* DER�� ���ڵ��� ���̳ʸ��� �ؽ��ϴ� �Լ�
* \param st
* ����ü�� void�� ������
* \param st_to_seq 
* ����ü�� SEQUENCE�� ��ȯ�ϴ� �Լ��� �̸� Ex)X509_CERT_to_Seq
* \param digest_id
* �ؽ� �Լ��� ID Ex) ISC_MD5, ISC_SHA1
* \param md
* �ؽ� �Լ��� ����� ������ ������ ������
* \returns
* -# �ؽ� ����� ����('0'�� ���� ������)
*/
ISC_API int get_ASN1_hash(void *st, PWRITE_FUNC pWreteFunc ,int digest_id, uint8* md);

/*!
* \brief
* ���ڿ��� character ���·� ������ִ� �Լ�
* \param c
* ���ڿ��� ������
* \param len 
* ���ڿ��� ����
*/
ISC_API void print_PCHAR(char* c, int len);

/*!
* \brief
* ���ڿ��� character ���·� ��ȯ�ϴ� �Լ�
* \param c
* ���ڿ��� ������
* \param len 
* ���ڿ��� ����
* \returns
* -# ���ڿ�
*/
ISC_API char* dump_PCHAR(char* c, int len);

/*!
* \brief
* ASN1_STRING ����ü�� ������ִ� �Լ�
* \param st
* ASN1_STRING ����ü�� ������
*/
ISC_API void print_ASN1STRING(ASN1_STRING *st);

/*!
* \brief
* ASN1_STRING ����ü�� character ���·� ��ȯ�ϴ� �Լ�
* \param st
* ASN1_STRING ����ü�� ������
* \returns
* -# ���ڿ�
*/
ISC_API char* dump_ASN1STRING(ASN1_STRING *st);
#else
#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(ASN1_UNIT*, new_ASN1_UNIT, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ASN1_UNIT, (ASN1_UNIT *asn1Unit), (asn1Unit) );
INI_VOID_LOADLIB_PKI(void, clean_ASN1_UNIT, (ASN1_UNIT *asn1Unit), (asn1Unit) );
INI_RET_LOADLIB_PKI(ASN1_UNIT*, dup_ASN1_UNIT, (ASN1_UNIT *asn1Unit), (asn1Unit), NULL);
INI_RET_LOADLIB_PKI(ASN1_STRING*, new_ASN1_STRING, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ASN1_STRING, (ASN1_STRING *asn1String), (asn1String) );
INI_VOID_LOADLIB_PKI(void, clean_ASN1_STRING, (ASN1_STRING *asn1String), (asn1String) );
INI_RET_LOADLIB_PKI(ISC_STATUS, set_ASN1_STRING_value, (ASN1_STRING *asn1String, int type, const uint8* data, int dLen), (asn1String,type,data,dLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, ASN1_STRING_to_Seq, (ASN1_STRING *asn1String, SEQUENCE **seq), (asn1String,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ASN1_STRING*, dup_ASN1_STRING, (ASN1_STRING *asn1String), (asn1String), NULL);
INI_RET_LOADLIB_PKI(int, cmp_ASN1_STRING, (ASN1_STRING *a, ASN1_STRING *b), (a,b), ISC_FAIL);
INI_RET_LOADLIB_PKI(ASN1_TIME*, new_ASN1_TIME, (void), (), NULL);
INI_RET_LOADLIB_PKI(ASN1_TIME*, charToASN1_TIME, (const char *data), (data), NULL);
INI_VOID_LOADLIB_PKI(void, free_ASN1_TIME, (ASN1_TIME *asn1Time), (asn1Time) );
INI_VOID_LOADLIB_PKI(void, clean_ASN1_TIME, (ASN1_TIME *asn1Time), (asn1Time) );
INI_RET_LOADLIB_PKI(ISC_STATUS, check_ASN1_TIME, (ASN1_TIME asn1Time), (asn1Time), ISC_FAIL);
INI_RET_LOADLIB_PKI(ASN1_TIME*, dup_ASN1_TIME, (ASN1_TIME *asn1Time), (asn1Time), NULL);
INI_RET_LOADLIB_PKI(ASN1_TIME*, getCurrentLocalTime, (void), (), NULL);
INI_RET_LOADLIB_PKI(ASN1_TIME*, getCurrentGMTime, (void), (), NULL);
INI_RET_LOADLIB_PKI(int, getASN1LengthSize, (uint8 *lengthOctet), (lengthOctet), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, getASN1ValueLength, (ASN1_UNIT *asn1Unit), (asn1Unit), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, getASN1ValueLengthFromLO, (uint8 *lengthOctet), (lengthOctet), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, getASN1IndefiniteValueLength, (uint8 *contentsOctet), (contentsOctet), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, getAsciiStringLength, (int number), (number), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, getSequenceChildNum, (SEQUENCE *sequence), (sequence), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, getChildType, (SEQUENCE *sequence, int index), (sequence,index), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, getASN1LengthForm, (int type, int valueLen), (type,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(uint16, cp949ToUnicode, (uint8 byte1, uint8 byte2), (byte1,byte2), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, cp949ToUTF8, (const char *data, uint8 **utf8), (data,utf8), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, cp949ToBMP, (const char *data, uint8 **bmp), (data,bmp), ISC_FAIL);
INI_RET_LOADLIB_PKI(uint8*, unicodeToCP949, (long unicode), (unicode), NULL);
INI_RET_LOADLIB_PKI(int, utf8ToCP949, (UTF8_STRING *utf8String, uint8 **cp949), (utf8String,cp949), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, bmpToCP949, (BMP_STRING *bmpString, uint8 **cp949), (bmpString,cp949), ISC_FAIL);
INI_RET_LOADLIB_PKI(uint8*, ascTouni, (const char *asc, int asclen, uint8 **uni, int *unilen), (asc,asclen,uni,unilen), NULL);
INI_RET_LOADLIB_PKI(char*, uniToasc, (uint8 *uni, int unilen), (uni,unilen), NULL);
INI_RET_LOADLIB_PKI(ASN1_TIME*, utcTimeToASN1_TIME, (UTC_TIME *utcTime), (utcTime), NULL);
INI_RET_LOADLIB_PKI(int, cmp_UTC_TIME, (UTC_TIME *utcTime1, UTC_TIME *utcTime2), (utcTime1,utcTime2), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_UTC_TIME, (UTC_TIME **utcTime, long seconds), (utcTime,seconds), ISC_FAIL);
INI_RET_LOADLIB_PKI(ASN1_TIME*, generalizedTimeToASN1_TIME, (GENERALIZED_TIME *generalizedTime), (generalizedTime), NULL);
INI_RET_LOADLIB_PKI(int, cmp_GENERALIZED_TIME, (GENERALIZED_TIME *generalizedTime1, GENERALIZED_TIME *generalizedTime2), (generalizedTime1,generalizedTime2), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_GENERALIZED_TIME, (GENERALIZED_TIME **generalizedTime, long seconds), (generalizedTime,seconds), ISC_FAIL);
INI_RET_LOADLIB_PKI(BIT_STRING*, new_BIT_STRING, (const char *data, int dataLen), (data,dataLen), NULL);
INI_RET_LOADLIB_PKI(BIT_STRING*, hexToBIT_STRING, (const char *data, int dataLen), (data,dataLen), NULL);
INI_RET_LOADLIB_PKI(BIT_STRING*, binaryToBIT_STRING, (const uint8 *data, int dataLen), (data,dataLen), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, addPadToBERBitString, (BIT_STRING *bitString, const char *paddingBits), (bitString,paddingBits), ISC_FAIL);
INI_VOID_LOADLIB_PKI(void, free_BIT_STRING, (BIT_STRING *bitString), (bitString) );
INI_VOID_LOADLIB_PKI(void, clean_BIT_STRING, (BIT_STRING *bitString), (bitString) );
INI_RET_LOADLIB_PKI(OCTET_STRING*, new_OCTET_STRING, (const uint8 *data, int dataLen), (data,dataLen), NULL);
INI_VOID_LOADLIB_PKI(void, free_OCTET_STRING, (OCTET_STRING *octestString), (octestString) );
INI_VOID_LOADLIB_PKI(void, clean_OCTET_STRING, (OCTET_STRING *octestString), (octestString) );
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, new_OBJECT_IDENTIFIER, (const char *data, int dataLen), (data,dataLen), NULL);
INI_VOID_LOADLIB_PKI(void, free_OBJECT_IDENTIFIER, (OBJECT_IDENTIFIER *oId), (oId) );
INI_VOID_LOADLIB_PKI(void, clean_OBJECT_IDENTIFIER, (OBJECT_IDENTIFIER *oId), (oId) );
INI_RET_LOADLIB_PKI(UTF8_STRING*, new_UTF8_STRING, (const uint8 *data, int dataLen), (data,dataLen), NULL);
INI_VOID_LOADLIB_PKI(void, free_UTF8_STRING, (UTF8_STRING *utf8String), (utf8String) );
INI_VOID_LOADLIB_PKI(void, clean_UTF8_STRING, (UTF8_STRING *utf8String), (utf8String) );
INI_RET_LOADLIB_PKI(PRINTABLE_STRING*, new_PRINTABLE_STRING, (const char *data, int length), (data,length), NULL);
INI_VOID_LOADLIB_PKI(void, free_PRINTABLE_STRING, (PRINTABLE_STRING *pString), (pString) );
INI_VOID_LOADLIB_PKI(void, clean_PRINTABLE_STRING, (PRINTABLE_STRING *pString), (pString) );
INI_RET_LOADLIB_PKI(T61_STRING*, new_T61_STRING, (const char *data, int dataLen), (data,dataLen), NULL);
INI_VOID_LOADLIB_PKI(void, free_T61_STRING, (T61_STRING *pString), (pString) );
INI_VOID_LOADLIB_PKI(void, clean_T61_STRING, (T61_STRING *pString), (pString) );
INI_RET_LOADLIB_PKI(IA5_STRING*, new_IA5_STRING, (const char *data, int dataLen), (data,dataLen), NULL);
INI_VOID_LOADLIB_PKI(void, free_IA5_STRING, (IA5_STRING *ia5String), (ia5String) );
INI_VOID_LOADLIB_PKI(void, clean_IA5_STRING, (IA5_STRING *ia5String), (ia5String) );
INI_RET_LOADLIB_PKI(UTC_TIME*, new_UTC_TIME, (const char *data, int time_form), (data,time_form), NULL);
INI_RET_LOADLIB_PKI(UTC_TIME*, asn1TimeToUTC_TIME, (ASN1_TIME *asn1Time, int time_form), (asn1Time,time_form), NULL);
INI_RET_LOADLIB_PKI(int, cmp_ASN1_TIME, (ASN1_TIME *asn1Time1, ASN1_TIME *asn1Time2), (asn1Time1,asn1Time2), ISC_FAIL);
INI_VOID_LOADLIB_PKI(void, free_UTC_TIME, (UTC_TIME *utcTime), (utcTime) );
INI_VOID_LOADLIB_PKI(void, clean_UTC_TIME, (UTC_TIME *utcTime), (utcTime) );
INI_RET_LOADLIB_PKI(ISC_STATUS, copy_UTC_TIME, (UTC_TIME *from, UTC_TIME *to), (from,to), ISC_FAIL);
INI_RET_LOADLIB_PKI(GENERALIZED_TIME*, new_GENERALIZED_TIME, (const char *data, int time_form), (data,time_form), NULL);
INI_RET_LOADLIB_PKI(GENERALIZED_TIME*, asn1TimeToGENERALIZED_TIME, (ASN1_TIME *asn1Time, int time_form), (asn1Time,time_form), NULL);
INI_VOID_LOADLIB_PKI(void, free_GENERALIZED_TIME, (GENERALIZED_TIME *GENERALIZEDTime), (GENERALIZEDTime) );
INI_VOID_LOADLIB_PKI(void, clean_GENERALIZED_TIME, (GENERALIZED_TIME *GENERALIZEDTime), (GENERALIZEDTime) );
INI_RET_LOADLIB_PKI(ISC_STATUS, copy_GENERALIZED_TIME, (GENERALIZED_TIME *from, GENERALIZED_TIME *to), (from,to), ISC_FAIL);
INI_RET_LOADLIB_PKI(BMP_STRING*, new_BMP_STRING, (const char *data, int dataLen), (data,dataLen), NULL);
INI_VOID_LOADLIB_PKI(void, free_BMP_STRING, (BMP_STRING *bmpString), (bmpString) );
INI_VOID_LOADLIB_PKI(void, clean_BMP_STRING, (BMP_STRING *bmpString), (bmpString) );
INI_RET_LOADLIB_PKI(ISC_STATUS, encodeToBERBoolean, (ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm), (asn1Unit,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encodeToBERInteger, (ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm), (asn1Unit,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encodeToBERBitString, (ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm), (asn1Unit,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encodeToBERNull, (ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm), (asn1Unit,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encodeToBERObjectIdentifier, (ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm), (asn1Unit,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encodeToBERUTCTime, (ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm), (asn1Unit,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encodeToBERGENERALIZEDTime, (ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm), (asn1Unit,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encodeToBERASN1String, (ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm), (asn1Unit,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encodeToBER, (ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm), (asn1Unit,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encodeToBER_CS, (ASN1_UNIT *asn1Unit, int cs_id, int type, void *value, int valueLen, int lengthForm), (asn1Unit,cs_id,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, addToBERSequence, (SEQUENCE *sequence, int type, void *value, int valueLen, int lengthForm), (sequence,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, addToBERSequenceOf, (SEQUENCE_OF *sequenceOf, int type, void *value, int valueLen, int lengthForm), (sequenceOf,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, addToBERSet, (SET *set, int type, void *value, int valueLen, int lengthForm), (set,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, addToBERSetOf, (SET_OF *setOf, int type, void *value, int valueLen, int lengthForm), (setOf,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, addToBERSequence_CS, (SEQUENCE *sequence, int cs_id, int type, void *value, int valueLen, int lengthForm), (sequence,cs_id,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, setBERLengthForm, (SEQUENCE *sequence, int lengthForm), (sequence,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, addToBERStringSequence, (STRING_SEQUENCE *stringSequence, int type, void *value, int valueLen, int lengthForm), (stringSequence,type,value,valueLen,lengthForm), ISC_FAIL);
INI_RET_LOADLIB_PKI(BOOLEAN*, decodeToBERBoolean, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(INTEGER*, decodeToBERInteger, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(BIT_STRING*, decodeToBERBitString, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(OCTET_STRING*, decodeToBEROctetString, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(NULL_VALUE*, decodeToBERNull, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, decodeToBERObjectIdentifier, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(ENUMERATED*, decodeToBEREnumerated, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(UTF8_STRING*, decodeToBERUTF8String, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(SEQUENCE*, decodeToBERSequence, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(PRINTABLE_STRING*, decodeToBERPrintableString, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(T61_STRING*, decodeToBERT61String, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(IA5_STRING*, decodeToBERIA5String, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(UTC_TIME*, decodeToBERUTCTime, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(GENERALIZED_TIME*, decodeToBERGENERALIZEDTime, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(BMP_STRING*, decodeToBERBMPString, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(ASN1_STRING*, decodeToBERASN1String, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(void*, getBERChildAt, (ASN1_UNIT *asn1Unit, int index, int childType), (asn1Unit,index,childType), NULL);
INI_RET_LOADLIB_PKI(void*, getBERChildOffset, (ASN1_UNIT *asn1Unit, int index, int childType, int* beforeOffset), (asn1Unit,index,childType,beforeOffset), NULL);
INI_VOID_LOADLIB_PKI(void, printBERData, (ASN1_UNIT *asn1Unit), (asn1Unit) );
INI_RET_LOADLIB_PKI(ISC_STATUS, checkDER, (int type, void *value, int *valueLen), (type,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encodeToDER, (ASN1_UNIT *asn1Unit, int type, void *value, int valueLen), (asn1Unit,type,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encodeToDER_CS, (ASN1_UNIT *asn1Unit, int cs_id, int type, void *value, int valueLen), (asn1Unit,cs_id,type,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, addToDERSequence, (SEQUENCE *sequence, int type, void *value, int valueLen), (sequence,type,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, addToDERSequenceOf, (SEQUENCE_OF *sequenceOf, int type, void *value, int valueLen), (sequenceOf,type,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, addToDERSet, (SET *set, int type, void *value, int valueLen), (set,type,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, addToDERSetOf, (SET_OF *setOf, int type, void *value, int valueLen), (setOf,type,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, addToDERSequence_CS, (SEQUENCE *sequence, int cs_id, int type, void *value, int valueLen), (sequence,cs_id,type,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(BOOLEAN*, decodeToDERBoolean, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(INTEGER*, decodeToDERInteger, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(BIT_STRING*, decodeToDERBitString, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(OCTET_STRING*, decodeToDEROctetString, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(NULL_VALUE*, decodeToDERNull, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, decodeToDERObjectIdentifier, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(ENUMERATED*, decodeToDEREnumerated, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(UTF8_STRING*, decodeToDERUTF8String, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(SEQUENCE*, decodeToDERSequence, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(PRINTABLE_STRING*, decodeToDERPrintableString, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(T61_STRING*, decodeToDERT61String, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(IA5_STRING*, decodeToDERIA5String, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(UTC_TIME*, decodeToDERUTCTime, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(GENERALIZED_TIME*, decodeToDERGENERALIZEDTime, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(BMP_STRING*, decodeToDERBMPString, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(ASN1_STRING*, decodeToDERASN1String, (uint8 *value), (value), NULL);
INI_RET_LOADLIB_PKI(void*, getDERChildAt, (ASN1_UNIT *asn1Unit, int index, int childType), (asn1Unit,index,childType), NULL);
INI_VOID_LOADLIB_PKI(void, printDERData, (ASN1_UNIT *asn1Unit), (asn1Unit) );
INI_RET_LOADLIB_PKI(int, hexToASCII, (uint8 *hex, int hexLen, uint8 *out), (hex,hexLen,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, ASN1_to_binary, (ASN1_UNIT *asn1Unit, uint8 **data), (asn1Unit,data), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, ASN1_STRING_to_binary, (ASN1_STRING *asn1Str, uint8 **data), (asn1Str,data), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, ASN1_to_FILE, (ASN1_UNIT *asn1Unit, const char *fileName), (asn1Unit,fileName), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, readDER_from_Binary, (void **st, PREAD_FUNC pReadFunc, uint8* derBytes), (st,pReadFunc,derBytes), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, readDER_from_File, (void **st, PREAD_FUNC pReadFunc, const char* fileName), (st,pReadFunc,fileName), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, writeDER_to_Binary, (void *st, PWRITE_FUNC pWreteFunc, uint8** derBytes), (st,pWreteFunc,derBytes), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, writeDER_to_FILE, (void *st, PWRITE_FUNC pWriteFunc, const char *fileName), (st,pWriteFunc,fileName), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, readPEM_from_Binary, (void **st, PREAD_FUNC pReadFunc, uint8* pemBytes, int pemLength), (st,pReadFunc,pemBytes,pemLength), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, readPEM_from_File, (void **st, PREAD_FUNC pReadFund, const char* fileName), (st,pReadFund,fileName), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, writePEM_to_Binary, (void *st, PWRITE_FUNC pWriteFunc, const char *pemStr, int pemStrLen, uint8** pemBytes), (st,pWriteFunc,pemStr,pemStrLen,pemBytes), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, writePEM_to_FILE, (void *st, PWRITE_FUNC pWriteFunc, const char *pemStr, int pemStrLen, const char* fileName), (st,pWriteFunc,pemStr,pemStrLen,fileName), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_ASN1_hash, (void *st, PWRITE_FUNC pWreteFunc ,int digest_id, uint8* md), (st,pWreteFunc,digest_id,md), ISC_FAIL);
INI_VOID_LOADLIB_PKI(void, print_PCHAR, (char* c, int len), (c,len) );
INI_RET_LOADLIB_PKI(char*, dump_PCHAR, (char* c, int len), (c,len), NULL);
INI_VOID_LOADLIB_PKI(void, print_ASN1STRING, (ASN1_STRING *st), (st) );
INI_RET_LOADLIB_PKI(char*, dump_ASN1STRING, (ASN1_STRING *st), (st), NULL);

#endif

/*!
* \brief
* STRING_SEQUENCE ����ü�� �����ϴ� ��ũ�� �Լ�
* \returns
* ������ STRING_SEQUENCE ����ü�� ������
*/
#define new_STRING_SEQUENCE() new_ASN1_UNIT()

/*!
* \brief
* STRING_SEQUENCE ����ü�� �޸� ���� ��ũ��  �Լ�
* \param stringSequence
* �޸𸮸� ������ STRING_SEQUENCE ����ü�� ������
*/
#define free_STRING_SEQUENCE(stringSequence) free_ASN1_UNIT((stringSequence))

/*!
* \brief
* STRING_SEQUENCE ����ü�� ���� �ʱ�ȭ�ϴ� ��ũ�� �Լ�
* \param stringSequence
* ���� �ʱ�ȭ �� STRING_SEQUENCE ����ü�� ������
*/
#define clean_STRING_SEQUENCE(stringSequence) clean_ASN1_UNIT((stringSequence))

/*!
* \brief
* INTEGER Ÿ���� Bytes ���̸� ���ϴ� ��ũ�� �Լ�
* \param bInt
* INTEGER ����ü�� ������
* \returns
* INTEGER Ÿ���� Bytes ����
*/
#define get_INTEGER_TYPE_bytes_length(bInt)			((ISC_IS_BIGINT_ZERO(bInt)||(bInt->data == 0L))? 1 : (ISC_Get_BIGINT_Bits_Length(bInt)+8)/8)

/*!
* \brief
* SEQUENCE ����ü�� �����ϴ� ��ũ�� �Լ�
* \returns
* ������ SEQUENCE ����ü�� ������
*/
#define new_SEQUENCE() new_ASN1_UNIT()
/*!
* \brief
* SEQUENCE ����ü�� �޸� ���� ��ũ��  �Լ�
* \param sequence
* �޸𸮸� ������ SEQUENCE ����ü�� ������
*/
#define free_SEQUENCE(sequence) free_ASN1_UNIT((sequence))
/*!
* \brief
* SEQUENCE ����ü�� ���� �ʱ�ȭ�ϴ� ��ũ�� �Լ�
* \param sequence
* ���� �ʱ�ȭ �� SEQUENCE ����ü�� ������
*/
#define clean_SEQUENCE(sequence) clean_ASN1_UNIT((sequence))

/*!
* \brief
* SEQUENCE_OF ����ü�� �����ϴ� ��ũ�� �Լ�
* \returns
* ������ SEQUENCE_OF ����ü�� ������
*/
#define new_SEQUENCE_OF() new_ASN1_UNIT()
/*!
* \brief
* SEQUENCE_OF ����ü�� �޸� ���� ��ũ��  �Լ�
* \param sequenceOf
* �޸𸮸� ������ SEQUENCE_OF ����ü�� ������
*/
#define free_SEQUENCE_OF(sequenceOf) free_ASN1_UNIT((sequenceOf))
/*!
* \brief
* SEQUENCE_OF ����ü�� ���� �ʱ�ȭ�ϴ� ��ũ�� �Լ�
* \param sequenceOf
* ���� �ʱ�ȭ �� SEQUENCE_OF ����ü�� ������
*/
#define clean_SEQUENCE_OF(sequenceOf) clean_ASN1_UNIT((sequenceOf))

/*!
* \brief
* SET ����ü�� �����ϴ� ��ũ�� �Լ�
* \returns
* ������ SET ����ü�� ������
*/
#define new_SET() new_ASN1_UNIT()
/*!
* \brief
* SET ����ü�� �޸� ���� ��ũ��  �Լ�
* \param set
* �޸𸮸� ������ SET ����ü�� ������
*/
#define free_SET(set) free_ASN1_UNIT((set))
/*!
* \brief
* SET ����ü�� ���� �ʱ�ȭ�ϴ� ��ũ�� �Լ�
* \param set
* ���� �ʱ�ȭ �� SET ����ü�� ������
*/
#define clean_SET(set) clean_ASN1_UNIT((set))

/*!
* \brief
* SET_OF ����ü�� �����ϴ� ��ũ�� �Լ�
* \returns
* ������ SET_OF ����ü�� ������
*/
#define new_SET_OF() new_ASN1_UNIT()
/*!
* \brief
* SET_OF ����ü�� �޸� ���� ��ũ��  �Լ�
* \param setOf
* �޸𸮸� ������ SET_OF ����ü�� ������
*/
#define free_SET_OF(setOf) free_ASN1_UNIT((setOf))
/*!
* \brief
* SET_OF ����ü�� ���� �ʱ�ȭ�ϴ� ��ũ�� �Լ�
* \param setOf
* ���� �ʱ�ȭ �� SET_OF ����ü�� ������
*/
#define clean_SET_OF(setOf) clean_ASN1_UNIT((setOf))

/*!
* \brief
* ����ü �̸��� seq_to_st �Լ��̸����� ���ν��� �ִ� ��ũ��
*/
#define READ_FUNC(st_name) Seq_to_##st_name

/*!
* \brief
* ����ü �̸��� st_to_seq �Լ��̸����� ���ν��� �ִ� ��ũ��
*/
#define WRITE_FUNC(st_name) st_name##_to_Seq

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_ASN1_H */

