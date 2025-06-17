/*!
* \file asn1.h
* \brief ASN.1 BER,DER Encoder/Decoder
* Abstract Syntax Notation One
* Basic Encoding Rules
* Distinguished Encoding Rules
* \remarks
* ASN.1 BER,DER 관련 구조체 및 함수 정의 헤더 파일
* ITU-T X.690 문서를 기준으로 작성되었음
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
 * SEQUENCE_OF 원래 값은 0x10로 SEQUENCE와 같지만
 * 길이 체크 때문에 구분 하였음 
 */
#define SEQUENCE_OF_TYPE			0x30	/*!< SEQUENCE OF(C)*/ 
#define SET_TYPE					0x11	/*!< SET(C)*/
/* 
 * SET_OF 원래 값은 0x11로 SET과 같지만
 * 길이 체크 때문에 구분 하였음 
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

#define ASN1_STRING_TYPE			0x20	/*!< ASN1의 모든 Type을 가리킴*/
#define STRING_SEQUENCE_TYPE		0x21	/*!< Constructed가 가능한 String Type(for BER)*/

#define SHORT_FORM					0x00	/*!< Short Form(길이 0 ~ 127)*/
#define LONG_FORM					0x01	/*!< Long Form(길이 128 이상)*/
#define INDEFINITE_FORM				0x02	/*!< Indefinite Form(길이 제한 없음, for BER)*/

/* UTC_TIME_TYPE에서 쓰이는 상수들 */
#define UTC_TIME_FORM				0x00	/*!< Universal Time Coordinated Form*/
#define LOCAL_TIME_FORM				0x00	/*!< Local Time Form*/
#define GMT_TIME_FORM				0x01	/*!< Greenwich Mean Time Form*/

#define YYMMDDhhmmZ					0x00	/*!< YY(년)MM(월)DD(일)hh(시)mm(분)Z(GMT)*/
#define YYMMDDhhmm_hhmm				0x01	/*!< YY(년)MM(월)DD(일)hh(시)mm(분)+,-hh(시)mm(분)*/
#define YYMMDDhhmmssZ				0x02	/*!< YY(년)MM(월)DD(일)hh(시)mm(분)ss(초)Z(GMT)*/
#define YYMMDDhhmmss_hhmm			0x03	/*!< YY(년)MM(월)DD(일)hh(시)mm(분)ss(초)+,-hh(시)mm(분)*/

#define YYYYMMDDhhmmZ				0x10	/*!< YYYY(년)MM(월)DD(일)hh(시)mm(분)Z(GMT)*/
#define YYYYMMDDhhmm_hhmm			0x11	/*!< YYYY(년)MM(월)DD(일)hh(시)mm(분)+,-hh(시)mm(분)*/
#define YYYYMMDDhhmmssZ				0x12	/*!< YYYY(년)MM(월)DD(일)hh(시)mm(분)ss(초)Z(GMT)*/
#define YYYYMMDDhhmmss_hhmm			0x13	/*!< YYYY(년)MM(월)DD(일)hh(시)mm(분)ss(초)+,-hh(시)mm(분)*/

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
* ASN.1 Encoding의 결과를 저장하는 구조체
*/
typedef struct ASN1_UNIT_structure {
	uint8 *Tag;		/*!< Identifier octets(Tag)의 포인터*/
	uint8 *Length;	/*!< Length octets의 포인터*/
	uint8 *Value;	/*!< Contents octets(Value)의 포인터*/
	uint8 *EOC;		/*!< End-of-contents octets(for Indefinite Form)의 포인터*/
} ASN1_UNIT;

/*!
* \brief
* ASN1_STRING의 정보를 담는 구조체
*/
typedef struct asn1_string_structure {
	int type;		/*!< 담고있는 Data의 Type*/	
	uint8 *data;	/*!< Data를 가리키는 포인터*/
	int length;		/*!< Data의 길이*/
	int opt;		/*!< Option : Unused Bit(for BIT_STRING_TYPE), Time Type(for UTC_TIME_TYPE)*/
} ASN1_STRING;

/*!
* \brief
* STRING_SEQUENCE(Constructed String)의 정보를 담는 구조체
* \remarks
* ANS1_UNIT 구조체 재정의
*/
typedef ASN1_UNIT STRING_SEQUENCE;

/*!
* \brief
* ASN1_TIME의 정보를 담는 구조체
* \remarks
* time.h의 tm 구조체 재정의
*/
typedef struct tm ASN1_TIME;

/*!
* \brief
* BOOLEAN 타입
* \remarks
* unsigned char 타입 재정의
*/
typedef uint8 BOOLEAN;

/*!
* \brief
* INTEGER의 정보를 담는 구조체
* \remarks
* ISC_BIGINT 구조체 재정의
*/
typedef ISC_BIGINT INTEGER;

/*!
* \brief
* BIT_STRING의 정보를 담는 구조체
* \remarks
* ASN1_STRING 구조체 재정의
*/
typedef ASN1_STRING BIT_STRING;

/*!
* \brief
* OCTET_STRING의 정보를 담는 구조체
* \remarks
* ASN1_STRING 구조체 재정의
*/
typedef ASN1_STRING OCTET_STRING;

/*!
* \brief
* NULL 타입
* \remarks
* int 타입 재정의
*/
typedef int NULL_VALUE;

/*!
* \brief
* OBJECT_IDENTIFIER의 정보를 담는 구조체
* \remarks
* ASN1_STRING 구조체 재정의
*/
typedef ASN1_STRING OBJECT_IDENTIFIER;

/*!
* \brief
* ENUMERATED의 정보를 담는 구조체
* \remarks
* ISC_BIGINT 구조체 재정의
*/
typedef ISC_BIGINT ENUMERATED;

/*!
* \brief
* UTF8_STRING의 정보를 담는 구조체
* \remarks
* ASN1_STRING 구조체 재정의
*/
typedef ASN1_STRING UTF8_STRING;

/*!
* \brief
* SEQUENCE의 정보를 담는 구조체
* \remarks
* ASN1_UNIT 구조체 재정의
*/
typedef ASN1_UNIT SEQUENCE;

/*!
* \brief
* SEQUENCE_OF의 정보를 담는 구조체
* \remarks
* ASN1_UNIT 구조체 재정의
*/
typedef ASN1_UNIT SEQUENCE_OF;

/*!
* \brief
* SET의 정보를 담는 구조체
* \remarks
* ASN1_UNIT 구조체 재정의
*/
typedef ASN1_UNIT SET;

/*!
* \brief
* SET_OF의 정보를 담는 구조체
* \remarks
* ASN1_UNIT 구조체 재정의
*/
typedef ASN1_UNIT SET_OF;

/*!
* \brief
* PRINTABLE_STRING의 정보를 담는 구조체
* \remarks
* ASN1_STRING 구조체 재정의
*/
typedef ASN1_STRING PRINTABLE_STRING;

/*!
* \brief
* T61_STRING의 정보를 담는 구조체
* \remarks
* ASN1_STRING 구조체 재정의
*/
typedef ASN1_STRING T61_STRING;

/*!
* \brief
* IA5_STRING의 정보를 담는 구조체
* \remarks
* ASN1_STRING 구조체 재정의
*/
typedef ASN1_STRING IA5_STRING;

/*!
* \brief
* UTC_TIME의 정보를 담는 구조체
* \remarks
* ASN1_STRING 구조체 재정의
*/
typedef ASN1_STRING UTC_TIME;

/*!
* \brief
* GENERALIZED_TIME의 정보를 담는 구조체
* \remarks
* ASN1_STRING 구조체 재정의
*/
typedef ASN1_STRING GENERALIZED_TIME;

/*!
* \brief
* BMP_STRING의 정보를 담는 구조체
* \remarks
* ASN1_STRING 구조체 재정의
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
* ASN1_UNIT 구조체를 생성하는 함수
* \returns
* 생성된 ASN1_UNIT 구조체의 포인터
*/
ISC_API ASN1_UNIT *new_ASN1_UNIT(void);

/*!
* \brief
* ASN1_UNIT 구조체의 메모리 해지 함수
* \param asn1Unit
* 메모리를 해지할 ASN1_UNIT 구조체의 포인터
*/
ISC_API void free_ASN1_UNIT(ASN1_UNIT *asn1Unit);

/*!
* \brief
* ASN1_UNIT 구조체의 값을 초기화하는 함수
* \param asn1Unit
* 값을 초기화 할 ASN1_UNIT 구조체의 포인터
*/
ISC_API void clean_ASN1_UNIT(ASN1_UNIT *asn1Unit);

/*!
* \brief
* ASN1_UNIT 구조체를 복사하는 함수
* \param asn1Unit
* 복사할 원본 ASN1_UNIT 구조체의 포인터
* \returns
* 복사된 ASN1_UNIT 구조체의 포인터
*/
ISC_API ASN1_UNIT * dup_ASN1_UNIT(ASN1_UNIT *asn1Unit);

/*!
* \brief
* ASN1_STRING 구조체를 생성하는 함수
* \returns
* 생성된 ASN1_STRING 구조체의 포인터
*/
ISC_API ASN1_STRING *new_ASN1_STRING(void);

/*!
* \brief
* ASN1_STRING 구조체의 메모리 해지 함수
* \param asn1String
* 메모리를 해지할 ASN1_STRING 구조체의 포인터
*/
ISC_API void free_ASN1_STRING(ASN1_STRING *asn1String);

/*!
* \brief
* ASN1_STRING 구조체의 값을 초기화하는 함수
* \param asn1String
* 값을 초기화 할 ASN1_STRING 구조체의 포인터
*/
ISC_API void clean_ASN1_STRING(ASN1_STRING *asn1String);

/*!
* \brief
* ASN1_STRING 구조체에 값을 저장하는 함수
* \param asn1String
* 값을 저장할 ASN1_STRING 구조체의 포인터
* \param type
* ASN1_STRING Data의 타입
* \param data
* 저장할 Data의 포인터
* \param dLen
* 저장할 Data의 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SET_ASN1_STRING_VALUE^ISC_ERR_NULL_INPUT : 입력값이 NULL인 경우
*/
ISC_API ISC_STATUS set_ASN1_STRING_value(ASN1_STRING *asn1String, int type, const uint8* data, int dLen);

/*!
* \brief
* ASN1_STRING 구조체를 SEQUENCE 구조체로 변환하는 함수
* \param asn1String
* 변환할 ASN1_STRING 구조체의 포인터
* \param seq
* SEQUENCE 구조체의 이중 포인터
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ASN1_STRING_TO_SEQ^ISC_ERR_NULL_INPUT : 입력값이 NULL인 경우
* -# LOCATION^F_ASN1_STRING_TO_SEQ^ISC_ERR_INVALID_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS ASN1_STRING_to_Seq(ASN1_STRING *asn1String, SEQUENCE **seq);

/*!
* \brief
* ASN1_STRING 구조체를 복사하는 함수
* \param asn1String
* 복사할 원본 ASN1_STRING 구조체의 포인터
* \returns
* 복사된 ASN1_STRING 구조체의 포인터
*/
ISC_API ASN1_STRING* dup_ASN1_STRING(ASN1_STRING *asn1String);

/*!
* \brief
* ASN1_STRING 구조체를 서로 비교하는 함수
* \param a
* 원본
* \param b
* 비교대상
* \returns
* 비교 결과(0 = equal)
*/
ISC_API int cmp_ASN1_STRING(ASN1_STRING *a, ASN1_STRING *b);

/*!
* \brief
* ASN1_TIME 구조체를 생성하는 함수
* \returns
* 생성된 ASN1_TIME 구조체의 포인터
*/
ISC_API ASN1_TIME *new_ASN1_TIME(void);

/*!
* \brief
* 문자열을 ASN1_TIME 구조체로 변환하는 함수
* 문자열 형식 = YYYY-MM-DD,hh:mm:ss
* Ex) 2008-12-25,23:24:35
* \param data
* 시간정보를 담고 있는 문자열의 포인터
* \returns
* 변환된 ASN1_TIME 구조체의 포인터
*/

ISC_API ASN1_TIME *charToASN1_TIME(const char *data);
/*!
* \brief
* ASN1_TIME 구조체의 메모리 해지 함수
* \param asn1Time
* 메모리를 해지할 ASN1_TIME 구조체의 포인터
*/
ISC_API void free_ASN1_TIME(ASN1_TIME *asn1Time);
/*!
* \brief
* ASN1_TIME 구조체의 값을 초기화하는 함수
* \param asn1Time
* 값을 초기화 할 ASN1_TIME 구조체의 포인터
*/
ISC_API void clean_ASN1_TIME(ASN1_TIME *asn1Time);
/*!
* \brief
* ASN1_TIME의 값을 체크하는 함수
* \param asn1Time
* ASN1_TIME 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CHECK_ASN1_TIME^ISC_ERR_INVALID_INPUT : 입력 파라미터 오류 
* \remarks
* 월(Month)의 범위 : 0(1월) ~ 11(12월)
* 시(Hour)의 범위 : 0(자정) ~ 23(11PM)
*/
ISC_API ISC_STATUS check_ASN1_TIME(ASN1_TIME asn1Time);
/*!
* \brief
* ASN1_TIME 구조체를 복사하는 함수
* \param asn1Time
* 복사할 원본 ASN1_TIME 구조체의 포인터
* \returns
* 복사된 ASN1_TIME 구조체의 포인터
*/
ISC_API ASN1_TIME* dup_ASN1_TIME(ASN1_TIME *asn1Time); 
/*!
* \brief
* 현재시간을 ASN1_TIME 구조체 형식으로 구하는 함수
* \returns
* 현재시간을 저장하고 있는 ASN1_TIME 구조체의 포인터
*/
/*ISC_API ASN1_TIME *getCurrentTime(void);*//* delete*/
/*!
* \brief
* 현재시간을 ASN1_TIME 구조체 형식으로 구하는 함수
* \returns
* 현재시간(Local time)을 저장하고 있는 ASN1_TIME 구조체의 포인터
*/
ISC_API ASN1_TIME *getCurrentLocalTime(void);
/*!
* \brief
* 현재시간을 ASN1_TIME 구조체 형식으로 구하는 함수
* \returns
* 현재시간(GM time)을 저장하고 있는 ASN1_TIME 구조체의 포인터
*/
ISC_API ASN1_TIME *getCurrentGMTime(void);

/*!
* \brief
* ASN1_UNIT의 Length octets의 크기를 구하는 함수
* \param lengthOctet
* ASN1_UNIT의 Length octets의 포인터
* \returns
* ASN1_UNIT의 Length octets의 크기(Byte)
*/
ISC_API int getASN1LengthSize(uint8 *lengthOctet);

/*!
* \brief
* ASN1_UNIT의 Contents octets의 길이를 구하는 함수
* \param asn1Unit
* ASN1_UNIT의 포인터
* \returns
* -# ASN1_UNIT의 Contents octets의 길이(Byte) : 성공
* -# -1 : 실패
*/
ISC_API int getASN1ValueLength(ASN1_UNIT *asn1Unit);

/*!
* \brief
* ASN1_UNIT의 Contents octets의 길이를 구하는 함수(from Length octets)
* \param lengthOctet
* ASN1_UNIT의 Length octets의 포인터
* \returns
* -# ASN1_UNIT의 Contents octets의 길이(Byte) : 성공
* -# -1 : 실패
*/
ISC_API int getASN1ValueLengthFromLO(uint8 *lengthOctet);

/*!
* \brief
* Indefinite Form 형태인 ASN1_UNIT의 Contents octets의 길이를 구하는 함수
* \param contentsOctet
* ASN1_UNIT의 Contents octets의 포인터
* \returns
* -# ASN1_UNIT의 Contents octets의 길이(Byte) : 성공
* -# -1 : 실패
*/
ISC_API int getASN1IndefiniteValueLength(uint8 *contentsOctet);

/*!
* \brief
* 정수의 Ascii String 길이를 구하는 함수
* \param number
* 정수의 값을 저장하고 있는 변수
* \returns
* Ascii String으로 변환 했을 때의 길이
*/
ISC_API int getAsciiStringLength(int number);

/*!
* \brief
* SEQUENCE 구조체의 자식의 갯수를 구하는 함수
* \param sequence
* SEQUENCE 구조체의 포인터
* \returns
* SEQUENCE 구조체의 자식의 갯수
*/
ISC_API int getSequenceChildNum(SEQUENCE *sequence);

/*!
* \brief
* SEQUENCE 구조체의 index번째 있는 자식의 타입을 구하는 함수
* \param sequence
* SEQUENCE 구조체의 포인터
* \param index
* SEQUENCE 구조체 자식의 index
* \returns
* -# SEQUENCE 구조체의 index번째 있는 자식의 타입 : 성공
* -# -1 : 실패
*/
ISC_API int getChildType(SEQUENCE *sequence, int index);

/*!
* \brief
* ASN1_UNIT의 Length Form을 구하는 함수
* \param type
* ASN1_UNIT의 타입
* \param valueLen
* ASN1_UNIT의 Contents octets의 길이
* \returns
* ASN1_UNIT의 Length Form
*/
ISC_API int getASN1LengthForm(int type, int valueLen);

/************************************************
*												*
*		CP949(Code Page 949, Windows 문자열)		*
*												*
************************************************/ 
/*!
* \brief
* CP949(Windows)형태의 문자열을 Unicode형태로 변환하는 함수
* \param byte1
* 문자열의 첫 번째 바이트
* \param byte2
* 문자열의 두 번째 바이트
* \returns
* 변환된 Unicode 값
*/
ISC_API uint16 cp949ToUnicode(uint8 byte1, uint8 byte2);

/*!
* \brief
* CP949(Windows)형태의 문자열을 UTF8(Unicode Transformation Format 8)형태로 변환하는 함수
* \param data
* 문자열의 포인터
* \param utf8
* UTF8 문자열을 저장할 버퍼의 이중 포인터
* \returns
* 변환된 UTF8문자열의 길이
*/
ISC_API int cp949ToUTF8(const char *data, uint8 **utf8);

/*!
* \brief
* CP949(Windows)형태의 문자열을 BMP(Basic Multilingual Plane)형태로 변환하는 함수
* \param data
* 문자열의 포인터
* \param bmp
* BMP 문자열을 저장할 버퍼의 이중 포인터
* \returns
* 변환된 BMP문자열의 길이
*/
ISC_API int cp949ToBMP(const char *data, uint8 **bmp);

/*!
* \brief
* Unicode를 CP949(Windows)형태의 문자열로 변환하는 함수
* \param unicode
* Unicode값을 저장하고 있는 변수
* \returns
* 변환된 CP949문자열의 포인터
*/
ISC_API uint8 *unicodeToCP949(long unicode);

/*!
* \brief
* UTF8_STRING 구조체를 CP949(Windows)형태의 문자열로 변환하는 함수
* \param utf8String
* UTF8_STRING 구조체의 포인터
* \param cp949
* CP949 문자열을 저장할 버퍼의 이중 포인터
* \returns
* 변환된 CP949문자열의 길이
*/
ISC_API int utf8ToCP949(UTF8_STRING *utf8String, uint8 **cp949);

/*!
* \brief
* BMP_STRING 구조체를 CP949(Windows)형태의 문자열로 변환하는 함수
* \param bmpString
* BMP_STRING 구조체의 포인터
* \param cp949
* CP949 문자열을 저장할 버퍼의 이중 포인터
* \returns
* 변환된 CP949문자열의 길이
*/
ISC_API int bmpToCP949(BMP_STRING *bmpString, uint8 **cp949);

/*!
* \brief
* Ascii형태의 문자열을 Unicode로 변환하는 함수
* \param asc
* Ascii문자열의 포인터
* \param asclen
* Ascii문자열의 길이
* \param uni
* Unicode를 저장할 버퍼의 이중 포인터
* \param unilen
* Unicode의 길이를 저장할 변수의 포인터
* \returns
* 변환된 Unicode의 포인터
*/
ISC_API uint8 *ascTouni(const char *asc, int asclen, uint8 **uni, int *unilen);

/*!
* \brief
* Unicode를 Ascii형태의 문자열로 변환하는 함수
* \param uni
* Unicode의 포인터
* \param unilen
* Unicode의 길이
* \returns
* 변환된 Ascii문자열의 포인터
*/
ISC_API char *uniToasc(uint8 *uni, int unilen);


/************************************************
*												*
*	  UTC_TIME(Universal Time, Coordinated)		*
*												*
************************************************/
/*!
* \brief
* UTC_TIME 구조체를 ASN1_TIME 구조체 형태로 변환하는 함수
* \param utcTime
* UTC_TIME 구조체의 포인터
* \returns
* 변환된 ASN1_TIME 구조체의 포인터
*/
ISC_API ASN1_TIME *utcTimeToASN1_TIME(UTC_TIME *utcTime);

/*!
* \brief
* 두개의 UTC_TIME 구조체의 시간을 비교하는 함수
* \param utcTime1
* 첫 번째 UTC_TIME 구조체의 포인터
* \param utcTime2
* 두 번째 UTC_TIME 구조체의 포인터
* \returns
* -# 1 : 첫 번째 UTC_TIME 구조체의 시간이 나중일 경우
* -# 0 : 두 구조체의 시간이 같을 경우
* -# -1 : 두 번째 UTC_TIME 구조체의 시간이 나중일 경우
*/
ISC_API int cmp_UTC_TIME(UTC_TIME *utcTime1, UTC_TIME *utcTime2);

/*!
* \brief
* UTC_TIME 구조체에 시간을 더하는 함수
* \param utcTime
* UTC_TIME 구조체의 이중 포인터
* \param seconds
* 더할 시간의 총 시간(단위 : 초(seconds))
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_UTC_TIME^ISC_ERR_NULL_INPUT : 입력값이 NULL일 경우
* -# LOCATION^F_ADD_UTC_TIME^ISC_ERR_INVALID_OUTPUT : 잘못된 결과값일 경우
*/
ISC_API ISC_STATUS add_UTC_TIME(UTC_TIME **utcTime, long seconds);


/********************************************************
*														*
*	  GENERALIZED_TIME(Universal Time, Coordinated)		*
*														*
*********************************************************/
/*!
* \brief
* GENERALIZED_TIME 구조체를 ASN1_TIME 구조체 형태로 변환하는 함수
* \param generalizedTime
* GENERALIZED_TIME 구조체의 포인터
* \returns
* 변환된 ASN1_TIME 구조체의 포인터
*/
ISC_API ASN1_TIME *generalizedTimeToASN1_TIME(GENERALIZED_TIME *generalizedTime);

/*!
* \brief
* 두개의 GENERALIZED_TIME 구조체의 시간을 비교하는 함수
* \param generalizedTime1
* 첫 번째 GENERALIZED_TIME 구조체의 포인터
* \param generalizedTime2
* 두 번째 GENERALIZED_TIME 구조체의 포인터
* \returns
* -# 1 : 첫 번째 GENERALIZED_TIME 구조체의 시간이 나중일 경우
* -# 0 : 두 구조체의 시간이 같을 경우
* -# -1 : 두 번째 GENERALIZED_TIME 구조체의 시간이 나중일 경우
*/
ISC_API int cmp_GENERALIZED_TIME(GENERALIZED_TIME *generalizedTime1, GENERALIZED_TIME *generalizedTime2);

/*!
* \brief
* GENERALIZED_TIME 구조체에 시간을 더하는 함수
* \param generalizedTime
* GENERALIZED_TIME 구조체의 이중 포인터
* \param seconds
* 더할 시간의 총 시간(단위 : 초(seconds))
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_GENERALIZED_TIME^ISC_ERR_NULL_INPUT : 입력값이 NULL일 경우
* -# LOCATION^F_ADD_GENERALIZED_TIME^ISC_ERR_INVALID_OUTPUT : 잘못된 결과값일 경우
*/
ISC_API ISC_STATUS add_GENERALIZED_TIME(GENERALIZED_TIME **generalizedTime, long seconds);


/************************************************
*												*
*			BER(Basic Encoding Rules)			*
*												*
************************************************/
/*!
* \brief
* 2진수 문자열로부터 BIT_STRING 구조체를 생성하는 함수
* Ex) "01001000101111"
* \param data
* 2진수 문자열의 포인터
* \param 길이
* 2진수 문자열의 길이
* \returns
* 생성된 BIT_STIRNG 구조체의 포인터
*/
ISC_API BIT_STRING *new_BIT_STRING(const char *data, int dataLen);

/*!
* \brief
* 16진수 문자열로부터 BIT_STRING 구조체를 생성하는 함수
* Ex) "AB01EF7"
* \param data
* 16진수 문자열의 포인터
* \param dataLen
* 16진수 문자열의 길이
* \returns
* 생성된 BIT_STIRNG 구조체의 포인터
*/
ISC_API BIT_STRING *hexToBIT_STRING(const char *data, int dataLen);

/*!
* \brief
* 바이너리 배열로부터 BIT_STRING 구조체를 생성하는 함수
* \param data
* 바이너리 배열의 포인터
* \param dataLen
* 바이너리 배열의 길이(Byte)
* \returns
* 생성된 BIT_STIRNG 구조체의 포인터
*/
ISC_API BIT_STRING *binaryToBIT_STRING(const uint8 *data, int dataLen);

/*!
* \brief
* BIT_STRING 구조체에 패딩을 하는 함수
* \param bitString
* BIT_STRING 구조체의 포인터
* \param paddingBits
* 패딩을 할 2진수 문자열의 포인터, Ex) "10111"
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_PAD_TO_BER_BIT_STRING^ERR_INVALID_ENCODE_INPUT : 잘못된 입력 파라미터
*/
ISC_API ISC_STATUS addPadToBERBitString(BIT_STRING *bitString, const char *paddingBits);

/*!
* \brief
* BIT_STRING 구조체의 메모리 해지 함수
* \param bitString
* 메모리를 해지할 BIT_STRING 구조체의 포인터
*/
ISC_API void free_BIT_STRING(BIT_STRING *bitString);

/*!
* \brief
* BIT_STRING 구조체의 값을 초기화하는 함수
* \param bitString
* 값을 초기화 할 BIT_STRING 구조체의 포인터
*/
ISC_API void clean_BIT_STRING(BIT_STRING *bitString);

/*!
* \brief
* OCTET_STRING 구조체를 생성하는 함수
* \param data
* 바이너리 데이터의 포인터
* \param dataLen
* 데이터의 길이(Byte)
* \returns
* 생성된 OCTET_STRING 구조체의 포인터
*/
ISC_API OCTET_STRING *new_OCTET_STRING(const uint8 *data, int dataLen);

/*!
* \brief
* OCTET_STRING 구조체의 메모리 해지 함수
* \param octestString
* 메모리를 해지할 OCTET_STRING 구조체의 포인터
*/
ISC_API void free_OCTET_STRING(OCTET_STRING *octestString);

/*!
* \brief
* OCTET_STRING 구조체의 값을 초기화하는 함수
* \param octestString
* 값을 초기화 할 OCTET_STRING 구조체의 포인터
*/
ISC_API void clean_OCTET_STRING(OCTET_STRING *octestString);

/*!
* \brief
* OBJECT_IDENTIFIER 구조체를 생성하는 함수
* \param data
* OID 문자열의 포인터, Ex) "1.2.840.113549.1.7"
* \param dataLen
* OID 문자열의 길이
* \returns
* 생성된 OBJECT_IDENTIFIER 구조체의 포인터
*/
ISC_API OBJECT_IDENTIFIER *new_OBJECT_IDENTIFIER(const char *data, int dataLen);

/*!
* \brief
* OBJECT_IDENTIFIER 구조체의 메모리 해지 함수
* \param oId
* 메모리를 해지할 OBJECT_IDENTIFIER 구조체의 포인터
*/
ISC_API void free_OBJECT_IDENTIFIER(OBJECT_IDENTIFIER *oId);

/*!
* \brief
* OBJECT_IDENTIFIER 구조체의 값을 초기화하는 함수
* \param oId
* 값을 초기화 할 OBJECT_IDENTIFIER 구조체의 포인터
*/
ISC_API void clean_OBJECT_IDENTIFIER(OBJECT_IDENTIFIER *oId);

/*!
* \brief
* UTF8_STRING 구조체를 생성하는 함수
* \param data
* 바이너리 데이터의 포인터
* \param dataLen
* 데이터의 길이(Byte)
* \returns
* 생성된 UTF8_STRING 구조체의 포인터
*/
ISC_API UTF8_STRING *new_UTF8_STRING(const uint8 *data, int dataLen);

/*!
* \brief
* UTF8_STRING 구조체의 메모리 해지 함수
* \param utf8String
* 메모리를 해지할 UTF8_STRING 구조체의 포인터
*/
ISC_API void free_UTF8_STRING(UTF8_STRING *utf8String);

/*!
* \brief
* UTF8_STRING 구조체의 값을 초기화하는 함수
* \param utf8String
* 값을 초기화 할 UTF8_STRING 구조체의 포인터
*/
ISC_API void clean_UTF8_STRING(UTF8_STRING *utf8String);

/*!
* \brief
* PRINTABLE_STRING 구조체를 생성하는 함수
* \param data
* 문자열의 포인터
* \param length
* 문자열의 길이
* \returns
* 생성된 PRINTABLE_STRING 구조체의 포인터
*/
ISC_API PRINTABLE_STRING *new_PRINTABLE_STRING(const char *data, int length);

/*!
* \brief
* PRINTABLE_STRING 구조체의 메모리 해지 함수
* \param pString
* 메모리를 해지할 PRINTABLE_STRING 구조체의 포인터
*/
ISC_API void free_PRINTABLE_STRING(PRINTABLE_STRING *pString);

/*!
* \brief
* PRINTABLE_STRING 구조체의 값을 초기화하는 함수
* \param pString
* 값을 초기화 할 PRINTABLE_STRING 구조체의 포인터
*/
ISC_API void clean_PRINTABLE_STRING(PRINTABLE_STRING *pString);

/*!
* \brief
* T61_STRING 구조체를 생성하는 함수
* \param data
* 문자열의 포인터
* \returns
* 생성된 T61_STRING 구조체의 포인터
*/
ISC_API T61_STRING *new_T61_STRING(const char *data, int dataLen);

/*!
* \brief
* T61_STRING 구조체의 메모리 해지 함수
* \param pString
* 메모리를 해지할 T61_STRING 구조체의 포인터
*/
ISC_API void free_T61_STRING(T61_STRING *pString);

/*!
* \brief
* T61_STRING 구조체의 값을 초기화하는 함수
* \param pString
* 값을 초기화 할 T61_STRING 구조체의 포인터
*/
ISC_API void clean_T61_STRING(T61_STRING *pString);

/*!
* \brief
* IA5_STRING 구조체를 생성하는 함수
* \param data
* IA5(International Alphabet 5) 문자열의 포인터
* \param dataLen
* 문자열의 길이(Byte)
* \returns
* 생성된 IA5_STRING 구조체의 포인터
*/
ISC_API IA5_STRING *new_IA5_STRING(const char *data, int dataLen);

/*!
* \brief
* IA5_STRING 구조체의 메모리 해지 함수
* \param ia5String
* 메모리를 해지할 IA5_STRING 구조체의 포인터
*/
ISC_API void free_IA5_STRING(IA5_STRING *ia5String);

/*!
* \brief
* IA5_STRING 구조체의 값을 초기화하는 함수
* \param ia5String
* 값을 초기화 할 IA5_STRING 구조체의 포인터
*/
ISC_API void clean_IA5_STRING(IA5_STRING *ia5String);

/*!
* \brief
* UTC_TIME 구조체를 생성하는 함수
* \param data
* 시간 정보를 담고있는 문자열의 포인터, Ex)"2008-12-25,23:11:20"
* \param time_form
* 저장할 시간의 형태, Ex)YYMMDDhhmmZ
* \returns
* 생성된 UTC_TIME 구조체의 포인터
*/
ISC_API UTC_TIME *new_UTC_TIME(const char *data, int time_form);

/*!
* \brief
* ASN1_TIME 구조체를 UTC_TIME 구조체로 변환하는 함수
* \param asn1Time
* ASN1_TIME 구조체의 포인터
* \param time_form
* 저장할 시간의 형태, Ex)YYMMDDhhmmZ
* \returns
* 생성된 UTC_TIME 구조체의 포인터
*/
ISC_API UTC_TIME *asn1TimeToUTC_TIME(ASN1_TIME *asn1Time, int time_form);

/*!
* \brief
* ASN1_TIME 을 서로 비교함
* \param asn1Time1
* ASN1_TIME 구조체의 포인터1
* \param asn1Time2
* ASN1_TIME 구조체의 포인터2
* \returns
* 비교한 결과(asn1Time1 - asn1Time2);
*/
ISC_API int cmp_ASN1_TIME(ASN1_TIME *asn1Time1, ASN1_TIME *asn1Time2);

/*!
* \brief
* UTC_TIME 구조체의 메모리 해지 함수
* \param utcTime
* 메모리를 해지할 UTC_TIME 구조체의 포인터
*/
ISC_API void free_UTC_TIME(UTC_TIME *utcTime);

/*!
* \brief
* UTC_TIME 구조체의 값을 초기화하는 함수
* \param utcTime
* 값을 초기화 할 UTC_TIME 구조체의 포인터
*/
ISC_API void clean_UTC_TIME(UTC_TIME *utcTime);

/*!
* \brief
* UTC_TIME 구조체를 복사하는 함수
* \param from
* 복사할 원본
* \param to
* 복사될 대상(메모리 할당해서 줄것.)
*/
ISC_API ISC_STATUS copy_UTC_TIME(UTC_TIME *from, UTC_TIME *to);

/*!
* \brief
* GENERALIZED_TIME 구조체를 생성하는 함수
* \param data
* 시간 정보를 담고있는 문자열의 포인터, Ex)"2008-12-25,23:11:20"
* \param time_form
* 저장할 시간의 형태, Ex)YYMMDDhhmmZ
* \returns
* 생성된 GENERALIZED_TIME 구조체의 포인터
*/
ISC_API GENERALIZED_TIME *new_GENERALIZED_TIME(const char *data, int time_form);

/*!
* \brief
* ASN1_TIME 구조체를 GENERALIZED_TIME 구조체로 변환하는 함수
* \param asn1Time
* ASN1_TIME 구조체의 포인터
* \param time_form
* 저장할 시간의 형태, Ex)YYMMDDhhmmZ
* \returns
* 생성된 GENERALIZED_TIME 구조체의 포인터
*/
ISC_API GENERALIZED_TIME *asn1TimeToGENERALIZED_TIME(ASN1_TIME *asn1Time, int time_form);

/*!
* \brief
* GENERALIZED_TIME 구조체의 메모리 해지 함수
* \param GENERALIZEDTime
* 메모리를 해지할 GENERALIZED_TIME 구조체의 포인터
*/
ISC_API void free_GENERALIZED_TIME(GENERALIZED_TIME *GENERALIZEDTime);

/*!
* \brief
* GENERALIZED_TIME 구조체의 값을 초기화하는 함수
* \param GENERALIZEDTime
* 값을 초기화 할 GENERALIZED_TIME 구조체의 포인터
*/
ISC_API void clean_GENERALIZED_TIME(GENERALIZED_TIME *GENERALIZEDTime);

/*!
* \brief
* GENERALIZED_TIME 구조체를 복사하는 함수
* \param from
* 복사할 원본
* \param to
* 복사될 대상(메모리 할당해서 줄것.)
*/
ISC_API ISC_STATUS copy_GENERALIZED_TIME(GENERALIZED_TIME *from, GENERALIZED_TIME *to);


/*!
* \brief
* BMP_STRING 구조체를 생성하는 함수
* \param data
* 바이너리 데이터의 포인터
* \param dataLen
* 문자열의 길이(Byte)
* \returns
* 생성된 BMP_STRING 구조체의 포인터
*/
ISC_API BMP_STRING *new_BMP_STRING(const char *data, int dataLen);

/*!
* \brief
* BMP_STRING 구조체의 메모리 해지 함수
* \param bmpString
* 메모리를 해지할 BMP_STRING 구조체의 포인터
*/
ISC_API void free_BMP_STRING(BMP_STRING *bmpString);

/*!
* \brief
* BMP_STRING 구조체의 값을 초기화하는 함수
* \param bmpString
* 값을 초기화 할 BMP_STRING 구조체의 포인터
*/
ISC_API void clean_BMP_STRING(BMP_STRING *bmpString);

/*!
* \brief
* Boolean 값을 BER로 Encoding하는 함수
* \param asn1Unit
* Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCODE_TO_BER_BOOLEAN^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS encodeToBERBoolean(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Integer 값을 BER로 Encoding하는 함수
* \param asn1Unit
* Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCODE_TO_BER_INTEGER^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS encodeToBERInteger(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Bit String 값을 BER로 Encoding하는 함수
* \param asn1Unit
* Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCODE_TO_BER_BIT_STRING^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS encodeToBERBitString(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Null 값을 BER로 Encoding하는 함수
* \param asn1Unit
* Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCODE_TO_BER_NULL^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS encodeToBERNull(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Object Identifier 값을 BER로 Encoding하는 함수
* \param asn1Unit
* Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCODE_TO_BER_OBJECT_IDENTIFIER^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS encodeToBERObjectIdentifier(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Utc Time 값을 BER로 Encoding하는 함수
* \param asn1Unit
* Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCODE_TO_BER_UTC_TIME^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS encodeToBERUTCTime(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* GENERALIZED Time 값을 BER로 Encoding하는 함수
* \param asn1Unit
* Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCODE_TO_BER_UTC_TIME^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS encodeToBERGENERALIZEDTime(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* ASN1 String 값을 BER로 Encoding하는 함수
* \param asn1Unit
* Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCODE_TO_BER_ASN1_STRING^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS encodeToBERASN1String(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* 데이터를 BER로 Encoding하는 함수
* \param asn1Unit
* Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCODE_TO_BER^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS encodeToBER(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* 데이터를 Context-Specific 형태의 BER로 Encoding하는 함수
* \param asn1Unit
* Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
* \param cs_id
* Context-Specific ID
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCODE_TO_BER_CS^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS encodeToBER_CS(ASN1_UNIT *asn1Unit, int cs_id, int type, void *value, int valueLen, int lengthForm);
    
/*!
 * \brief
 * 데이터를 Context-Specific 형태의 BER로 Encoding하는 함수
 * \param asn1Unit
 * Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
 * \param cs_id
 * Context-Specific ID
 * \param type
 * Encoding할 Type
 * \param value
 * 데이터의 void형 포인터
 * \param valueLen
 * 데이터의 길이(Byte)
 * \param lengthForm
 * Encoding할 Length Form
 * \returns
 * -# ISC_SUCCESS : 성공
 * -# LOCATION^F_ENCODE_TO_BER_CS^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
 */
ISC_API ISC_STATUS encodeToBER_CS_Scraping(ASN1_UNIT *asn1Unit, int cs_id, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* 데이터를 SEQUENCE에 저장한 뒤 BER로 Encoding하는 함수
* \param sequence
* Encoding 결과를 저장할 SEQUENCE 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_TO_BER_SEQUENCE^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS addToBERSequence(SEQUENCE *sequence, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* 데이터를 SEQUENCE OF에 저장한 뒤 BER로 Encoding하는 함수
* \param sequenceOf
* Encoding 결과를 저장할 SEQUENCE OF 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_TO_BER_SEQUENCE_OF^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS addToBERSequenceOf(SEQUENCE_OF *sequenceOf, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* 데이터를 SET에 저장한 뒤 BER로 Encoding하는 함수
* \param set
* Encoding 결과를 저장할 SET 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_TO_BER_SET^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS addToBERSet(SET *set, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* 데이터를 SET OF에 저장한 뒤 BER로 Encoding하는 함수
* \param setOf
* Encoding 결과를 저장할 SET OF 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_TO_BER_SET_OF^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS addToBERSetOf(SET_OF *setOf, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* 데이터를 Context-Specific 형태의 SEQUENCE로 저장한 뒤 BER로 Encoding하는 함수
* \param sequence
* Encoding 결과를 저장할 SEQUENCE 구조체의 포인터
* \param cs_id
* Context-Specific ID
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_TO_BER_SEQUENCE_CS^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS addToBERSequence_CS(SEQUENCE *sequence, int cs_id, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Encoding 된 SEQUENCE 구조체의 Length Form을 세팅하는 함수
* \param sequence
* SEQUENCE 구조체의 포인터
* \param lengthForm
* 세팅할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SET_BER_LENGTH_FORM^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS setBERLengthForm(SEQUENCE *sequence, int lengthForm);

/*!
* \brief
* 데이터를 STRING SEQUENCE에 저장한 뒤 BER로 Encoding하는 함수
* \param stringSequence
* Encoding 결과를 저장할 STRING SEQUENCE 구조체의 포인터
* \param type
* Encoding할 String Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \param lengthForm
* Encoding할 Length Form
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_TO_BER_STRING_SEQUENCE^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS addToBERStringSequence(STRING_SEQUENCE *stringSequence, int type, void *value, int valueLen, int lengthForm);

/*!
* \brief
* Encoding된 데이터를 Boolean 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 BOOLEAN 변수의 포인터
*/
ISC_API BOOLEAN *decodeToBERBoolean(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Integer 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 INTEGER 구조체의 포인터
*/
ISC_API INTEGER *decodeToBERInteger(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Bit String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 BIT_STRING 구조체의 포인터
*/
ISC_API BIT_STRING *decodeToBERBitString(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Octet String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 OCTET_STRING 구조체의 포인터
*/
ISC_API OCTET_STRING *decodeToBEROctetString(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Null 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 NULL_VALUE 변수의 포인터
*/
ISC_API NULL_VALUE *decodeToBERNull(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Object Identifier 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 OBJECT_IDENTIFIER 구조체의 포인터
*/
ISC_API OBJECT_IDENTIFIER *decodeToBERObjectIdentifier(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Enumerated 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 ENUMERATED 구조체의 포인터
*/
ISC_API ENUMERATED *decodeToBEREnumerated(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Utf8 String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 UTF8_STRING 구조체의 포인터
*/
ISC_API UTF8_STRING *decodeToBERUTF8String(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Sequence 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 SEQUENCE 구조체의 포인터
*/
ISC_API SEQUENCE *decodeToBERSequence(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Printable String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 PRINTABLE_STRING 구조체의 포인터
*/
ISC_API PRINTABLE_STRING *decodeToBERPrintableString(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 T61 String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 T61_STRING 구조체의 포인터
*/
ISC_API T61_STRING *decodeToBERT61String(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 IA5 String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 IA5_STRING 구조체의 포인터
*/
ISC_API IA5_STRING *decodeToBERIA5String(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Utc Time 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 UTC_TIME 구조체의 포인터
*/
ISC_API UTC_TIME *decodeToBERUTCTime(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Utc Time 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 GENERALIZED_TIME 구조체의 포인터
*/
ISC_API GENERALIZED_TIME *decodeToBERGENERALIZEDTime(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Bmp String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 BMP_STRING 구조체의 포인터
*/
ISC_API BMP_STRING *decodeToBERBMPString(uint8 *value);
/*!
* \brief
* Encoding된 데이터를 ASN1 String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 ASN1_STRING 구조체의 포인터
*/
ISC_API ASN1_STRING *decodeToBERASN1String(uint8 *value);

/*!
* \brief
* ASN1_UNIT 구조체에서 index번째 자식을 Decoding하는 함수
* \param asn1Unit
* ASN1_UNIT 구조체의 포인터
* \param index
* Decoding할 자식의 인덱스
* \param childType
* Decoding할 자식의 타입
* \returns
* Decoding된 자식의 void형 포인터
*/
ISC_API void *getBERChildAt(ASN1_UNIT *asn1Unit, int index, int childType);
ISC_API void *getBERChildOffset(ASN1_UNIT *asn1Unit, int index, int childType, int* beforeOffset/*[in,out]*/);

/*!
* \brief
* ASN1_UNIT 구조체를 출력해 주는 함수
* \param asn1Unit
* ASN1_UNIT 구조체의 포인터
*/
ISC_API void printBERData(ASN1_UNIT *asn1Unit);


/************************************************
*												*
*		DER(Distinguished Encoding Rules)		*
*												*
************************************************/
/*!
* \brief
* 데이터가 DER 형태에 맞는지 체크하는 함수
* \param type
* Encoding할 타입
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이를 가리키는 포인터
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CHECK_DER^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS checkDER(int type, void *value, int *valueLen);

/*!
* \brief
* 데이터를 DER로 Encoding하는 함수
* \param asn1Unit
* Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCODE_TO_DER^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS encodeToDER(ASN1_UNIT *asn1Unit, int type, void *value, int valueLen);

/*!
* \brief
* 데이터를 Context-Specific 형태의 DER로 Encoding하는 함수
* \param asn1Unit
* Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
* \param cs_id
* Context-Specific ID
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCODE_TO_DER_CS^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS encodeToDER_CS(ASN1_UNIT *asn1Unit, int cs_id, int type, void *value, int valueLen);
/*!
 * \brief
 * 데이터를 Context-Specific 형태의 DER로 Encoding하는 함수
 * \param asn1Unit
 * Encoding 결과를 저장할 ASN1_UNIT 구조체의 포인터
 * \param cs_id
 * Context-Specific ID
 * \param type
 * Encoding할 Type
 * \param value
 * 데이터의 void형 포인터
 * \param valueLen
 * 데이터의 길이(Byte)
 * \returns
 * -# ISC_SUCCESS : 성공
 * -# LOCATION^F_ENCODE_TO_DER_CS^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
 */
ISC_API ISC_STATUS encodeToDER_CS_Scraping(ASN1_UNIT *asn1Unit, int cs_id, int type, void *value, int valueLen);
/*!
* \brief
* 데이터를 SEQUENCE에 저장한 뒤 DER로 Encoding하는 함수
* \param sequence
* Encoding 결과를 저장할 SEQUENCE 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_TO_DER_SEQUENCE^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS addToDERSequence(SEQUENCE *sequence, int type, void *value, int valueLen);

/*!
* \brief
* 데이터를 SEQUENCE OF에 저장한 뒤 DER로 Encoding하는 함수
* \param sequenceOf
* Encoding 결과를 저장할 SEQUENCE OF 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_TO_DER_SEQUENCE_OF^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS addToDERSequenceOf(SEQUENCE_OF *sequenceOf, int type, void *value, int valueLen);

/*!
* \brief
* 데이터를 SET에 저장한 뒤 DER로 Encoding하는 함수
* \param set
* Encoding 결과를 저장할 SET 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_TO_DER_SET^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS addToDERSet(SET *set, int type, void *value, int valueLen);

/*!
* \brief
* 데이터를 SET OF에 저장한 뒤 DER로 Encoding하는 함수
* \param setOf
* Encoding 결과를 저장할 SET OF 구조체의 포인터
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_TO_DER_SET_OF^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS addToDERSetOf(SET_OF *setOf, int type, void *value, int valueLen);

/*!
* \brief
* 데이터를 Context-Specific 형태의 SEQUENCE로 저장한 뒤 DER로 Encoding하는 함수
* \param sequence
* Encoding 결과를 저장할 SEQUENCE 구조체의 포인터
* \param cs_id
* Context-Specific ID
* \param type
* Encoding할 Type
* \param value
* 데이터의 void형 포인터
* \param valueLen
* 데이터의 길이(Byte)
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_TO_DER_SEQUENCE_CS^ERR_INVALID_ENCODE_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS addToDERSequence_CS(SEQUENCE *sequence, int cs_id, int type, void *value, int valueLen);

/*!
* \brief
* Encoding된 데이터를 Boolean 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 BOOLEAN 변수의 포인터
*/
ISC_API BOOLEAN *decodeToDERBoolean(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Integer 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 INTEGER 구조체의 포인터
*/
ISC_API INTEGER *decodeToDERInteger(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Bit String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 BIT_STRING 구조체의 포인터
*/
ISC_API BIT_STRING *decodeToDERBitString(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Octet String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 OCTET_STRING 구조체의 포인터
*/
ISC_API OCTET_STRING *decodeToDEROctetString(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Null 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 NULL_VALUE 변수의 포인터
*/
ISC_API NULL_VALUE *decodeToDERNull(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Object Identifier 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 OBJECT_IDENTIFIER 구조체의 포인터
*/
ISC_API OBJECT_IDENTIFIER *decodeToDERObjectIdentifier(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Enumerated 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 ENUMERATED 구조체의 포인터
*/
ISC_API ENUMERATED *decodeToDEREnumerated(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Utf8 String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 UTF8_STRING 구조체의 포인터
*/
ISC_API UTF8_STRING *decodeToDERUTF8String(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Sequence 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 SEQUENCE 구조체의 포인터
*/
ISC_API SEQUENCE *decodeToDERSequence(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Printable String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 PRINTABLE_STRING 구조체의 포인터
*/
ISC_API PRINTABLE_STRING *decodeToDERPrintableString(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 T61 String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 T61_STRING 구조체의 포인터
*/
ISC_API T61_STRING *decodeToDERT61String(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 IA5 String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 IA5_STRING 구조체의 포인터
*/
ISC_API IA5_STRING *decodeToDERIA5String(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Utc Time 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 UTC_TIME 구조체의 포인터
*/
ISC_API UTC_TIME *decodeToDERUTCTime(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 GENERALIZED Time 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 GENERALIZED_TIME 구조체의 포인터
*/
ISC_API GENERALIZED_TIME *decodeToDERGENERALIZEDTime(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 Bmp String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 BMP_STRING 구조체의 포인터
*/
ISC_API BMP_STRING *decodeToDERBMPString(uint8 *value);

/*!
* \brief
* Encoding된 데이터를 ASN1 String 값으로 Decoding하는 함수
* \param value
* Encoding된 바이너리 데이터의 포인터
* \returns
* Decoding된 ASN1_STRING 구조체의 포인터
*/
ISC_API ASN1_STRING *decodeToDERASN1String(uint8 *value);

/*!
* \brief
* ASN1_UNIT 구조체에서 beforeOffset 기준으로 index번째 자식을 Decoding하는 함수
* \param asn1Unit
* ASN1_UNIT 구조체의 포인터
* \param index
* Decoding할 자식의 인덱스
* \param childType
* Decoding할 자식의 타입
* \param beforeOffset
* Decoding할 offset주소
* \returns
* Decoding된 자식의 void형 포인터
*/
ISC_API void *getBERChildOffset(ASN1_UNIT *asn1Unit, int index, int childType, int *beforeOffset/*[in,out]*/);

/*!
* \brief
* ASN1_UNIT 구조체에서 index번째 자식을 Decoding하는 함수
* \param asn1Unit
* ASN1_UNIT 구조체의 포인터
* \param index
* Decoding할 자식의 인덱스
* \param childType
* Decoding할 자식의 타입
* \returns
* Decoding된 자식의 void형 포인터
*/
ISC_API void *getDERChildAt(ASN1_UNIT *asn1Unit, int index, int childType);

/*!
* \brief
* ASN1_UNIT 구조체를 출력해 주는 함수
* \param asn1Unit
* ASN1_UNIT 구조체의 포인터
*/
ISC_API void printDERData(ASN1_UNIT *asn1Unit);

/*!
* \brief
* HEX 문자열을 ASCII(바이너리) 배열로 바꿔주는 함수
* \param hex
* HEX 문자열의 포인터
* \param hexLen
* HEX 문자열의 길이
* \param out
* 출력될 ASCII 배열의 포인터
* \returns
* 출력된 ASCII 배열의 길이
*/
ISC_API int hexToASCII(uint8 *hex, int hexLen, uint8 *out);


/************************************************
*												*
*				I/O(Input/Output)				*
*												*
************************************************/

/*!
* \brief
* ASN1_UNIT 구조체를 바이너리 데이터로 변환하는 함수
* \param asn1Unit
* ASN1_UNIT 구조체의 포인터
* \param data
* 바이너리를 저장할 버퍼의 이중 포인터
* \returns
* -# 변환된 바이너리의 길이(Byte) : 성공
* -# -1 : 실패
*/
ISC_API int ASN1_to_binary(ASN1_UNIT *asn1Unit, uint8 **data);

/*!
* \brief
* ASN1_STRING 구조체를 바이너리 데이터로 변환하는 함수
* \param asn1Str
* ASN1_STRING 구조체의 포인터
* \param data
* 바이너리를 저장할 버퍼의 이중 포인터
* \returns
* -# 변환된 바이너리의 길이(Byte) : Success
* -# -1 : Fail
*/
ISC_API int ASN1_STRING_to_binary(ASN1_STRING *asn1Str, uint8 **data);

/*!
* \brief
* ASN1_UNIT 구조체를 File로 변환하는 함수
* \param asn1Unit
* ASN1_UNIT 구조체의 포인터
* \param fileName
* File 이름 문자열의 포인터, Ex)"D:\\test.der"
* \returns
* -# 파일에 쓰여진 길이 : 성공
* -# -1 : 실패
*/
ISC_API int ASN1_to_FILE(ASN1_UNIT *asn1Unit, const char *fileName);

/*!
* \brief
* 바이너리 데이터로부터 DER로 인코딩된 데이터를 읽는 함수
* \param st
* 데이터를 저장할 구조체의 void형 이중 포인터
* \param seq_to_st 
* SEQUENCE를 구조체로 변환하는 함수의 이름 Ex)Seq_to_X509_CERT 
* \param derBytes
* DER로 인코딩된 바이너리를 가리키는 포인터
* \returns
* -# ISC_SUCCESS : 성공
* -# L_DER^ISC_ERR_READ_FROM_BINARY : 기본 에러코드
* -# L_DER^ISC_ERR_INVALID_INPUT : 입력 파라미터 에러
* -# seq_to_st 함수로부터 발생된 오류 코드
*/
ISC_API ISC_STATUS readDER_from_Binary(void **st, PREAD_FUNC pReadFunc, uint8* derBytes);

/*!
* \brief
* 파일로부터 DER로 인코딩된 데이터를 읽는 함수
* \param st
* 데이터를 저장할 구조체의 void형 이중 포인터
* \param seq_to_st 
* SEQUENCE를 구조체로 변환하는 함수의 이름 Ex)Seq_to_X509_CERT 
* \param fileName
* File 이름 문자열의 포인터, Ex)"D:\\test.der"
* \returns
* -# ISC_SUCCESS : 성공
* -# L_DER^ISC_ERR_READ_FROM_FILE : 기본 에러코드
* -# L_DER^ISC_ERR_INVALID_INPUT : 입력 파라미터 오류
* -# readDER_from_Binary 함수로부터 발생된 오류 코드
*/
ISC_API ISC_STATUS readDER_from_File(void **st, PREAD_FUNC pReadFunc, const char* fileName);

/*!
* \brief
* 구조체를 DER로 인코딩한 뒤 바이너리로 쓰는 함수
* \param st
* 구조체의 void형 포인터
* \param st_to_seq 
* 구조체를 SEQUENCE로 변환하는 함수의 이름 Ex)X509_CERT_to_Seq
* \param derBytes
* 바이너리로 저장할 버퍼의 이중 포인터
* \returns
* -# 버퍼에 쓰여진 길이 : 성공
* -# -1 : 실패
*/
ISC_API int writeDER_to_Binary(void *st, PWRITE_FUNC pWreteFunc, uint8** derBytes);

/*!
* \brief
* 구조체를 DER로 인코딩한 뒤 파일로 쓰는 함수
* \param st
* 구조체의 void형 포인터
* \param st_to_seq 
* 구조체를 SEQUENCE로 변환하는 함수의 이름 Ex)X509_CERT_to_Seq
* \param fileName
* File 이름 문자열의 포인터, Ex)"D:\\test.der"
* \returns
* -# 버퍼에 쓰여진 길이 : 성공
* -# -1 : 실패
*/
ISC_API int writeDER_to_FILE(void *st, PWRITE_FUNC pWriteFunc, const char *fileName);

/*!
* \brief
* 바이너리 데이터로부터 PEM으로 인코딩된 데이터를 읽는 함수
* \param st
* 데이터를 저장할 구조체의 void형 이중 포인터
* \param seq_to_st 
* SEQUENCE를 구조체로 변환하는 함수의 이름 Ex)Seq_to_X509_CERT 
* \param pemBytes
* PEM으로 인코딩된 바이너리를 가리키는 포인터
* \param pemLength
* PEM으로 인코딩된 바이너리의 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# L_PEM^ISC_ERR_READ_FROM_BINARY : 기본 에러코드
* -# L_PEM^ISC_ERR_INVALID_INPUT : 입력 파라미터 오류
* -# seq_to_st 함수로부터 발생된 오류 코드
*/
ISC_API ISC_STATUS readPEM_from_Binary(void **st, PREAD_FUNC pReadFunc, uint8* pemBytes, int pemLength);

/*!
* \brief
* 파일로부터 PEM으로 인코딩된 데이터를 읽는 함수
* \param st
* 데이터를 저장할 구조체의 void형 이중 포인터
* \param seq_to_st 
* SEQUENCE를 구조체로 변환하는 함수의 이름 Ex)Seq_to_X509_CERT 
* \param fileName
* File 이름 문자열의 포인터, Ex)"D:\\test.pem"
* \returns
* -# ISC_SUCCESS : 성공
* -# L_PEM^ISC_ERR_READ_FROM_FILE : 기본 에러코드
* -# L_PEM^ISC_ERR_INVALID_INPUT : 입력 파라미터 오류
* -# readPEM_from_Binary 함수로부터 발생된 오류 코드
*/
ISC_API ISC_STATUS readPEM_from_File(void **st, PREAD_FUNC pReadFund, const char* fileName);

/*!
* \brief
* 구조체를 PEM으로 인코딩한 뒤 바이너리로 쓰는 함수
* \param st
* 구조체의 void형 포인터
* \param st_to_seq 
* 구조체를 SEQUENCE로 변환하는 함수의 이름 Ex)X509_CERT_to_Seq
* \param pemStr
* PEM String Ex)"X509 CERTIFICATE"
* \param pemStrLen
* PEM String 문자열의 길이
* \param pemBytes
* 바이너리로 저장할 버퍼의 이중 포인터
* \returns
* -# 버퍼에 쓰여진 길이 : 성공
* -# -1 : 실패
*/
ISC_API int writePEM_to_Binary(void *st, PWRITE_FUNC pWriteFunc, const char *pemStr, int pemStrLen, uint8** pemBytes);

/*!
* \brief
* 구조체를 PEM으로 인코딩한 뒤 파일로 쓰는 함수
* \param st
* 구조체의 void형 포인터
* \param st_to_seq 
* 구조체를 SEQUENCE로 변환하는 함수의 이름 Ex)X509_CERT_to_Seq
* \param pemStr
* PEM String Ex)"X509 CERTIFICATE"
* \param pemStrLen
* PEM String 문자열의 길이
* \param fileName
* File 이름 문자열의 포인터, Ex)"D:\\test.pem"
* \returns
* -# 버퍼에 쓰여진 길이 : 성공
* -# -1 : 실패
*/
ISC_API int writePEM_to_FILE(void *st, PWRITE_FUNC pWriteFunc, const char *pemStr, int pemStrLen, const char* fileName);

/*!
* \brief
* DER로 인코딩된 바이너리를 해쉬하는 함수
* \param st
* 구조체의 void형 포인터
* \param st_to_seq 
* 구조체를 SEQUENCE로 변환하는 함수의 이름 Ex)X509_CERT_to_Seq
* \param digest_id
* 해쉬 함수의 ID Ex) ISC_MD5, ISC_SHA1
* \param md
* 해쉬 함수의 결과를 저장할 버퍼의 포인터
* \returns
* -# 해쉬 결과의 길이('0'인 경우는 실패임)
*/
ISC_API int get_ASN1_hash(void *st, PWRITE_FUNC pWreteFunc ,int digest_id, uint8* md);

/*!
* \brief
* 문자열을 character 형태로 출력해주는 함수
* \param c
* 문자열의 포인터
* \param len 
* 문자열의 길이
*/
ISC_API void print_PCHAR(char* c, int len);

/*!
* \brief
* 문자열을 character 형태로 반환하는 함수
* \param c
* 문자열의 포인터
* \param len 
* 문자열의 길이
* \returns
* -# 문자열
*/
ISC_API char* dump_PCHAR(char* c, int len);

/*!
* \brief
* ASN1_STRING 구조체를 출력해주는 함수
* \param st
* ASN1_STRING 구조체의 포인터
*/
ISC_API void print_ASN1STRING(ASN1_STRING *st);

/*!
* \brief
* ASN1_STRING 구조체를 character 형태로 반환하는 함수
* \param st
* ASN1_STRING 구조체의 포인터
* \returns
* -# 문자열
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
* STRING_SEQUENCE 구조체를 생성하는 매크로 함수
* \returns
* 생성된 STRING_SEQUENCE 구조체의 포인터
*/
#define new_STRING_SEQUENCE() new_ASN1_UNIT()

/*!
* \brief
* STRING_SEQUENCE 구조체의 메모리 해지 매크로  함수
* \param stringSequence
* 메모리를 해지할 STRING_SEQUENCE 구조체의 포인터
*/
#define free_STRING_SEQUENCE(stringSequence) free_ASN1_UNIT((stringSequence))

/*!
* \brief
* STRING_SEQUENCE 구조체의 값을 초기화하는 매크로 함수
* \param stringSequence
* 값을 초기화 할 STRING_SEQUENCE 구조체의 포인터
*/
#define clean_STRING_SEQUENCE(stringSequence) clean_ASN1_UNIT((stringSequence))

/*!
* \brief
* INTEGER 타입의 Bytes 길이를 구하는 매크로 함수
* \param bInt
* INTEGER 구조체의 포인터
* \returns
* INTEGER 타입의 Bytes 길이
*/
#define get_INTEGER_TYPE_bytes_length(bInt)			((ISC_IS_BIGINT_ZERO(bInt)||(bInt->data == 0L))? 1 : (ISC_Get_BIGINT_Bits_Length(bInt)+8)/8)

/*!
* \brief
* SEQUENCE 구조체를 생성하는 매크로 함수
* \returns
* 생성된 SEQUENCE 구조체의 포인터
*/
#define new_SEQUENCE() new_ASN1_UNIT()
/*!
* \brief
* SEQUENCE 구조체의 메모리 해지 매크로  함수
* \param sequence
* 메모리를 해지할 SEQUENCE 구조체의 포인터
*/
#define free_SEQUENCE(sequence) free_ASN1_UNIT((sequence))
/*!
* \brief
* SEQUENCE 구조체의 값을 초기화하는 매크로 함수
* \param sequence
* 값을 초기화 할 SEQUENCE 구조체의 포인터
*/
#define clean_SEQUENCE(sequence) clean_ASN1_UNIT((sequence))

/*!
* \brief
* SEQUENCE_OF 구조체를 생성하는 매크로 함수
* \returns
* 생성된 SEQUENCE_OF 구조체의 포인터
*/
#define new_SEQUENCE_OF() new_ASN1_UNIT()
/*!
* \brief
* SEQUENCE_OF 구조체의 메모리 해지 매크로  함수
* \param sequenceOf
* 메모리를 해지할 SEQUENCE_OF 구조체의 포인터
*/
#define free_SEQUENCE_OF(sequenceOf) free_ASN1_UNIT((sequenceOf))
/*!
* \brief
* SEQUENCE_OF 구조체의 값을 초기화하는 매크로 함수
* \param sequenceOf
* 값을 초기화 할 SEQUENCE_OF 구조체의 포인터
*/
#define clean_SEQUENCE_OF(sequenceOf) clean_ASN1_UNIT((sequenceOf))

/*!
* \brief
* SET 구조체를 생성하는 매크로 함수
* \returns
* 생성된 SET 구조체의 포인터
*/
#define new_SET() new_ASN1_UNIT()
/*!
* \brief
* SET 구조체의 메모리 해지 매크로  함수
* \param set
* 메모리를 해지할 SET 구조체의 포인터
*/
#define free_SET(set) free_ASN1_UNIT((set))
/*!
* \brief
* SET 구조체의 값을 초기화하는 매크로 함수
* \param set
* 값을 초기화 할 SET 구조체의 포인터
*/
#define clean_SET(set) clean_ASN1_UNIT((set))

/*!
* \brief
* SET_OF 구조체를 생성하는 매크로 함수
* \returns
* 생성된 SET_OF 구조체의 포인터
*/
#define new_SET_OF() new_ASN1_UNIT()
/*!
* \brief
* SET_OF 구조체의 메모리 해지 매크로  함수
* \param setOf
* 메모리를 해지할 SET_OF 구조체의 포인터
*/
#define free_SET_OF(setOf) free_ASN1_UNIT((setOf))
/*!
* \brief
* SET_OF 구조체의 값을 초기화하는 매크로 함수
* \param setOf
* 값을 초기화 할 SET_OF 구조체의 포인터
*/
#define clean_SET_OF(setOf) clean_ASN1_UNIT((setOf))

/*!
* \brief
* 구조체 이름을 seq_to_st 함수이름으로 매핑시켜 주는 매크로
*/
#define READ_FUNC(st_name) Seq_to_##st_name

/*!
* \brief
* 구조체 이름을 st_to_seq 함수이름으로 매핑시켜 주는 매크로
*/
#define WRITE_FUNC(st_name) st_name##_to_Seq

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_ASN1_H */

