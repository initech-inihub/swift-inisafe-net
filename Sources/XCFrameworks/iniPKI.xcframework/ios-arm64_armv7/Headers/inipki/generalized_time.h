/*!
* \file generalized_time.h
* \brief GENERALIZED_TIME(Universal Time, Coordinated)	
* \remarks
* RFC3280, Network Working Group
* \author
* Copyright (c) 2008 by \<INITECH\> / Developed by Seon Jong. Kim.
*/

#ifndef __GENERALIZED_TIME_H__
#define __GENERALIZED_TIME_H__

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <time.h>

#include <inicrypto/foundation.h>
#include <inicrypto/biginteger.h>

#include "asn1.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* GENERALIZED_TIME의 정보를 담는 구조체
* \remarks
* ASN1_STRING 구조체 재정의
*/
typedef ASN1_STRING GENERALIZED_TIME;


/*------------------------- 함수 시작 -------------------------------------------*/

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
INI_API ASN1_TIME *generalizedTimeToASN1_TIME(GENERALIZED_TIME *generalizedTime);

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
INI_API int cmp_GENERALIZED_TIME(GENERALIZED_TIME *generalizedTime1, GENERALIZED_TIME *generalizedTime2);

/*!
* \brief
* GENERALIZED_TIME 구조체에 시간을 더하는 함수
* \param generalizedTime
* GENERALIZED_TIME 구조체의 이중 포인터
* \param seconds
* 더할 시간의 총 시간(단위 : 초(seconds))
* \returns
* -# INI_SUCCESS : 성공
* -# LOCATION^F_ADD_GENERALIZED_TIME^ERR_NULL_INPUT : 입력값이 NULL일 경우
* -# LOCATION^F_ADD_GENERALIZED_TIME^ERR_INVALID_OUTPUT : 잘못된 결과값일 경우
*/
INI_API ini_status add_GENERALIZED_TIME(GENERALIZED_TIME **generalizedTime, long seconds);


#ifdef  __cplusplus
}
#endif 

#endif /* __GENERALIZED_TIME_H__ */
