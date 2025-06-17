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
* GENERALIZED_TIME�� ������ ��� ����ü
* \remarks
* ASN1_STRING ����ü ������
*/
typedef ASN1_STRING GENERALIZED_TIME;


/*------------------------- �Լ� ���� -------------------------------------------*/

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
INI_API ASN1_TIME *generalizedTimeToASN1_TIME(GENERALIZED_TIME *generalizedTime);

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
INI_API int cmp_GENERALIZED_TIME(GENERALIZED_TIME *generalizedTime1, GENERALIZED_TIME *generalizedTime2);

/*!
* \brief
* GENERALIZED_TIME ����ü�� �ð��� ���ϴ� �Լ�
* \param generalizedTime
* GENERALIZED_TIME ����ü�� ���� ������
* \param seconds
* ���� �ð��� �� �ð�(���� : ��(seconds))
* \returns
* -# INI_SUCCESS : ����
* -# LOCATION^F_ADD_GENERALIZED_TIME^ERR_NULL_INPUT : �Է°��� NULL�� ���
* -# LOCATION^F_ADD_GENERALIZED_TIME^ERR_INVALID_OUTPUT : �߸��� ������� ���
*/
INI_API ini_status add_GENERALIZED_TIME(GENERALIZED_TIME **generalizedTime, long seconds);


#ifdef  __cplusplus
}
#endif 

#endif /* __GENERALIZED_TIME_H__ */
