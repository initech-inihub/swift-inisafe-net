/*!
* \file platform_win.h
* \brief win32 platform 특성 정의
* \remarks
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PLATFORM_WIN32_H
#define HEADER_PLATFORM_WIN32_H


#if defined(_MSC_VER) && !defined(_MT)
	#error Must compile with /MD, /MDd, /MT or /MTd
#endif


#if defined(NDEBUG) && defined(_DEBUG)
	#error Inconsistent build settings (check for /MD[d])
#endif

#if defined(UNICODE) && !defined(ISC_WIN32_UTF8)
	#define ISC_WIN32_UTF8
#endif


#if defined(_MSC_VER) /* [fix][chk] 컴파일시 경고 나타나도록 수정*/
	/*#pragma warning(disable:4013)*/
	/*#pragma warning(disable:4018) */ /* signed/unsigned comparison*/   
	/*#pragma warning(disable:4251)*/ /* ... needs to have dll-interface warning */
	/*#pragma warning(disable:4355)*/ /* 'this' : used in base member initializer list*/
	/*#pragma warning(disable:4996)*/ /* VC++ 8.0 deprecation warnings*/
	/*#pragma warning(disable:4351)*/ /* new behavior: elements of array '...' will be default initialized*/
	/*#pragma warning(disable:4675)*/ /* resolved overload was found by argument-dependent lookup*/
	/*#pragma warning(disable:4142)*/
#endif


#endif /* HEADER_PLATFORM_WIN32_H */
