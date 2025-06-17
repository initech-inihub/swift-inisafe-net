/*!
* \file platform_posix.h
* \brief posix platform 특성 정의
* \remarks
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PLATFORM_POSIX_H
#define HEADER_PLATFORM_POSIX_H



/* PA-RISC based HP-UX platforms have some issues...*/

#if defined(hpux) || defined(_hpux)
	#if defined(__hppa) || defined(__hppa__)
		#define ISC_NO_SYS_SELECT_H 1
		#if defined(__HP_aCC)
			#define ISC_NO_TEMPLATE_ICOMPARE 1
		#endif
	#endif
#endif


#endif /* HEADER_PLATFORM_POSIX_H */

