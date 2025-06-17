/*!
* \file platform_vms.h
* \brief vms platform 특성 정의
* \remarks
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PLATFORM_VMS_H
#define HEADER_PLATFORM_VMS_H


#if __INITIAL_POINTER_SIZE != 64
	#define ISC_DESCRIPTOR_STRING(name, string) \
		struct dsc$descriptor_s name =	\
		{								\
			string.size(),				\
			DSC$K_DTYPE_T,				\
			DSC$K_CLASS_S,				\
			(char*) string.data()		\
		}
	#define ISC_DESCRIPTOR_LITERAL(name, string) \
		struct dsc$descriptor_s name =	\
		{								\
			sizeof(string) - 1,			\
			DSC$K_DTYPE_T,				\
			DSC$K_CLASS_S,				\
			(char*) string				\
		}
#else
	#define ISC_DESCRIPTOR_STRING(name, string) \
		struct dsc64$descriptor_s name =\
		{								\
			1,							\
			DSC64$K_DTYPE_T,			\
			DSC64$K_CLASS_S,			\
			-1,							\
			string.size(),				\
			(char*) string.data()		\
		}
	#define ISC_DESCRIPTOR_LITERAL(name, string) \
		struct dsc64$descriptor_s name =\
		{								\
			1,							\
			DSC64$K_DTYPE_T,			\
			DSC64$K_CLASS_S,			\
			-1,							\
			sizeof(string) - 1,			\
			(char*) string				\
		}
#endif


/* No <sys/select.h> header file*/
#define ISC_NO_SYS_SELECT_H


#endif /* HEADER_PLATFORM_VMS_H */
