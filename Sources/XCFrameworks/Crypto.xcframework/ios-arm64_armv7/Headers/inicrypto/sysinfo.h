/*!
* \file sysinfo.h
* \brief 시스템 정보(CPU, MEMORY, HDD)를 가져오기위한 Function 정의
* \remarks
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_SYS_INFO_H
#define HEADER_SYS_INFO_H

#include "foundation.h"

#if defined (ISC_OS_FAMILY_WINDOWS)

#include <stdio.h>
#include <stdlib.h>

#include <windows.h>
#include <psapi.h>
#include <iphlpapi.h>
#ifdef _DEBUG
#include <tchar.h>
#endif

#elif defined(ISC_OS_FAMILY_UNIX)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>      
#include <sys/types.h>
#include <sys/stat.h>

#if defined(ISC_OS_MEMBER_HPUX)
# include <poll.h>
# include <sys/mib.h> 
# include <sys/param.h>
# include <sys/pstat.h>
# include <sys/socket.h>
# include <time.h>
# include <sys/types.h> 
# include <sys/unistd.h>
# include <sys/wait.h>

# if defined(__ia64)
# include <machine/sys/inline.h>
# else
# include <machine/inline.h>
# endif

#elif defined(ISC_OS_MEMBER_SOLARIS)

# include <stdarg.h>
# include <stropts.h>
# include <nlist.h>
# include <syslog.h>
# include <kstat.h>
# include <sys/wait.h>
# include <rpc/rpc.h>
# include <inet/mib2.h>
# include <sys/prsystm.h>
# include <procfs.h>

/*------------------------*/
#elif defined(ISC_OS_MEMBER_AIX)

# include <time.h>
# include <sys/sysinfo.h> 
# include <sys/time.h>
# include <sys/wait.h>
# include <libperfstat.h>

/*------------------------*/
#elif defined(ISC_OS_MEMBER_LINUX) || defined(ISC_OS_MEMBER_ANDROID)

# include <time.h>
# include <poll.h>
# include <fnmatch.h>

# include <sys/sysinfo.h>

#ifndef ANDROID
# include <sys/statvfs.h>
#else
# include <sys/vfs.h>
#endif

# include <sys/time.h>
# include <sys/wait.h>

struct cpuInfo {
	char vendor_id[50];
	int family;
	char model[50];
	float freq;
	char cache[20];
};

struct nstat_ent
{
	struct nstat_ent *next;
	char		 *id;
	unsigned long long val;
	unsigned long	   ival;
};

/*------------------------*/
#elif defined(ISC_OS_MEMBER_MAC)
#include <stdint.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/statvfs.h>
#include <mach/mach.h>
#include <mach/mach_time.h>   
#include <time.h>   

#include <sys/resource.h> 

#ifdef _SHARED_LIBRARY
/* for disk info */
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>

/* for network info */
#include <sys/socket.h>
#include <net/if.h>

#ifndef ISC_OS_IOS
#include <net/route.h>
#endif /* #ifndef ISC_OS_IOS */

#endif /* _SHARED_LIBRARY */

#endif
#endif

#include "prng.h"
#include "utils.h"
#include "drbg.h"

#ifdef __cplusplus

extern "C" {
#endif

#define ISC_MAX_FORK_CNT		1
#define ISC_MAX_SLEEP_CNT		1

#ifdef _INI_PACCEL
#define PACCEL_CPU_COUNT 2
#define PACCEL_RAND_LENGTH 64
#endif

/************************************************************************/
/* System info                                                          */
/************************************************************************/

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

ISC_INTERNAL void isc_Get_Current_Process_Info();
ISC_INTERNAL void isc_Get_Current_Time_Info();
ISC_INTERNAL void isc_Get_Process_Stat_Info();
ISC_INTERNAL void isc_Get_Process_Status_Info();
ISC_INTERNAL void isc_Get_Process_Task_Info();
ISC_INTERNAL void isc_Get_System_Info();
ISC_INTERNAL void isc_Get_System_Stat_Info();
ISC_INTERNAL void isc_Get_CPU_Info();
ISC_INTERNAL void isc_Get_Disk_Info();
ISC_INTERNAL void isc_Get_Battery_Info();
ISC_INTERNAL void isc_Get_Sleep_Time_Info();
ISC_INTERNAL void isc_Get_System_RNG_Info();
ISC_INTERNAL void isc_Get_CPU_Speed_Info();
ISC_INTERNAL void isc_Get_Network_Traffic_Info();

#if defined(WIN32) || defined(WINCE)
void isc_Get_Current_Thread_Info();
void isc_Get_Current_WinDow_Info();
void isc_Get_GUID();
void isc_Get_Queue_Status_Info();
void isc_Get_Address_Of_Malloc_Returned();
void isc_Get_Current_Resource_Info();
void isc_Get_Tick_Count_After_Boot();
#endif

#if defined(WIN32)
void isc_Get_PNP_Data_Info();
void isc_Get_System_MBM_Info();
void isc_Get_Net_Statistic_Info();
#endif

#ifndef WIN32
ISC_INTERNAL void isc_Get_Shared_Memory_Info();
ISC_INTERNAL void isc_Get_System_Memory_Info();
ISC_INTERNAL void isc_Get_Fork_Response_Info();
#endif

#endif /* ISC_WIN_LOADLIBRARY_CRYPTO */

/************************************************************************/
/* Entropy System info                                                          */
/************************************************************************/

#ifndef ISC_DEBUG_PRINT_ENTROPY

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO
ISC_INTERNAL void isc_Entropy_Get_Current_Process_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_Current_Time_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_CPU_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_Disk_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_Battery_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_Sleep_Time_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_System_RNG_Info(ISC_ENTROPY_UNIT* unit, int len);
ISC_INTERNAL void isc_Entropy_Get_CPU_Speed_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_Network_Traffic_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_Process_Stat_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_Process_Status_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_Process_Task_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_System_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_System_Stat_Info(ISC_ENTROPY_UNIT* unit);

#if defined(WIN32) || defined(WINCE)
void isc_Entropy_Get_Current_Thread_Info(ISC_ENTROPY_UNIT* unit);
void isc_Entropy_Get_Current_Thread_Id_Info(ISC_ENTROPY_UNIT* unit);
void isc_Entropy_Get_Clipboard_Viewer(ISC_ENTROPY_UNIT *unit);
void isc_Entropy_Get_Desktop_Window(ISC_ENTROPY_UNIT *unit);
void isc_Entropy_Get_Process_Heap(ISC_ENTROPY_UNIT *unit);
void isc_Entropy_Get_Foreground_Window(ISC_ENTROPY_UNIT *unit);
void isc_Entropy_Get_Cursor_Pos(ISC_ENTROPY_UNIT *unit);
void isc_Entropy_Get_GUID(ISC_ENTROPY_UNIT* unit);
void isc_Entropy_Get_Queue_Status_Info(ISC_ENTROPY_UNIT* unit);
void isc_Entropy_Get_Address_Of_Malloc_Returned(ISC_ENTROPY_UNIT* unit);
void isc_Entropy_Get_Current_Resource_Info(ISC_ENTROPY_UNIT* unit);
void isc_Entropy_Get_Tick_Count_After_Boot(ISC_ENTROPY_UNIT* unit);
void isc_Entropy_Get_Current_Process_Id_Info(ISC_ENTROPY_UNIT *unit);
void isc_Entropy_Get_System_CNG_Info(ISC_ENTROPY_UNIT* unit, int len);
#endif

#ifdef WIN32
void isc_Entropy_Get_PNP_Data_Info(ISC_ENTROPY_UNIT* unit);
void isc_Entropy_Get_System_MBM_Info(ISC_ENTROPY_UNIT* unit);
void isc_Entropy_Get_Net_Statistic_Info(ISC_ENTROPY_UNIT* unit);
#endif

#ifndef WIN32
ISC_INTERNAL void isc_Entropy_Get_Shared_Memory_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_Shared_Memory_Info2(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_System_Memory_Info(ISC_ENTROPY_UNIT* unit);
ISC_INTERNAL void isc_Entropy_Get_Fork_Response_Info(ISC_ENTROPY_UNIT* unit);
#if defined(ISC_OS_MEMBER_ANDROID) || defined(ISC_OS_MEMBER_LINUX)
ISC_INTERNAL void isc_Entropy_Get_Dev_Random(ISC_ENTROPY_UNIT *unit);
#endif
#endif
#endif /* ISC_WIN_LOADLIBRARY_CRYPTO */

#else /* #ifndef ISC_DEBUG_PRINT_ENTROPY */

ISC_API void isc_Entropy_Get_Current_Process_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Current_Time_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_CPU_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Disk_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Battery_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Sleep_Time_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_System_RNG_Info(ISC_ENTROPY_UNIT* unit, int len);
ISC_API void isc_Entropy_Get_CPU_Speed_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Network_Traffic_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Process_Stat_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Process_Status_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Process_Task_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_System_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_System_Stat_Info(ISC_ENTROPY_UNIT* unit);

#if defined(WIN32) || defined(WINCE)
ISC_API void isc_Entropy_Get_Current_Thread_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Current_Thread_Id_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Clipboard_Viewer(ISC_ENTROPY_UNIT *unit);
ISC_API void isc_Entropy_Get_Desktop_Window(ISC_ENTROPY_UNIT *unit);
ISC_API void isc_Entropy_Get_Process_Heap(ISC_ENTROPY_UNIT *unit);
ISC_API void isc_Entropy_Get_Foreground_Window(ISC_ENTROPY_UNIT *unit);
ISC_API void isc_Entropy_Get_Cursor_Pos(ISC_ENTROPY_UNIT *unit);
ISC_API void isc_Entropy_Get_GUID(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Queue_Status_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Address_Of_Malloc_Returned(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Current_Resource_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Tick_Count_After_Boot(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Current_Process_Id_Info(ISC_ENTROPY_UNIT *unit);
ISC_API void isc_Entropy_Get_System_CNG_Info(ISC_ENTROPY_UNIT* unit, int len);
#endif

#ifdef WIN32
ISC_API void isc_Entropy_Get_PNP_Data_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_System_MBM_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Net_Statistic_Info(ISC_ENTROPY_UNIT* unit);
#endif

#ifndef WIN32
ISC_API void isc_Entropy_Get_Shared_Memory_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Shared_Memory_Info2(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_System_Memory_Info(ISC_ENTROPY_UNIT* unit);
ISC_API void isc_Entropy_Get_Fork_Response_Info(ISC_ENTROPY_UNIT* unit);

#if defined(ISC_OS_MEMBER_ANDROID) || defined(ISC_OS_MEMBER_LINUX)
ISC_API void isc_Entropy_Get_Dev_Random(ISC_ENTROPY_UNIT *unit);
#endif
#endif

#endif /* #ifndef ISC_DEBUG_PRINT_ENTROPY */


#ifdef __cplusplus
}
#endif

#endif /* HEADER_SYS_INFO_H */
