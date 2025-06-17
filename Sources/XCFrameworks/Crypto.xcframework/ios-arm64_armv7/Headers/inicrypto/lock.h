#ifndef HEADER_LOCK_H
#define HEADER_LOCK_H

#ifdef  __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined(WIN32) || defined(_WIN32_WCE)
#include <windows.h>
#else
#include <pthread.h>
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO
#if defined(WIN32) || defined(_WIN32) || defined(_WIN32_WCE) || defined(ISC_BADA)
    ISC_INTERNAL ISC_STATUS isc_Init_Lock(HANDLE *mutex);
    ISC_INTERNAL ISC_STATUS isc_Wait_Lock(HANDLE *mutex);
    ISC_INTERNAL ISC_STATUS isc_Release_Lock(HANDLE *mutex);
    ISC_INTERNAL ISC_STATUS isc_Clear_Lock(HANDLE *mutex);
#else
    ISC_INTERNAL ISC_STATUS isc_Init_Lock(pthread_mutex_t *mutex);
    ISC_INTERNAL ISC_STATUS isc_Wait_Lock(pthread_mutex_t *mutex);
    ISC_INTERNAL ISC_STATUS isc_Release_Lock(pthread_mutex_t *mutex);
    ISC_INTERNAL ISC_STATUS isc_Clear_Lock(pthread_mutex_t *mutex);
#endif /* defined(WIN32) || defined(_WIN32_WCE) */
#endif /* ISC_WIN_LOADLIBRARY_CRYPTO */

#ifdef  __cplusplus
}
#endif /* __cplusplus */

#endif /* HEADER_LOCK_H */

