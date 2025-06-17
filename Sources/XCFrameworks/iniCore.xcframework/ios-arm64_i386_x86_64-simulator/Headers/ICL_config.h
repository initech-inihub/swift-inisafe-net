#ifndef __CONFIG_H_
#define __CONFIG_H_

#ifdef _INI_BADA
#include "ICL_bada.h"
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef INISAFECORE_API
#if defined(WIN32) || defined(_WIN32_WCE)
	#ifdef INISAFECORE_EXPORTS
	#define INISAFECORE_API __declspec(dllexport)
	#else
	#define INISAFECORE_API __declspec(dllimport)
	#endif
#else
	#define INISAFECORE_API
#endif
#endif

typedef struct {
	int line;
	char name[128];
	char value[512];
} st_CONFIG;


#ifndef _WIN32_LOADLOBRARY_CORE_
/******************************************************************************
 * function��      : CFG_Load_File()
 * function���    : {configȭ�Ϸ� ���� ��� ���� �о� ����ü�� ��� ���´�.}
 * �Է�����        : {char *config_file- configȭ�Ϸ� �� ȭ���� �̸�}
 * �������        : {}
 * return ��       : {CONFIG *  - fail:NULL}
 * REMARKS ����    : {CFG_Get_String()ȣ������ �ݵ�� ����Ǿ� �ϴ� �۾��̴�.}
 ******************************************************************************/
INISAFECORE_API st_CONFIG *ICL_Load_File(char* config_file);


/******************************************************************************
 * function��      : {CFG_Free_Config}
 * function���    : {config file�� ������ ��Ҵ� ����ü�� �޸� free
 * �Է�����        : {}
 * �������        : {}
 * return ��       : {}
 * REMARKS ����    : {CFG_Load_File()���� ���������� �Ҵ��� �޸� ���� �ݳ��ϰ� �����Ѵ�. �ݵ�� ȣ��}
 ******************************************************************************/
INISAFECORE_API void ICL_Free_Config(st_CONFIG *G_config);


/******************************************************************************
 * function��      : {CFG_Get_Num}
 * function���    : {�־��� ���ǰ� Ű���� �ش��ϴ� ���� int�� ��´�.}
 * �Է�����        : {CONFIG *G_config - config������ ������ ����ִ� ����ü }
 *                   {char *session -������ �̸�, ���� ��� NULL�� �Է�}
 *                   {char *name -Ű�� �̸�  }
 * �������        : {}
 * return ��       : {0 : ���� Ȥ�� ��ġ��� ����, �׹� : �� ���� value�� int }
 * REMARKS ����    : {CFG_Load_File()�� ����Ǿ��Ѵ�.}
 ******************************************************************************/
INISAFECORE_API int ICL_Get_Num(st_CONFIG *G_config, char* session, char* name);

/******************************************************************************
 * function��      : {CFG_Get_String}
 * function���    : {�־��� ���ǰ� Ű���� �ش��ϴ� ���� char*�� ��´�.}
 * �Է�����        : {CONFIG *G_config - config������ ������ ����ִ� ����ü }
 *                   {char *session -������ �̸�, ���� ��� NULL�� �Է�}
 *                   {char *name -Ű�� �̸�  }
 * �������        : {}
 * return ��       : {NULL : ���� Ȥ�� ��ġ��� ����, �׹� : �� value�� pt }
 * REMARKS ����    : {CFG_Load_File()�� ����Ǿ��Ѵ�.}
 ******************************************************************************/
INISAFECORE_API char* ICL_Get_String(st_CONFIG *G_config, char* session, char* name);

/**
 * @brief	: Get Section Count
 * @param	:(st_CONFIG *) 			: Loaded st_CONFIG pointer
 * @return	:(int) section_count (if ( error or no section) then return -1 )
 */
INISAFECORE_API int ICL_Get_Section_Count(st_CONFIG *G_config);

/**
 * @brief	: Get IDXst Section Name
 * @param	:(st_CONFIG *) :[in] Loaded st_CONFIG pointer
 * @param	:(int) :[in] IDXst (1 ~ )
 * @param   :(char *) :[out] output section name , must allocated buffer , size is 128
 * @return	:(int) : last search postion
 */
INISAFECORE_API int ICL_Get_Section_by_IDX(st_CONFIG *G_config, int idx, char *section);

/**
 * @brief	: Get Next Section Name from startp
 * @param	:(st_CONFIG *) :[in] Loaded st_CONFIG pointer
 * @param   :(int) :[in] start search postion
 * @param   :(char *) :[out] output section name , must allocated buffer , size is 128
 * @return	:(int) : next search postion
 */
INISAFECORE_API int ICL_Get_Next_Section(st_CONFIG *G_config, int startp, char *section);

/**
 * @brief	: Get Section's Value Count
 * @param	:(st_CONFIG *) :[in] Loaded st_CONFIG pointer
 * @param	:(char *) :[in] Section Name
 * @return	:(int) value_count (if ( error or no section or no value) then return -1 )
 */
INISAFECORE_API int ICL_Get_Section_Value_Count(st_CONFIG *G_config, char *section);

/**
 * @brief	: Get  Section's IDXst Value(name, value)
 * @param	:(st_CONFIG *) :[in] Loaded st_CONFIG pointer
 * @param   :(char *)      :[in] section name
 * @param	:(int) :[in] IDXst (1 ~ )
 * @param   :(int) :[in] last search postion , if(lasti == 0) retry full search
 * @param   :(char *) :[out] output section's value name , must allocated buffer , size is 128
 * @param   :(char *) :[out] output section's value value , must allocated buffer, size is 512
 * @return	:(int) : last search postion , for avoid duplicated search
 */
INISAFECORE_API int ICL_Get_Section_Value_by_IDX(st_CONFIG *G_config, char *section, int idx, int lasti, char *name, char *value);

INISAFECORE_API int ICL_convert_env(char *org_path, char *new_path);
INISAFECORE_API int ICL_count_line(FILE* fp);
INISAFECORE_API int ICL_get_value_index(char* namevalue);
INISAFECORE_API int ICL_trim(char* input, char *output);
INISAFECORE_API int ICL_read_line(FILE* fp, char* pbuf);
#else
INI_RET_LOADLIB_CORE(st_CONFIG*, ICL_Load_File, (char* config_file), (config_file), NULL);
INI_VOID_LOADLIB_CORE(void, ICL_Free_Config, (st_CONFIG *G_config), (G_config) );
INI_RET_LOADLIB_CORE(int, ICL_Get_Num, (st_CONFIG *G_config, char* session, char* name), (G_config,session,name), -10000);
INI_RET_LOADLIB_CORE(char*, ICL_Get_String, (st_CONFIG *G_config, char* session, char* name), (G_config,session,name), NULL);
INI_RET_LOADLIB_CORE(int, ICL_Get_Section_Count, (st_CONFIG *G_config), (G_config), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Get_Section_by_IDX, (st_CONFIG *G_config, int idx, char *section), (G_config, idx, section), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Get_Next_Section, (st_CONFIG *G_config, int startp, char *section), (G_config, startp, section), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Get_Section_Value_Count, (st_CONFIG *G_config, char *section), (G_config, section), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Get_Section_Value_by_IDX, (st_CONFIG *G_config, char *section, int idx, int lasti, char *name, char *value), (G_config, section, idx, lasti, name, value), -10000);

INI_RET_LOADLIB_CORE(int, ICL_convert_env, (char *org_path, char *new_path), (org_path,new_path), -10000);
INI_RET_LOADLIB_CORE(int, ICL_count_line, (FILE* fp), (fp), -10000);
INI_RET_LOADLIB_CORE(int, ICL_get_value_index, (char* namevalue), (namevalue), -10000);
INI_RET_LOADLIB_CORE(int, ICL_trim, (char* input, char *output), (input,output), -10000);
INI_RET_LOADLIB_CORE(int, ICL_read_line, (FILE* fp, char* pbuf), (fp,pbuf), -10000);
#endif

#ifdef  __cplusplus
}
#endif

#endif
