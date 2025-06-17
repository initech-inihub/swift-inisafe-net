/*!
* \file stack.h
* \brief 스택 구현 헤더
* \remarks
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_STACK_H
#define HEADER_STACK_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <inicrypto/foundation.h>


#ifdef WIN32
#undef STACK
#endif

typedef struct stack_st
{
	int num;
	char **data;
	int sorted;
	int num_alloc;
	int (*comp)(const char * const *, const char * const *);
} STACK;

ISC_API STACK *new_STACK_compare_func(int (*cmp)(const char * const *, const char * const *));
ISC_API STACK *new_STACK(void);
ISC_API void free_STACK(STACK *st);
ISC_API void free_STACK_values(STACK *st, void (*func)(void *));
ISC_API int get_STACK_count(const STACK *st);
ISC_API char *get_STACK_value(const STACK *st, int i);
ISC_API int insert_STACK_value(STACK *st,char *data,int pos);
ISC_API char *remove_STACK_value(STACK *st,int pos);
ISC_API int find_STACK_value(STACK *st,char *data);
ISC_API int push_STACK_value(STACK *st,char *data);
ISC_API char *pop_STACK_value(STACK *st);
ISC_API char *set_STACK_value(STACK *st, char *data,int pos);
ISC_API STACK *dup_STACK(STACK *st);
ISC_API void sort_STACK(STACK *st);
ISC_API int is_STACK_sorted(const STACK *st);

#define STK(st) STACK

#define new_STK_comp(opt, cmp) \
	new_STACK_compare_func((int (*)(const char * const *, const char * const *))(cmp))
#define new_STK(opt) \
	new_STACK()
#define free_STK(opt, st) \
	free_STACK(st)
#define free_STK_values(opt, st,free_func) \
	free_STACK_values(st, (void (*)(void *))free_func)
#define get_STK_count(opt, st) \
	get_STACK_count(st)
#define get_STK_value(opt, st,i) \
	((opt *)get_STACK_value(st, i))
#define push_STK_value(opt, st,val) \
	push_STACK_value(st, (char *)val)
#define find_STK_value(opt, st,val) \
	find_STACK_value(st, (char *)val)
#define remove_STK_value(opt, st,i) \
	((opt *)remove_STACK_value(st, i))
#define insert_STK_value(opt, st,val,i) \
	insert_STACK_value(st, (char *)val, i)
#define set_STK_value(opt, st,val,i) \
	set_STACK_value(st, (char *)val, i)
#define dup_STK(opt, st) \
	dup_STACK(st)
#define pop_STK_value(opt, st) \
	((opt *)pop_STACK_value(st))
#define sort_STK(opt, st) \
	sort_STACK(st)
#define is_STK_sorted(opt, st) \
	is_STACK_sorted(st)

#ifdef  __cplusplus
}
#endif

#endif
