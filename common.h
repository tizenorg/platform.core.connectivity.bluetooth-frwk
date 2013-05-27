#ifndef __COMMON_H
#define __COMMON_H

#include <stdio.h>
#if 0
#define THIS_LOG(level, fmt, arg...) \
		printf(level, TAG_CALL, "%s()" fmt "\n",__func__, ##arg)

#define DBG(fmt, arg...) THIS_LOG(LOG_DEBUG," :%d " fmt "\n", __LINE__, ## arg)
#define WARN(fmt, arg...) THIS_LOG(LOG_WARN," :%d " fmt "\n", __LINE__, ## arg)
#define ERROR(fmt, arg...) THIS_LOG(LOG_ERROR," :%d " fmt "\n", __LINE__, ## arg)

#endif 

#define DBG(fmt, arg...) printf("%s:%d %s()" fmt "\n", __FILE__, __LINE__, __func__, ## arg)
#define WARN(fmt, arg...) printf("warning %s:%d %s()" fmt "\n", __FILE__, __LINE__, __func__, ## arg)
#define ERROR(fmt, arg...) printf("error %s:%d %s()" fmt "\n", __FILE__, __LINE__, __func__, ## arg)

#endif
