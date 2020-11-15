#ifndef XBPS_STRING_UTIL_H
#define XBPS_STRING_UTIL_H

#include "string.h"
#include "ctype.h"

char *ltrim(char *str, const char *seps);
char *rtrim(char *str, const char *seps);
char *trim(char *str, const char *seps);
void toupperstr( char *str );

#endif // XBPS_STRING_UTIL_H
