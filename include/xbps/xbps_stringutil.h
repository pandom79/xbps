#ifndef XBPS_STRINGUTIL_H
#define XBPS_STRINGUTIL_H

#include "string.h"
#include "ctype.h"

char * ltrim(char *, const char *);
char * rtrim(char *, const char *);
char * trim(char *, const char *);
void toupperstr(char *);

#endif // XBPS_STRINGUTIL_H
