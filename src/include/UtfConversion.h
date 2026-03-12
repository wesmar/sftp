#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef unsigned long   UCS4;
typedef unsigned short  UCS2;
typedef unsigned short  UTF16;
typedef unsigned char   UTF8;


#define CVT_OK                0   /* conversion successful */
#define CVT_sourceExhausted (-1)  /* partial character in source, but hit end */
#define CVT_targetExhausted (-2)  /* insuff. room in target for conversion */


int ConvertUCS4toUTF16 (UCS4** sourceStart, const UCS4* sourceEnd, UTF16** targetStart, const UTF16* targetEnd);

int ConvertUTF16toUCS4 (UTF16** sourceStart, UTF16* sourceEnd, UCS4** targetStart, const UCS4* targetEnd);

int ConvertUTF16toUTF8 (UTF16** sourceStart, const UTF16* sourceEnd, UTF8** targetStart, const UTF8* targetEnd);

int ConvertUTF8toUTF16 (UTF8** sourceStart, UTF8* sourceEnd, UTF16** targetStart, const UTF16* targetEnd);

int ConvertUCS4toUTF8 (UCS4** sourceStart, const UCS4* sourceEnd, UTF8** targetStart, const UTF8* targetEnd);

int ConvertUTF8toUCS4 (UTF8** sourceStart, UTF8* sourceEnd, UCS4** targetStart, const UCS4* targetEnd);

#ifdef __cplusplus
}
#endif
