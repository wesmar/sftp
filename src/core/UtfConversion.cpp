#include "UtfConversion.h"

const UCS4 kReplacementCharacter = 0x0000FFFDUL;
const UCS4 kMaximumUCS2          = 0x0000FFFFUL;
const UCS4 kMaximumUTF16         = 0x0010FFFFUL;
const UCS4 kMaximumUCS4          = 0x7FFFFFFFUL;

const int halfShift              = 10;
const UCS4 halfBase              = 0x0010000UL;
const UCS4 halfMask              = 0x3FFUL;
const UCS4 kSurrogateHighStart   = 0xD800UL;
const UCS4 kSurrogateHighEnd     = 0xDBFFUL;
const UCS4 kSurrogateLowStart    = 0xDC00UL;
const UCS4 kSurrogateLowEnd      = 0xDFFFUL;

/* ================================================================ */

int ConvertUCS4toUTF16 (UCS4** sourceStart, const UCS4* sourceEnd, UTF16** targetStart, const UTF16* targetEnd)
{
    int result = CVT_OK;
    UCS4* source = *sourceStart;
    UTF16* target = *targetStart;
    while (source < sourceEnd) {
        UCS4 ch;
        if (target >= targetEnd) {
            result = CVT_targetExhausted;
            break;
        }
        ch = *source++;
        if (ch <= kMaximumUCS2) {
            *target++ = ch;
        } else if (ch > kMaximumUTF16) {
            *target++ = kReplacementCharacter;
        } else {
            if (target + 1 >= targetEnd) {
                result = CVT_targetExhausted;
                break;
            }
            ch -= halfBase;
            *target++ = (ch >> halfShift) + kSurrogateHighStart;
            *target++ = (ch & halfMask) + kSurrogateLowStart;
        }
    }
    *sourceStart = source;
    *targetStart = target;
    return result;
}


int ConvertUTF16toUCS4(UTF16** sourceStart, UTF16* sourceEnd, UCS4** targetStart, const UCS4* targetEnd)
{
    int result = CVT_OK;
    UTF16* source = *sourceStart;
    UCS4* target = *targetStart;
    while (source < sourceEnd) {
        UCS4 ch;
        ch = *source++;
        if (ch >= kSurrogateHighStart && ch <= kSurrogateHighEnd && source < sourceEnd) {
            UCS4 ch2 = *source;
            if (ch2 >= kSurrogateLowStart && ch2 <= kSurrogateLowEnd) {
                ch = ((ch - kSurrogateHighStart) << halfShift) + (ch2 - kSurrogateLowStart) + halfBase;
                ++source;
            }
        }
        if (target >= targetEnd) {
            result = CVT_targetExhausted;
            break;
        }
        *target++ = ch;
    }
    *sourceStart = source;
    *targetStart = target;
    return result;
}

/* ================================================================ */

const UCS4 offsetsFromUTF8[6] = {
    0x00000000UL,
    0x00003080UL,
    0x000E2080UL,
    0x03C82080UL,
    0xFA082080UL,
    0x82082080UL
};

const char bytesFromUTF8[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5};

const UTF8 firstByteMark[7] = {0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC};


/* ================================================================ */
int ConvertUTF16toUTF8 (UTF16** sourceStart, const UTF16* sourceEnd, UTF8** targetStart, const UTF8* targetEnd)
{
    int result = CVT_OK;
    UTF16* source = *sourceStart;
    UTF8* target = *targetStart;
    while (source < sourceEnd) {
        UCS4 ch;
        size_t bytesToWrite = 0;
        const UCS4 byteMask = 0xBF;
        const UCS4 byteMark = 0x80; 
        ch = *source++;
        if (ch >= kSurrogateHighStart && ch <= kSurrogateHighEnd && source < sourceEnd) {
            UCS4 ch2 = *source;
            if (ch2 >= kSurrogateLowStart && ch2 <= kSurrogateLowEnd) {
                ch = ((ch - kSurrogateHighStart) << halfShift) + (ch2 - kSurrogateLowStart) + halfBase;
                ++source;
            }
        }
        if (ch < 0x80)                { bytesToWrite = 1;
        } else if (ch < 0x800)        { bytesToWrite = 2;
        } else if (ch < 0x10000)      { bytesToWrite = 3;
        } else if (ch < 0x200000)     { bytesToWrite = 4;
        } else if (ch < 0x4000000)    { bytesToWrite = 5;
        } else if (ch <= kMaximumUCS4){ bytesToWrite = 6;
        } else {
            /* I wish there were a smart way to avoid this conditional */
            bytesToWrite = 2;
            ch = kReplacementCharacter;
        }

        target += bytesToWrite;
        if (target > targetEnd) {
            target -= bytesToWrite;
            result = CVT_targetExhausted;
            break;
        }
        switch (bytesToWrite) { /* NOTE: intentional fallthrough across cases. */
            case 6: *--target = (ch | byteMark) & byteMask; ch >>= 6;
            case 5: *--target = (ch | byteMark) & byteMask; ch >>= 6;
            case 4: *--target = (ch | byteMark) & byteMask; ch >>= 6;
            case 3: *--target = (ch | byteMark) & byteMask; ch >>= 6;
            case 2: *--target = (ch | byteMark) & byteMask; ch >>= 6;
            case 1: *--target =  ch | firstByteMark[bytesToWrite];
        }
        target += bytesToWrite;
    }
    *sourceStart = source;
    *targetStart = target;
    return result;
}

/* ================================================================ */

int ConvertUTF8toUTF16 (UTF8** sourceStart, UTF8* sourceEnd, UTF16** targetStart, const UTF16* targetEnd)
{
    int result = CVT_OK;
    UTF8* source = *sourceStart;
    UTF16* target = *targetStart;
    while (source < sourceEnd) {
        UCS4 ch = 0;
        size_t extraBytesToWrite = bytesFromUTF8[*source];
        if (source + extraBytesToWrite > sourceEnd) {
            result = CVT_sourceExhausted;
            break;
        }
        switch (extraBytesToWrite) { /* NOTE: intentional fallthrough across cases. */
            case 5: ch += *source++; ch <<= 6;
            case 4: ch += *source++; ch <<= 6;
            case 3: ch += *source++; ch <<= 6;
            case 2: ch += *source++; ch <<= 6;
            case 1: ch += *source++; ch <<= 6;
            case 0: ch += *source++;
        }
        ch -= offsetsFromUTF8[extraBytesToWrite];

        if (target >= targetEnd) {
            result = CVT_targetExhausted;
            break;
        }
        if (ch <= kMaximumUCS2) {
            *target++ = ch;
        } else if (ch > kMaximumUTF16) {
            *target++ = kReplacementCharacter;
        } else {
            if (target + 1 >= targetEnd) {
                result = CVT_targetExhausted;
                break;
            }
            ch -= halfBase;
            *target++ = (ch >> halfShift) + kSurrogateHighStart;
            *target++ = (ch & halfMask) + kSurrogateLowStart;
        }
    }
    *sourceStart = source;
    *targetStart = target;
    return result;
}


int ConvertUCS4toUTF8 (UCS4** sourceStart, const UCS4* sourceEnd, UTF8** targetStart, const UTF8* targetEnd)
{
    int result = CVT_OK;
    UCS4* source = *sourceStart;
    UTF8* target = *targetStart;
    while (source < sourceEnd) {
        UCS4 ch;
        size_t bytesToWrite = 0;
        const UCS4 byteMask = 0xBF;
        const UCS4 byteMark = 0x80; 
        ch = *source++;
        if (ch >= kSurrogateHighStart && ch <= kSurrogateHighEnd && source < sourceEnd) {
            UCS4 ch2 = *source;
            if (ch2 >= kSurrogateLowStart && ch2 <= kSurrogateLowEnd) {
                ch = ((ch - kSurrogateHighStart) << halfShift) + (ch2 - kSurrogateLowStart) + halfBase;
                ++source;
            }
        }
        if (ch < 0x80)                { bytesToWrite = 1;
        } else if (ch < 0x800)        { bytesToWrite = 2;
        } else if (ch < 0x10000)      { bytesToWrite = 3;
        } else if (ch < 0x200000)     { bytesToWrite = 4;
        } else if (ch < 0x4000000)    { bytesToWrite = 5;
        } else if (ch <= kMaximumUCS4){ bytesToWrite = 6;
        } else {
            /* I wish there were a smart way to avoid this conditional */
            bytesToWrite = 2;
            ch = kReplacementCharacter;
        }

        target += bytesToWrite;
        if (target > targetEnd) {
            target -= bytesToWrite; result = CVT_targetExhausted; break;
        }
        switch (bytesToWrite) { /* NOTE: intentional fallthrough across cases. */
            case 6: *--target = (ch | byteMark) & byteMask; ch >>= 6;
            case 5: *--target = (ch | byteMark) & byteMask; ch >>= 6;
            case 4: *--target = (ch | byteMark) & byteMask; ch >>= 6;
            case 3: *--target = (ch | byteMark) & byteMask; ch >>= 6;
            case 2: *--target = (ch | byteMark) & byteMask; ch >>= 6;
            case 1: *--target =  ch | firstByteMark[bytesToWrite];
        }
        target += bytesToWrite;
    }
    *sourceStart = source;
    *targetStart = target;
    return result;
}


int ConvertUTF8toUCS4 (UTF8** sourceStart, UTF8* sourceEnd, UCS4** targetStart, const UCS4* targetEnd)
{
    int result = CVT_OK;
    UTF8* source = *sourceStart;
    UCS4* target = *targetStart;
    while (source < sourceEnd) {
        UCS4 ch = 0;
        size_t extraBytesToWrite = bytesFromUTF8[*source];
        if (source + extraBytesToWrite > sourceEnd) {
            result = CVT_sourceExhausted;
            break;
        }
        switch (extraBytesToWrite) { /* NOTE: intentional fallthrough across cases. */
            case 5: ch += *source++; ch <<= 6;
            case 4: ch += *source++; ch <<= 6;
            case 3: ch += *source++; ch <<= 6;
            case 2: ch += *source++; ch <<= 6;
            case 1: ch += *source++; ch <<= 6;
            case 0: ch += *source++;
        }
        ch -= offsetsFromUTF8[extraBytesToWrite];

        if (target >= targetEnd) {
            result = CVT_targetExhausted;
            break;
        }
        if (ch <= kMaximumUCS2) {
            *target++ = ch;
        } else if (ch > kMaximumUCS4) {
            *target++ = kReplacementCharacter;
        } else {
            if (target + 1 >= targetEnd) {
                result = CVT_targetExhausted;
                break;
            }
            ch -= halfBase;
            *target++ = (ch >> halfShift) + kSurrogateHighStart;
            *target++ = (ch & halfMask) + kSurrogateLowStart;
        }
    }
    *sourceStart = source;
    *targetStart = target;
    return result;
}


