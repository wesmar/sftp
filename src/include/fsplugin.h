// contents of fsplugin.h  version 2.0 (30.Jan.2009)

#pragma once

#pragma pack(push, 1)

// ids for FsGetFile
#define FS_FILE_OK                  0
#define FS_FILE_EXISTS              1
#define FS_FILE_NOTFOUND            2
#define FS_FILE_READERROR           3
#define FS_FILE_WRITEERROR          4
#define FS_FILE_USERABORT           5
#define FS_FILE_NOTSUPPORTED        6
#define FS_FILE_EXISTSRESUMEALLOWED 7

#define FS_EXEC_OK           0
#define FS_EXEC_ERROR        1
#define FS_EXEC_YOURSELF    -1
#define FS_EXEC_SYMLINK     -2

#define FS_COPYFLAGS_OVERWRITE            0x01
#define FS_COPYFLAGS_RESUME               0x02
#define FS_COPYFLAGS_MOVE                 0x04
#define FS_COPYFLAGS_EXISTS_SAMECASE      0x08
#define FS_COPYFLAGS_EXISTS_DIFFERENTCASE 0x10

// flags for tRequestProc
#define RT_Other            0
#define RT_UserName         1
#define RT_Password         2
#define RT_Account          3
#define RT_UserNameFirewall 4
#define RT_PasswordFirewall 5
#define RT_TargetDir        6
#define RT_URL              7
#define RT_MsgOK            8
#define RT_MsgYesNo         9
#define RT_MsgOKCancel      10

// flags for tLogProc
#define MSGTYPE_CONNECT           1
#define MSGTYPE_DISCONNECT        2
#define MSGTYPE_DETAILS           3
#define MSGTYPE_TRANSFERCOMPLETE  4
#define MSGTYPE_CONNECTCOMPLETE   5
#define MSGTYPE_IMPORTANTERROR    6
#define MSGTYPE_OPERATIONCOMPLETE 7

// flags for FsStatusInfo
#define FS_STATUS_START           0
#define FS_STATUS_END             1

#define FS_STATUS_OP_LIST              1
#define FS_STATUS_OP_GET_SINGLE        2
#define FS_STATUS_OP_GET_MULTI         3
#define FS_STATUS_OP_PUT_SINGLE        4
#define FS_STATUS_OP_PUT_MULTI         5
#define FS_STATUS_OP_RENMOV_SINGLE     6
#define FS_STATUS_OP_RENMOV_MULTI      7
#define FS_STATUS_OP_DELETE            8
#define FS_STATUS_OP_ATTRIB            9
#define FS_STATUS_OP_MKDIR            10
#define FS_STATUS_OP_EXEC             11
#define FS_STATUS_OP_CALCSIZE         12
#define FS_STATUS_OP_SEARCH           13
#define FS_STATUS_OP_SEARCH_TEXT      14
#define FS_STATUS_OP_SYNC_SEARCH      15
#define FS_STATUS_OP_SYNC_GET         16
#define FS_STATUS_OP_SYNC_PUT         17
#define FS_STATUS_OP_SYNC_DELETE      18
#define FS_STATUS_OP_GET_MULTI_THREAD 19
#define FS_STATUS_OP_PUT_MULTI_THREAD 20

#define FS_ICONFLAG_SMALL         0x01
#define FS_ICONFLAG_BACKGROUND    0x02

#define FS_ICON_USEDEFAULT        0
#define FS_ICON_EXTRACTED         1
#define FS_ICON_EXTRACTED_DESTROY 2
#define FS_ICON_DELAYED           3

#define FS_BITMAP_NONE               0
#define FS_BITMAP_EXTRACTED          1
#define FS_BITMAP_EXTRACT_YOURSELF   2
#define FS_BITMAP_EXTRACT_YOURSELF_ANDDELETE 3
#define FS_BITMAP_CACHE              256

#define FS_CRYPT_SAVE_PASSWORD       1
#define FS_CRYPT_LOAD_PASSWORD       2
#define FS_CRYPT_LOAD_PASSWORD_NO_UI 3 // Load password only if master password has already been entered!
#define FS_CRYPT_COPY_PASSWORD       4 // Copy encrypted password to new connection name
#define FS_CRYPT_MOVE_PASSWORD       5 // Move password when renaming a connection
#define FS_CRYPT_DELETE_PASSWORD     6 // Delete password


#define FS_CRYPTOPT_MASTERPASS_SET   1 // The user already has a master password defined

#define BG_DOWNLOAD    0x01            // Plugin supports downloads in background
#define BG_UPLOAD      0x02            // Plugin supports uploads in background
#define BG_ASK_USER    0x04            // Plugin requires separate connection for background transfers -> ask user first

#define FS_CHK_CRC32   0x0001
#define FS_CHK_MD5     0x0002
#define FS_CHK_SHA1    0x0004
#define FS_CHK_SHA256  0x0008
#define FS_CHK_SHA512  0x0010
#define FS_CHK_OTHER   0x0200

#define FS_CHK_ERR_BUSY   -1           // Checksum calculation still active, try again
#define FS_CHK_ERR_FAIL   -2           // Failed to get checksum

#define FS_TIME_UNKNOWN  (-2LL)        // Use the following settings for files which don't have a time

#define FS_ATTR_UNIXMODE  0x80000000   // for Unix systems: set the dwReserved0 parameter to the Unix file mode (permissions).


typedef struct {
    union {
        struct {
            DWORD SizeLow;
            DWORD SizeHigh;
        };
        INT64 Size64;
    };
    union {
        FILETIME LastWriteTime;
        INT64   iLastWriteTime;
    };
    DWORD Attr;
} RemoteInfoStruct, *PRemoteInfoStruct;

typedef struct {
    int   size;
    DWORD PluginInterfaceVersionLow;
    DWORD PluginInterfaceVersionHi;
    char  DefaultIniName[MAX_PATH];
} FsDefaultParamStruct;

// callback functions
typedef int  (WINAPI *tProgressProc)(int PluginNr, LPCSTR SourceName, LPCSTR TargetName, int PercentDone);
typedef int  (WINAPI *tProgressProcW)(int PluginNr, LPCWSTR SourceName, LPCWSTR TargetName, int PercentDone);
typedef void (WINAPI *tLogProc)(int PluginNr, int MsgType, LPCSTR LogString);
typedef void (WINAPI *tLogProcW)(int PluginNr, int MsgType, LPCWSTR LogString);

typedef BOOL (WINAPI *tRequestProc)(int PluginNr, int RequestType, LPCSTR CustomTitle, LPCSTR CustomText, LPSTR ReturnedText, int maxlen);
typedef BOOL (WINAPI *tRequestProcW)(int PluginNr, int RequestType, LPCWSTR CustomTitle, LPCWSTR CustomText, LPWSTR ReturnedText, int maxlen);
typedef int  (WINAPI *tCryptProc)(int PluginNr, int CryptoNr, int Mode, LPCSTR ConnectionName, LPSTR Password, int maxlen);
typedef int  (WINAPI *tCryptProcW)(int PluginNr, int CryptoNr, int Mode, LPCWSTR ConnectionName, LPWSTR Password, int maxlen);

// Function prototypes
int  WINAPI FsInit(int PluginNr, tProgressProc pProgressProc, tLogProc pLogProc, tRequestProc pRequestProc);
int  WINAPI FsInitW(int PluginNr, tProgressProcW pProgressProcW, tLogProcW pLogProcW, tRequestProcW pRequestProcW);
void WINAPI FsSetCryptCallback(tCryptProc pCryptProc, int CryptoNr, int Flags);
void WINAPI FsSetCryptCallbackW(tCryptProcW pCryptProcW, int CryptoNr, int Flags);
HANDLE WINAPI FsFindFirst(LPCSTR Path, LPWIN32_FIND_DATA FindData);
HANDLE WINAPI FsFindFirstW(LPCWSTR Path, LPWIN32_FIND_DATAW FindData);

BOOL WINAPI FsFindNext(HANDLE Hdl, LPWIN32_FIND_DATA FindData);
BOOL WINAPI FsFindNextW(HANDLE Hdl, LPWIN32_FIND_DATAW FindData);
int  WINAPI FsFindClose(HANDLE Hdl);
BOOL WINAPI FsMkDir(LPCSTR Path);
BOOL WINAPI FsMkDirW(LPCWSTR Path);
int  WINAPI FsExecuteFile(HWND MainWin, LPSTR RemoteName, LPCSTR Verb);
int  WINAPI FsExecuteFileW(HWND MainWin, LPWSTR RemoteName, LPCWSTR Verb);
int  WINAPI FsRenMovFile(LPCSTR OldName, LPCSTR NewName, BOOL Move,  BOOL OverWrite, RemoteInfoStruct * ri);
int  WINAPI FsRenMovFileW(LPCWSTR OldName, LPCWSTR NewName, BOOL Move, BOOL OverWrite, RemoteInfoStruct * ri);
int  WINAPI FsGetFile(LPCSTR RemoteName, LPSTR LocalName, int CopyFlags, RemoteInfoStruct * ri);
int  WINAPI FsGetFileW(LPCWSTR RemoteName, LPWSTR LocalName, int CopyFlags, RemoteInfoStruct * ri);
int  WINAPI FsPutFile(LPCSTR LocalName, LPCSTR RemoteName, int CopyFlags);
int  WINAPI FsPutFileW(LPCWSTR LocalName, LPCWSTR RemoteName, int CopyFlags);
BOOL WINAPI FsDeleteFile(LPCSTR RemoteName);
BOOL WINAPI FsDeleteFileW(LPCWSTR RemoteName);
BOOL WINAPI FsRemoveDir(LPCSTR RemoteName);
BOOL WINAPI FsRemoveDirW(LPCWSTR RemoteName);
BOOL WINAPI FsDisconnect(LPCSTR DisconnectRoot);
BOOL WINAPI FsDisconnectW(LPCWSTR DisconnectRoot);
BOOL WINAPI FsSetAttr(LPCSTR RemoteName, int NewAttr);
BOOL WINAPI FsSetAttrW(LPCWSTR RemoteName, int NewAttr);
BOOL WINAPI FsSetTime(LPCSTR RemoteName, LPFILETIME CreationTime, LPFILETIME LastAccessTime, LPFILETIME LastWriteTime);
BOOL WINAPI FsSetTimeW(LPCWSTR RemoteName, LPFILETIME CreationTime, LPFILETIME LastAccessTime, LPFILETIME LastWriteTime);
void WINAPI FsStatusInfo(LPCSTR RemoteDir, int InfoStartEnd, int InfoOperation);
void WINAPI FsStatusInfoW(LPCWSTR RemoteDir, int InfoStartEnd, int InfoOperation);
int  WINAPI FsExtractCustomIcon(LPCSTR RemoteName, int ExtractFlags, HICON * TheIcon);
int  WINAPI FsExtractCustomIconW(LPCWSTR RemoteName, int ExtractFlags, HICON * TheIcon);

void WINAPI FsGetDefRootName(LPSTR DefRootName, int maxlen);
void WINAPI FsSetDefaultParams(FsDefaultParamStruct * dps);

int  WINAPI FsServerSupportsChecksums(LPCSTR RemoteName);
int  WINAPI FsServerSupportsChecksumsW(LPCWSTR RemoteName);
HANDLE WINAPI FsStartFileChecksum(int ChecksumType, LPCSTR RemoteName);
HANDLE WINAPI FsStartFileChecksumW(int ChecksumType, LPCWSTR RemoteName);
int  WINAPI FsGetFileChecksumResult(BOOL WantResult, HANDLE ChecksumHandle, LPCSTR RemoteName, LPSTR checksum, int maxlen);
int  WINAPI FsGetFileChecksumResultW(BOOL WantResult, HANDLE ChecksumHandle, LPCWSTR RemoteName, LPSTR checksum, int maxlen);

int  WINAPI FsGetPreviewBitmap(char* RemoteName, int width, int height, HBITMAP* ReturnedBitmap);
int  WINAPI FsGetPreviewBitmapW(WCHAR* RemoteName, int width, int height, HBITMAP* ReturnedBitmap);
BOOL WINAPI FsLinksToLocalFiles(void);
BOOL WINAPI FsGetLocalName(char* RemoteName, int maxlen);
BOOL WINAPI FsGetLocalNameW(WCHAR* RemoteName, int maxlen);

// ************************** content plugin extension ****************************

// 
#define ft_nomorefields     0
#define ft_numeric_32       1
#define ft_numeric_64       2
#define ft_numeric_floating 3
#define ft_date             4
#define ft_time             5
#define ft_boolean          6
#define ft_multiplechoice   7
#define ft_string           8
#define ft_fulltext         9
#define ft_datetime        10
#define ft_stringw         11  // Should only be returned by Unicode function

// for FsContentGetValue
#define ft_nosuchfield   -1  // error, invalid field number given
#define ft_fileerror     -2  // file i/o error
#define ft_fieldempty    -3  // field valid, but empty
#define ft_ondemand      -4  // field will be retrieved only when user presses <SPACEBAR>
#define ft_delayed        0  // field takes a long time to extract -> try again in background

// for FsContentSetValue
#define ft_setsuccess     0  // setting of the attribute succeeded


// for ContentGetSupportedFieldFlags
typedef enum cont_subst : BYTE {
  cont_size     = 1,
  cont_datetime = 2,
  cont_date     = 3,
  cont_time     = 4,
  cont_attributes = 5,
  cont_attributestr = 6,
  cont_passthrough_size_float = 7,
} cont_subst;

typedef struct {
  BYTE   edit      : 1;
  BYTE   subst     : 3;   /* see cont_subst */
  BYTE   fieldedit : 1;
  BYTE   reserved  : 3;
} tcContFlags_t;

// for FsContentGetSupportedFieldFlags
#define contflags_edit                   0x01
#define contflags_substsize              (cont_size << 1)
#define contflags_substdatetime          (cont_datetime << 1)
#define contflags_substdate              (cont_date << 1)
#define contflags_substtime              (cont_time << 1)
#define contflags_substattributes        (cont_attributes << 1)
#define contflags_substattributestr      (cont_attributestr << 1)
#define contflags_passthrough_size_float (cont_passthrough_size_float << 1)
#define contflags_substmask              0x0E
#define contflags_fieldedit              0x10

// for FsContentSetValue
#define setflags_first_attribute   0x01  // First attribute of this file
#define setflags_last_attribute    0x02  // Last attribute of this file
#define setflags_only_date         0x04  // Only set the date of the datetime value!


#define CONTENT_DELAYIFSLOW 1  // ContentGetValue called in foreground


typedef struct {
    int   size;
    DWORD PluginInterfaceVersionLow;
    DWORD PluginInterfaceVersionHi;
    char  DefaultIniName[MAX_PATH];
} ContentDefaultParamStruct;

typedef struct {
    WORD wYear;
    WORD wMonth;
    WORD wDay;
} tdateformat, *pdateformat;

typedef struct {
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
} ttimeformat, *ptimeformat;

int  WINAPI FsContentGetSupportedField(int FieldIndex, char* FieldName, char* Units, int maxlen);
int  WINAPI FsContentGetValue(char* FileName, int FieldIndex, int UnitIndex, void* FieldValue, int maxlen, int flags);
int  WINAPI FsContentGetValueW(WCHAR* FileName, int FieldIndex, int UnitIndex, void* FieldValue, int maxlen, int flags);

void WINAPI FsContentStopGetValue(char* FileName);
void WINAPI FsContentStopGetValueW(WCHAR* FileName);
int  WINAPI FsContentGetDefaultSortOrder(int FieldIndex);
void WINAPI FsContentPluginUnloading(void);
int  WINAPI FsContentGetSupportedFieldFlags(int FieldIndex);
int  WINAPI FsContentSetValue(char* FileName, int FieldIndex, int UnitIndex, int FieldType, void* FieldValue, int flags);
int  WINAPI FsContentSetValueW(WCHAR* FileName, int FieldIndex, int UnitIndex, int FieldType, void* FieldValue, int flags);

BOOL WINAPI FsContentGetDefaultView(char* ViewContents, char* ViewHeaders, char* ViewWidths, char* ViewOptions, int maxlen);
BOOL WINAPI FsContentGetDefaultViewW(WCHAR* ViewContents, WCHAR* ViewHeaders, WCHAR* ViewWidths, WCHAR* ViewOptions, int maxlen);

int  WINAPI FsGetBackgroundFlags(void);

#pragma pack(pop)


