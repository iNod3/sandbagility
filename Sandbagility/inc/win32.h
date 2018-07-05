BOOL WINAPI CryptExportKey(
  _In_     HCRYPTKEY hKey,
  _In_     HCRYPTKEY hExpKey,
  _In_     DWORD dwBlobType,
  _In_     DWORD dwFlags,
  _Out_    BYTE *pbData,
  _Inout_  DWORD *pdwDataLen
);

BOOL WINAPI CryptImportKey(
  _In_   HCRYPTPROV hProv,
  _In_   BYTE *pbData,
  _In_   DWORD dwDataLen,
  _In_   HCRYPTKEY hPubKey,
  _In_   DWORD dwFlags,
  _Out_  HCRYPTKEY *phKey
);

BOOL WINAPI CryptEncrypt(
  _In_     HCRYPTKEY hKey,
  _In_     HCRYPTHASH hHash,
  _In_     BOOL Final,
  _In_     DWORD dwFlags,
  _Inout_  BYTE *pbData,
  _Inout_  DWORD *pdwDataLen,
  _In_     DWORD dwBufLen
);

BOOL WINAPI CryptDecrypt(
	_In_     HCRYPTKEY hKey,
	_In_     HCRYPTHASH hHash,
	_In_     BOOL Final,
	_In_     DWORD dwFlags,
	_Inout_  BYTE *pbData,
	_Inout_  DWORD *pdwDataLen
);

BOOL WINAPI CryptGetHashParam(
  _In_     HCRYPTHASH hHash,
  _In_     DWORD dwParam,
  _Out_    BYTE *pbData,
  _Inout_  DWORD *pdwDataLen,
  _In_     DWORD dwFlags
);

BOOL WINAPI CryptHashData(
  _In_  HCRYPTHASH hHash,
  _In_  BYTE *pbData,
  _In_  DWORD dwDataLen,
  _In_  DWORD dwFlags
);

BOOL WINAPI CryptCreateHash(
  _In_   HCRYPTPROV hProv,
  _In_   ALG_ID Algid,
  _In_   HCRYPTKEY hKey,
  _In_   DWORD dwFlags,
  _Out_  HCRYPTHASH *phHash
);

BOOL WINAPI CryptGenKey(
  _In_   HCRYPTPROV hProv,
  _In_   ALG_ID Algid,
  _In_   DWORD dwFlags,
  _Out_  HCRYPTKEY *phKey
);

BOOL WINAPI CryptAcquireContext(
  _Out_  HCRYPTPROV *phProv,
  _In_   LPCTSTR pszContainer,
  _In_   LPCTSTR pszProvider,
  _In_   DWORD dwProvType,
  _In_   DWORD dwFlags
);

BOOL WINAPI CryptDecodeObjectEx(
	_In_ DWORD              dwCertEncodingType,
	_In_ LPCSTR             lpszStructType,
	_In_ const BYTE         *pbEncoded,
	_In_ DWORD              cbEncoded,
	_In_ DWORD              dwFlags,
	_In_ PCRYPT_DECODE_PARA pDecodePara,
	_In_Out_ LPVOID               pvStructInfo,
	_In_Out_ DWORD              *pcbStructInfo
);

HRSRC WINAPI FindResource(
  _In_opt_  HMODULE hModule,
  _In_      LPCTSTR lpName,
  _In_      LPCTSTR lpType
);

HRSRC WINAPI FindResourceEx(
  _In_opt_  HMODULE hModule,
  _In_      LPCTSTR lpType,
  _In_      LPCTSTR lpName,
  _In_      WORD wLanguage
);

HGLOBAL WINAPI LoadResource(
  _In_opt_  HMODULE hModule,
  _In_      HRSRC hResInfo
);

DWORD WINAPI SizeofResource(
  _In_opt_  HMODULE hModule,
  _In_      HRSRC hResInfo
);

SC_HANDLE WINAPI OpenSCManager(
	_In_opt_  LPCTSTR lpMachineName,
	_In_opt_  LPCTSTR lpDatabaseName,
	_In_      DWORD dwDesiredAccess
);

SC_HANDLE WINAPI OpenService(
	_In_  SC_HANDLE hSCManager,
	_In_  LPCTSTR lpServiceName,
	_In_  DWORD dwDesiredAccess
);

BOOL WINAPI CloseServiceHandle(
	_In_  SC_HANDLE hSCObject
);

SC_HANDLE WINAPI CreateService(
	_In_       SC_HANDLE hSCManager,
	_In_       LPCTSTR lpServiceName,
	_In_opt_   LPCTSTR lpDisplayName,
	_In_       DWORD dwDesiredAccess,
	_In_       DWORD dwServiceType,
	_In_       DWORD dwStartType,
	_In_       DWORD dwErrorControl,
	_In_opt_   LPCTSTR lpBinaryPathName,
	_In_opt_   LPCTSTR lpLoadOrderGroup,
	_Out_opt_  LPDWORD lpdwTagId,
	_In_opt_   LPCTSTR lpDependencies,
	_In_opt_   LPCTSTR lpServiceStartName,
	_In_opt_   LPCTSTR lpPassword
);

BOOL WINAPI ChangeServiceConfig(
	_In_       SC_HANDLE hService,
	_In_       DWORD dwServiceType,
	_In_       DWORD dwStartType,
	_In_       DWORD dwErrorControl,
	_In_opt_   LPCTSTR lpBinaryPathName,
	_In_opt_   LPCTSTR lpLoadOrderGroup,
	_Out_opt_  LPDWORD lpdwTagId,
	_In_opt_   LPCTSTR lpDependencies,
	_In_opt_   LPCTSTR lpServiceStartName,
	_In_opt_   LPCTSTR lpPassword,
	_In_opt_   LPCTSTR lpDisplayName
);

BOOL WINAPI StartServiceCtrlDispatcher(
	_In_  const SERVICE_TABLE_ENTRY *lpServiceTable
);

SERVICE_STATUS_HANDLE WINAPI RegisterServiceCtrlHandler(
	_In_  LPCTSTR lpServiceName,
	_In_  LPHANDLER_FUNCTION lpHandlerProc
);

BOOL WINAPI StartService(
  _In_      SC_HANDLE hService,
  _In_      DWORD dwNumServiceArgs,
  _In_opt_  LPCTSTR *lpServiceArgVectors
);

BOOL WINAPI DeleteService(
	_In_ SC_HANDLE hService
);

BOOL WINAPI ControlService(
  _In_  SC_HANDLE        hService,
  _In_  DWORD            dwControl,
  _Out_ LPSERVICE_STATUS lpServiceStatus
);

HINTERNET WINAPI InternetOpen(
	_In_  LPCTSTR lpszAgent,
	_In_  DWORD dwAccessType,
	_In_  LPCTSTR lpszProxyName,
	_In_  LPCTSTR lpszProxyBypass,
	_In_  DWORD dwFlags
);

HINTERNET WINAPI InternetOpenUrl(
	_In_  HINTERNET hInternet,
	_In_  LPCTSTR lpszUrl,
	_In_  LPCTSTR lpszHeaders,
	_In_  DWORD dwHeadersLength,
	_In_  DWORD dwFlags,
	_In_  DWORD_PTR dwContext
);

HINTERNET WINAPI InternetConnect(
  _In_ HINTERNET     hInternet,
  _In_ LPCTSTR       lpszServerName,
  _In_ INTERNET_PORT nServerPort,
  _In_ LPCTSTR       lpszUsername,
  _In_ LPCTSTR       lpszPassword,
  _In_ DWORD         dwService,
  _In_ DWORD         dwFlags,
  _In_ DWORD_PTR     dwContext
);

BOOL WINAPI InternetReadFile(
  _In_  HINTERNET hFile,
  _Out_ LPVOID    lpBuffer,
  _In_  DWORD     dwNumberOfBytesToRead,
  _Out_ LPDWORD   lpdwNumberOfBytesRead
);

BOOL WINAPI HttpSendRequest(
  _In_ HINTERNET hRequest,
  _In_ LPCTSTR   lpszHeaders,
  _In_ DWORD     dwHeadersLength,
  _In_ LPVOID    lpOptional,
  _In_ DWORD     dwOptionalLength
);

HINTERNET WINAPI HttpOpenRequest(
  _In_ HINTERNET hConnect,
  _In_ LPCTSTR   lpszVerb,
  _In_ LPCTSTR   lpszObjectName,
  _In_ LPCTSTR   lpszVersion,
  _In_ LPCTSTR   lpszReferer,
  _In_ LPCTSTR   *lplpszAcceptTypes,
  _In_ DWORD     dwFlags,
  _In_ DWORD_PTR dwContext
);

BOOLEAN WINAPI RtlFreeHeap(
	_In_     PVOID HeapHandle,
	_In_opt_ ULONG Flags,
	_In_     PVOID HeapBase
);

PVOID WINAPI RtlAllocateHeap(
	_In_     PVOID  HeapHandle,
	_In_opt_ ULONG  Flags,
	_In_     SIZE_T Size
);

HANDLE WINAPI CreateFile(
		_In_ LPCTSTR lpFileName,
		_In_ DWORD dwDesiredAccess,
		_In_ DWORD dwShareMode,
		_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		_In_ DWORD dwCreationDisposition,
		_In_ DWORD dwFlagsAndAttributes,
		_In_opt_ HANDLE hTemplateFile
);

BOOL WINAPI ReadFile(
	_In_        HANDLE       FileHandle,
	_Out_       LPVOID       Buffer,
	_In_        DWORD        Length,
	_Out_opt_   LPDWORD      lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);

BOOL WINAPI WriteFile(
	_In_        HANDLE       FileHandle,
	_In_        LPCVOID      Buffer,
	_In_        DWORD        Length,
	_Out_opt_   LPDWORD      lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);

DWORD WINAPI send(
	_In_ SOCKET Socket,
	_In_ BYTE *Buffer,
	_In_ DWORD Length,
	_In_ DWORD Flags
);

DWORD WINAPI recv(
	_In_ SOCKET Socket,
	_Out_ BYTE *Buffer,
	_In_ DWORD Length,
	_In_ DWORD Flags
);

DWORD WINAPI connect(
	_In_ SOCKET Socket,
	_In_ BYTE *Addr,
	_In_ DWORD NameLength
);

DWORD WINAPI bind(
	_In_ SOCKET Socket,
	_In_ BYTE *Addr,
	_In_ DWORD NameLength
);

HANDLE WINAPI CreateMutex(
	_In_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
	_In_ BOOL bInitialOwner,
	_In_ LPCTSTR lpName
);

HANDLE WINAPI CreateMutexEx(
	_In_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
	_In_ LPCTSTR lpName,
	_In_ DWORD dwFlags,
	_In_ DWORD dwDesiredAccess
);

HANDLE WINAPI CreateEventEx(
	_In_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
	_In_ LPCTSTR lpName,
	_In_ DWORD dwFlags,
	_In_ DWORD dwDesiredAccess
);