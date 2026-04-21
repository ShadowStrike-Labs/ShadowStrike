/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * WinMacroUndef.hpp - Undefines Windows SDK preprocessor macros that collide
 * with Phantom guest-side constexpr constants declared in Constants.hpp and
 * APITypes.hpp.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

// Helper to #undef a symbol if defined.  Kept as a sequence of explicit
// directives so the preprocessor can exactly tell which tokens must be
// shadowed as typed constexpr values.
#define PHANTOM_UNDEF_(name) \
    /* intentionally empty — placeholder for documentation */

// ---- NTSTATUS values (winnt.h / ntstatus.h) -------------------------------
#ifdef STATUS_SUCCESS
#  undef STATUS_SUCCESS
#endif
#ifdef STATUS_PENDING
#  undef STATUS_PENDING
#endif
#ifdef STATUS_BUFFER_OVERFLOW
#  undef STATUS_BUFFER_OVERFLOW
#endif
#ifdef STATUS_NO_MORE_ENTRIES
#  undef STATUS_NO_MORE_ENTRIES
#endif
#ifdef STATUS_UNSUCCESSFUL
#  undef STATUS_UNSUCCESSFUL
#endif
#ifdef STATUS_NOT_IMPLEMENTED
#  undef STATUS_NOT_IMPLEMENTED
#endif
#ifdef STATUS_INVALID_INFO_CLASS
#  undef STATUS_INVALID_INFO_CLASS
#endif
#ifdef STATUS_INFO_LENGTH_MISMATCH
#  undef STATUS_INFO_LENGTH_MISMATCH
#endif
#ifdef STATUS_ACCESS_VIOLATION
#  undef STATUS_ACCESS_VIOLATION
#endif
#ifdef STATUS_INVALID_HANDLE
#  undef STATUS_INVALID_HANDLE
#endif
#ifdef STATUS_INVALID_PARAMETER
#  undef STATUS_INVALID_PARAMETER
#endif
#ifdef STATUS_NO_SUCH_FILE
#  undef STATUS_NO_SUCH_FILE
#endif
#ifdef STATUS_END_OF_FILE
#  undef STATUS_END_OF_FILE
#endif
#ifdef STATUS_NO_MEMORY
#  undef STATUS_NO_MEMORY
#endif
#ifdef STATUS_CONFLICTING_ADDRESSES
#  undef STATUS_CONFLICTING_ADDRESSES
#endif
#ifdef STATUS_ACCESS_DENIED
#  undef STATUS_ACCESS_DENIED
#endif
#ifdef STATUS_BUFFER_TOO_SMALL
#  undef STATUS_BUFFER_TOO_SMALL
#endif
#ifdef STATUS_OBJECT_TYPE_MISMATCH
#  undef STATUS_OBJECT_TYPE_MISMATCH
#endif
#ifdef STATUS_OBJECT_NAME_NOT_FOUND
#  undef STATUS_OBJECT_NAME_NOT_FOUND
#endif
#ifdef STATUS_OBJECT_NAME_COLLISION
#  undef STATUS_OBJECT_NAME_COLLISION
#endif
#ifdef STATUS_OBJECT_PATH_NOT_FOUND
#  undef STATUS_OBJECT_PATH_NOT_FOUND
#endif
#ifdef STATUS_OBJECT_PATH_SYNTAX_BAD
#  undef STATUS_OBJECT_PATH_SYNTAX_BAD
#endif
#ifdef STATUS_SHARING_VIOLATION
#  undef STATUS_SHARING_VIOLATION
#endif
#ifdef STATUS_INSUFFICIENT_RESOURCES
#  undef STATUS_INSUFFICIENT_RESOURCES
#endif
#ifdef STATUS_NOT_SUPPORTED
#  undef STATUS_NOT_SUPPORTED
#endif
#ifdef STATUS_ILLEGAL_FUNCTION
#  undef STATUS_ILLEGAL_FUNCTION
#endif
#ifdef STATUS_PRIVILEGE_NOT_HELD
#  undef STATUS_PRIVILEGE_NOT_HELD
#endif
#ifdef STATUS_PROCEDURE_NOT_FOUND
#  undef STATUS_PROCEDURE_NOT_FOUND
#endif
#ifdef STATUS_DLL_NOT_FOUND
#  undef STATUS_DLL_NOT_FOUND
#endif
#ifdef STATUS_ENTRYPOINT_NOT_FOUND
#  undef STATUS_ENTRYPOINT_NOT_FOUND
#endif
#ifdef STATUS_DLL_INIT_FAILED
#  undef STATUS_DLL_INIT_FAILED
#endif
#ifdef STATUS_PORT_NOT_SET
#  undef STATUS_PORT_NOT_SET
#endif
#ifdef STATUS_NOT_FOUND
#  undef STATUS_NOT_FOUND
#endif
#ifdef STATUS_TIMEOUT
#  undef STATUS_TIMEOUT
#endif

// ---- NT_* macros ----------------------------------------------------------
#ifdef NT_SUCCESS
#  undef NT_SUCCESS
#endif
#ifdef NT_ERROR
#  undef NT_ERROR
#endif
#ifdef NT_WARNING
#  undef NT_WARNING
#endif
#ifdef NT_INFORMATION
#  undef NT_INFORMATION
#endif

// ---- Win32 ERROR_* codes (winerror.h) -------------------------------------
#ifdef ERROR_SUCCESS
#  undef ERROR_SUCCESS
#endif
#ifdef ERROR_INVALID_FUNCTION
#  undef ERROR_INVALID_FUNCTION
#endif
#ifdef ERROR_FILE_NOT_FOUND
#  undef ERROR_FILE_NOT_FOUND
#endif
#ifdef ERROR_PATH_NOT_FOUND
#  undef ERROR_PATH_NOT_FOUND
#endif
#ifdef ERROR_TOO_MANY_OPEN_FILES
#  undef ERROR_TOO_MANY_OPEN_FILES
#endif
#ifdef ERROR_ACCESS_DENIED
#  undef ERROR_ACCESS_DENIED
#endif
#ifdef ERROR_INVALID_HANDLE
#  undef ERROR_INVALID_HANDLE
#endif
#ifdef ERROR_NOT_ENOUGH_MEMORY
#  undef ERROR_NOT_ENOUGH_MEMORY
#endif
#ifdef ERROR_OUTOFMEMORY
#  undef ERROR_OUTOFMEMORY
#endif
#ifdef ERROR_INVALID_DRIVE
#  undef ERROR_INVALID_DRIVE
#endif
#ifdef ERROR_NO_MORE_FILES
#  undef ERROR_NO_MORE_FILES
#endif
#ifdef ERROR_NOT_READY
#  undef ERROR_NOT_READY
#endif
#ifdef ERROR_SHARING_VIOLATION
#  undef ERROR_SHARING_VIOLATION
#endif
#ifdef ERROR_HANDLE_EOF
#  undef ERROR_HANDLE_EOF
#endif
#ifdef ERROR_NOT_SUPPORTED
#  undef ERROR_NOT_SUPPORTED
#endif
#ifdef ERROR_INVALID_PARAMETER
#  undef ERROR_INVALID_PARAMETER
#endif
#ifdef ERROR_INSUFFICIENT_BUFFER
#  undef ERROR_INSUFFICIENT_BUFFER
#endif
#ifdef ERROR_INVALID_NAME
#  undef ERROR_INVALID_NAME
#endif
#ifdef ERROR_MOD_NOT_FOUND
#  undef ERROR_MOD_NOT_FOUND
#endif
#ifdef ERROR_PROC_NOT_FOUND
#  undef ERROR_PROC_NOT_FOUND
#endif
#ifdef ERROR_ALREADY_EXISTS
#  undef ERROR_ALREADY_EXISTS
#endif
#ifdef ERROR_MORE_DATA
#  undef ERROR_MORE_DATA
#endif
#ifdef ERROR_NO_MORE_ITEMS
#  undef ERROR_NO_MORE_ITEMS
#endif
#ifdef ERROR_NOACCESS
#  undef ERROR_NOACCESS
#endif
#ifdef ERROR_NOT_FOUND
#  undef ERROR_NOT_FOUND
#endif

// ---- Handle constants -----------------------------------------------------
#ifdef INVALID_HANDLE_VALUE
#  undef INVALID_HANDLE_VALUE
#endif

// ---- Memory allocation / protection flags (winnt.h) -----------------------
#ifdef MEM_COMMIT
#  undef MEM_COMMIT
#endif
#ifdef MEM_RESERVE
#  undef MEM_RESERVE
#endif
#ifdef MEM_DECOMMIT
#  undef MEM_DECOMMIT
#endif
#ifdef MEM_RELEASE
#  undef MEM_RELEASE
#endif
#ifdef MEM_RESET
#  undef MEM_RESET
#endif
#ifdef MEM_TOP_DOWN
#  undef MEM_TOP_DOWN
#endif
#ifdef MEM_WRITE_WATCH
#  undef MEM_WRITE_WATCH
#endif
#ifdef MEM_LARGE_PAGES
#  undef MEM_LARGE_PAGES
#endif
#ifdef PAGE_NOACCESS
#  undef PAGE_NOACCESS
#endif
#ifdef PAGE_READONLY
#  undef PAGE_READONLY
#endif
#ifdef PAGE_READWRITE
#  undef PAGE_READWRITE
#endif
#ifdef PAGE_WRITECOPY
#  undef PAGE_WRITECOPY
#endif
#ifdef PAGE_EXECUTE
#  undef PAGE_EXECUTE
#endif
#ifdef PAGE_EXECUTE_READ
#  undef PAGE_EXECUTE_READ
#endif
#ifdef PAGE_EXECUTE_READWRITE
#  undef PAGE_EXECUTE_READWRITE
#endif
#ifdef PAGE_EXECUTE_WRITECOPY
#  undef PAGE_EXECUTE_WRITECOPY
#endif
#ifdef PAGE_GUARD
#  undef PAGE_GUARD
#endif
#ifdef PAGE_NOCACHE
#  undef PAGE_NOCACHE
#endif
#ifdef PAGE_WRITECOMBINE
#  undef PAGE_WRITECOMBINE
#endif

// ---- PE image section characteristics / relocation types (winnt.h) -------
#ifdef IMAGE_SCN_CNT_CODE
#  undef IMAGE_SCN_CNT_CODE
#endif
#ifdef IMAGE_SCN_CNT_INITIALIZED_DATA
#  undef IMAGE_SCN_CNT_INITIALIZED_DATA
#endif
#ifdef IMAGE_SCN_CNT_UNINITIALIZED_DATA
#  undef IMAGE_SCN_CNT_UNINITIALIZED_DATA
#endif
#ifdef IMAGE_SCN_MEM_EXECUTE
#  undef IMAGE_SCN_MEM_EXECUTE
#endif
#ifdef IMAGE_SCN_MEM_READ
#  undef IMAGE_SCN_MEM_READ
#endif
#ifdef IMAGE_SCN_MEM_WRITE
#  undef IMAGE_SCN_MEM_WRITE
#endif
#ifdef IMAGE_SCN_MEM_SHARED
#  undef IMAGE_SCN_MEM_SHARED
#endif
#ifdef IMAGE_SCN_MEM_DISCARDABLE
#  undef IMAGE_SCN_MEM_DISCARDABLE
#endif
#ifdef IMAGE_REL_BASED_ABSOLUTE
#  undef IMAGE_REL_BASED_ABSOLUTE
#endif
#ifdef IMAGE_REL_BASED_HIGHLOW
#  undef IMAGE_REL_BASED_HIGHLOW
#endif
#ifdef IMAGE_REL_BASED_DIR64
#  undef IMAGE_REL_BASED_DIR64
#endif

// ---- File access rights (winnt.h) -----------------------------------------
#ifdef FILE_READ_DATA
#  undef FILE_READ_DATA
#endif
#ifdef FILE_WRITE_DATA
#  undef FILE_WRITE_DATA
#endif
#ifdef FILE_APPEND_DATA
#  undef FILE_APPEND_DATA
#endif
#ifdef FILE_READ_EA
#  undef FILE_READ_EA
#endif
#ifdef FILE_WRITE_EA
#  undef FILE_WRITE_EA
#endif
#ifdef FILE_EXECUTE
#  undef FILE_EXECUTE
#endif
#ifdef FILE_READ_ATTRIBUTES
#  undef FILE_READ_ATTRIBUTES
#endif
#ifdef FILE_WRITE_ATTRIBUTES
#  undef FILE_WRITE_ATTRIBUTES
#endif
#ifdef GENERIC_READ
#  undef GENERIC_READ
#endif
#ifdef GENERIC_WRITE
#  undef GENERIC_WRITE
#endif
#ifdef GENERIC_EXECUTE
#  undef GENERIC_EXECUTE
#endif
#ifdef GENERIC_ALL
#  undef GENERIC_ALL
#endif

// ---- File share mode / creation disposition ------------------------------
#ifdef FILE_SHARE_READ
#  undef FILE_SHARE_READ
#endif
#ifdef FILE_SHARE_WRITE
#  undef FILE_SHARE_WRITE
#endif
#ifdef FILE_SHARE_DELETE
#  undef FILE_SHARE_DELETE
#endif
#ifdef CREATE_NEW
#  undef CREATE_NEW
#endif
#ifdef CREATE_ALWAYS
#  undef CREATE_ALWAYS
#endif
#ifdef OPEN_EXISTING
#  undef OPEN_EXISTING
#endif
#ifdef OPEN_ALWAYS
#  undef OPEN_ALWAYS
#endif
#ifdef TRUNCATE_EXISTING
#  undef TRUNCATE_EXISTING
#endif

// ---- Registry key access / types (winreg.h / winnt.h) ---------------------
#ifdef KEY_QUERY_VALUE
#  undef KEY_QUERY_VALUE
#endif
#ifdef KEY_SET_VALUE
#  undef KEY_SET_VALUE
#endif
#ifdef KEY_CREATE_SUB_KEY
#  undef KEY_CREATE_SUB_KEY
#endif
#ifdef KEY_ENUMERATE_SUB_KEYS
#  undef KEY_ENUMERATE_SUB_KEYS
#endif
#ifdef KEY_NOTIFY
#  undef KEY_NOTIFY
#endif
#ifdef KEY_ALL_ACCESS
#  undef KEY_ALL_ACCESS
#endif
#ifdef KEY_READ
#  undef KEY_READ
#endif
#ifdef KEY_WRITE
#  undef KEY_WRITE
#endif
#ifdef REG_NONE
#  undef REG_NONE
#endif
#ifdef REG_SZ
#  undef REG_SZ
#endif
#ifdef REG_EXPAND_SZ
#  undef REG_EXPAND_SZ
#endif
#ifdef REG_BINARY
#  undef REG_BINARY
#endif
#ifdef REG_DWORD
#  undef REG_DWORD
#endif
#ifdef REG_MULTI_SZ
#  undef REG_MULTI_SZ
#endif
#ifdef REG_QWORD
#  undef REG_QWORD
#endif

// ---- Process / Thread access rights (winnt.h) -----------------------------
#ifdef PROCESS_TERMINATE
#  undef PROCESS_TERMINATE
#endif
#ifdef PROCESS_CREATE_THREAD
#  undef PROCESS_CREATE_THREAD
#endif
#ifdef PROCESS_VM_OPERATION
#  undef PROCESS_VM_OPERATION
#endif
#ifdef PROCESS_VM_READ
#  undef PROCESS_VM_READ
#endif
#ifdef PROCESS_VM_WRITE
#  undef PROCESS_VM_WRITE
#endif
#ifdef PROCESS_DUP_HANDLE
#  undef PROCESS_DUP_HANDLE
#endif
#ifdef PROCESS_CREATE_PROCESS
#  undef PROCESS_CREATE_PROCESS
#endif
#ifdef PROCESS_QUERY_INFORMATION
#  undef PROCESS_QUERY_INFORMATION
#endif
#ifdef PROCESS_ALL_ACCESS
#  undef PROCESS_ALL_ACCESS
#endif
#ifdef THREAD_TERMINATE
#  undef THREAD_TERMINATE
#endif
#ifdef THREAD_SUSPEND_RESUME
#  undef THREAD_SUSPEND_RESUME
#endif
#ifdef THREAD_GET_CONTEXT
#  undef THREAD_GET_CONTEXT
#endif
#ifdef THREAD_SET_CONTEXT
#  undef THREAD_SET_CONTEXT
#endif
#ifdef THREAD_QUERY_INFORMATION
#  undef THREAD_QUERY_INFORMATION
#endif
#ifdef THREAD_ALL_ACCESS
#  undef THREAD_ALL_ACCESS
#endif

// ---- Wait / exit status (winbase.h) --------------------------------------
#ifdef WAIT_TIMEOUT
#  undef WAIT_TIMEOUT
#endif
#ifdef WAIT_OBJECT_0
#  undef WAIT_OBJECT_0
#endif
#ifdef WAIT_ABANDONED
#  undef WAIT_ABANDONED
#endif
#ifdef WAIT_FAILED
#  undef WAIT_FAILED
#endif
#ifdef STILL_ACTIVE
#  undef STILL_ACTIVE
#endif

#undef PHANTOM_UNDEF_
