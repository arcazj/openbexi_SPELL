"""Handle-relative, no-follow filesystem primitives for the v0.8 virtual roots."""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


class SecureFilesystemError(OSError):
    """Raised when a filesystem object cannot satisfy the closed VFS contract."""


@dataclass(slots=True)
class OwnedDirectory:
    """A directory identity retained by the server for handle-relative access."""

    path: Path
    handle: int
    identity: tuple[int, ...]
    closed: bool = False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if os.name == "nt":
            _win_close_handle(self.handle)
        else:
            os.close(self.handle)


def open_owned_directory(path: Path, *, create: bool = False) -> OwnedDirectory:
    """Open an absolute directory without following any existing link component."""

    absolute = Path(path).absolute()
    if os.name == "nt":
        return _win_open_absolute_directory(absolute, create=create)

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(os.path.sep, flags)
    current = Path(os.path.sep)
    try:
        for component in absolute.parts[1:]:
            _validate_leaf(component)
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(component, flags, dir_fd=descriptor)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode):
                os.close(child)
                raise SecureFilesystemError(errno.ENOTDIR, "path component is not a directory")
            os.close(descriptor)
            descriptor = child
            current /= component
        info = os.fstat(descriptor)
        return OwnedDirectory(absolute, descriptor, (info.st_dev, info.st_ino))
    except Exception:
        os.close(descriptor)
        raise


def open_child_directory(
    parent: OwnedDirectory,
    name: str,
    *,
    create: bool = False,
) -> OwnedDirectory:
    _validate_leaf(name)
    if os.name == "nt":
        handle = _win_nt_open(
            parent.handle,
            name,
            desired_access=(
                _WIN_GENERIC_READ
                | _WIN_GENERIC_WRITE
                | _WIN_SYNCHRONIZE
            ),
            disposition=_WIN_FILE_OPEN_IF if create else _WIN_FILE_OPEN,
            options=(
                _WIN_FILE_DIRECTORY_FILE
                | _WIN_FILE_OPEN_REPARSE_POINT
                | _WIN_FILE_SYNCHRONOUS_IO_NONALERT
            ),
            share=_WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE,
        )
        try:
            info = _win_handle_information(handle)
            _win_require_directory(info)
            return OwnedDirectory(
                parent.path / name,
                handle,
                _win_identity(info),
            )
        except Exception:
            _win_close_handle(handle)
            raise

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent.handle)
        except FileExistsError:
            pass
    descriptor = os.open(name, flags, dir_fd=parent.handle)
    try:
        info = os.fstat(descriptor)
        parent_info = os.fstat(parent.handle)
        if not stat.S_ISDIR(info.st_mode):
            raise SecureFilesystemError(errno.ENOTDIR, "path component is not a directory")
        if info.st_dev != parent_info.st_dev:
            raise SecureFilesystemError(errno.EXDEV, "nested mount points are forbidden")
        return OwnedDirectory(
            parent.path / name,
            descriptor,
            (info.st_dev, info.st_ino),
        )
    except Exception:
        os.close(descriptor)
        raise


def open_regular_file(
    directory: OwnedDirectory,
    name: str,
    *,
    create: bool = False,
    writable: bool = False,
    delete_access: bool = False,
    share_delete: bool = False,
) -> BinaryIO:
    """Open one direct child as a single-link regular file without following it."""

    _validate_leaf(name)
    if os.name == "nt":
        desired = _WIN_GENERIC_READ | _WIN_SYNCHRONIZE
        if writable:
            desired |= _WIN_GENERIC_WRITE
        if delete_access:
            desired |= _WIN_DELETE
        share = _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE
        if share_delete:
            share |= _WIN_FILE_SHARE_DELETE
        handle = _win_nt_open(
            directory.handle,
            name,
            desired_access=desired,
            disposition=_WIN_FILE_CREATE if create else _WIN_FILE_OPEN,
            options=(
                _WIN_FILE_NON_DIRECTORY_FILE
                | _WIN_FILE_OPEN_REPARSE_POINT
                | _WIN_FILE_SYNCHRONOUS_IO_NONALERT
            ),
            share=share,
        )
        try:
            info = _win_handle_information(handle)
            _win_require_regular(info)
            import msvcrt

            flags = os.O_BINARY | (os.O_RDWR if writable else os.O_RDONLY)
            descriptor = msvcrt.open_osfhandle(handle, flags)
            handle = 0
            return os.fdopen(descriptor, "r+b" if writable else "rb", buffering=0)
        except Exception:
            if handle:
                _win_close_handle(handle)
            raise

    flags = os.O_CLOEXEC | os.O_NOFOLLOW | (os.O_RDWR if writable else os.O_RDONLY)
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory.handle)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            raise SecureFilesystemError(
                errno.EPERM, "regular file identity is ambiguous"
            ) from exc
        raise
    try:
        _require_regular_stat(os.fstat(descriptor))
        return os.fdopen(descriptor, "r+b" if writable else "rb", buffering=0)
    except Exception:
        os.close(descriptor)
        raise


def file_identity(stream: BinaryIO) -> tuple[int, ...]:
    if os.name == "nt":
        import msvcrt

        handle = msvcrt.get_osfhandle(stream.fileno())
        return _win_identity(_win_handle_information(handle))
    info = os.fstat(stream.fileno())
    _require_regular_stat(info)
    return (info.st_dev, info.st_ino)


def read_stream(stream: BinaryIO) -> bytes:
    stream.seek(0)
    payload = stream.read()
    if not isinstance(payload, bytes):
        raise SecureFilesystemError(errno.EIO, "regular file did not return bytes")
    return payload


def read_regular_file(directory: OwnedDirectory, name: str) -> bytes:
    with open_regular_file(directory, name) as stream:
        return read_stream(stream)


def regular_file_exists(directory: OwnedDirectory, name: str) -> bool:
    try:
        stream = open_regular_file(directory, name)
    except FileNotFoundError:
        return False
    try:
        return True
    finally:
        stream.close()


def unlink_regular_file(directory: OwnedDirectory, name: str) -> bool:
    """Delete the exact no-follow regular-file identity, returning whether it existed."""

    _validate_leaf(name)
    if os.name == "nt":
        try:
            handle = _win_nt_open(
                directory.handle,
                name,
                desired_access=_WIN_DELETE | _WIN_GENERIC_READ | _WIN_SYNCHRONIZE,
                disposition=_WIN_FILE_OPEN,
                options=(
                    _WIN_FILE_NON_DIRECTORY_FILE
                    | _WIN_FILE_OPEN_REPARSE_POINT
                    | _WIN_FILE_SYNCHRONOUS_IO_NONALERT
                ),
                share=(
                    _WIN_FILE_SHARE_READ
                    | _WIN_FILE_SHARE_WRITE
                    | _WIN_FILE_SHARE_DELETE
                ),
            )
        except FileNotFoundError:
            return False
        try:
            _win_require_regular(_win_handle_information(handle))
            _win_mark_delete(handle)
        finally:
            _win_close_handle(handle)
        return True
    try:
        stream = open_regular_file(directory, name)
    except FileNotFoundError:
        return False
    try:
        os.unlink(name, dir_fd=directory.handle)
    finally:
        stream.close()
    return True


def unlink_entry(directory: OwnedDirectory, name: str) -> bool:
    """Unlink one non-directory entry by retained parent without following it."""

    _validate_leaf(name)
    if os.name != "nt":
        try:
            os.unlink(name, dir_fd=directory.handle)
        except FileNotFoundError:
            return False
        return True
    try:
        handle = _win_nt_open(
            directory.handle,
            name,
            desired_access=_WIN_DELETE | _WIN_GENERIC_READ | _WIN_SYNCHRONIZE,
            disposition=_WIN_FILE_OPEN,
            options=_WIN_FILE_OPEN_REPARSE_POINT | _WIN_FILE_SYNCHRONOUS_IO_NONALERT,
            share=(
                _WIN_FILE_SHARE_READ
                | _WIN_FILE_SHARE_WRITE
                | _WIN_FILE_SHARE_DELETE
            ),
        )
    except FileNotFoundError:
        return False
    try:
        info = _win_handle_information(handle)
        if info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_DIRECTORY:
            raise IsADirectoryError(name)
        _win_mark_delete(handle)
    finally:
        _win_close_handle(handle)
    return True


def rename_open_file(
    source_directory: OwnedDirectory,
    source_name: str,
    source_stream: BinaryIO,
    target_directory: OwnedDirectory,
    target_name: str,
) -> None:
    """Atomically rename an opened stage into a retained target directory."""

    _validate_leaf(source_name)
    _validate_leaf(target_name)
    if os.name == "nt":
        import msvcrt

        _win_rename_handle(
            msvcrt.get_osfhandle(source_stream.fileno()),
            target_directory.handle,
            target_name,
        )
        return
    os.replace(
        source_name,
        target_name,
        src_dir_fd=source_directory.handle,
        dst_dir_fd=target_directory.handle,
    )


def list_names(directory: OwnedDirectory) -> tuple[str, ...]:
    """Enumerate a retained directory without trusting a replaceable path."""

    if os.name != "nt":
        return tuple(os.listdir(directory.handle))
    _win_assert_path_identity(directory)
    names = tuple(item.name for item in os.scandir(directory.path))
    _win_assert_path_identity(directory)
    return names


def entry_kind(directory: OwnedDirectory, name: str) -> str:
    """Return REGULAR, DIRECTORY, or FORBIDDEN without following the entry."""

    _validate_leaf(name)
    if os.name == "nt":
        handle = _win_nt_open(
            directory.handle,
            name,
            desired_access=_WIN_GENERIC_READ | _WIN_SYNCHRONIZE,
            disposition=_WIN_FILE_OPEN,
            options=_WIN_FILE_OPEN_REPARSE_POINT | _WIN_FILE_SYNCHRONOUS_IO_NONALERT,
            share=(
                _WIN_FILE_SHARE_READ
                | _WIN_FILE_SHARE_WRITE
                | _WIN_FILE_SHARE_DELETE
            ),
        )
        try:
            info = _win_handle_information(handle)
            attributes = info.dwFileAttributes
            if attributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT:
                return "FORBIDDEN"
            if attributes & _WIN_FILE_ATTRIBUTE_DIRECTORY:
                return "DIRECTORY"
            return "REGULAR" if info.nNumberOfLinks == 1 else "FORBIDDEN"
        finally:
            _win_close_handle(handle)

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if hasattr(os, "O_PATH"):
        flags = os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory.handle)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return "FORBIDDEN"
        raise
    try:
        info = os.fstat(descriptor)
        if stat.S_ISLNK(info.st_mode):
            return "FORBIDDEN"
        if stat.S_ISDIR(info.st_mode):
            if info.st_dev != os.fstat(directory.handle).st_dev:
                return "FORBIDDEN"
            return "DIRECTORY"
        if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            return "REGULAR"
        return "FORBIDDEN"
    finally:
        os.close(descriptor)


def move_entry(
    source_directory: OwnedDirectory,
    source_name: str,
    target_directory: OwnedDirectory,
    target_name: str,
) -> None:
    """Move one entry between retained directories without following it."""

    _validate_leaf(source_name)
    _validate_leaf(target_name)
    if os.name != "nt":
        os.replace(
            source_name,
            target_name,
            src_dir_fd=source_directory.handle,
            dst_dir_fd=target_directory.handle,
        )
        return
    handle = _win_nt_open(
        source_directory.handle,
        source_name,
        desired_access=_WIN_DELETE | _WIN_GENERIC_READ | _WIN_SYNCHRONIZE,
        disposition=_WIN_FILE_OPEN,
        options=_WIN_FILE_OPEN_REPARSE_POINT | _WIN_FILE_SYNCHRONOUS_IO_NONALERT,
        share=(
            _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE | _WIN_FILE_SHARE_DELETE
        ),
    )
    try:
        _win_rename_handle(handle, target_directory.handle, target_name)
    finally:
        _win_close_handle(handle)


def fsync_directory(directory: OwnedDirectory) -> None:
    if os.name == "nt":
        _win_flush(directory.handle)
        return
    try:
        os.fsync(directory.handle)
    except OSError:
        pass


def _require_regular_stat(info: os.stat_result) -> None:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or attributes & reparse
    ):
        raise SecureFilesystemError(errno.EPERM, "regular file identity is ambiguous")


def _validate_leaf(name: str) -> None:
    if (
        type(name) is not str
        or not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
    ):
        raise SecureFilesystemError(errno.EINVAL, "secure filesystem name is not one leaf")


if os.name == "nt":
    import ctypes
    import ctypes.wintypes as wintypes

    _WIN_GENERIC_READ = 0x80000000
    _WIN_GENERIC_WRITE = 0x40000000
    _WIN_DELETE = 0x00010000
    _WIN_SYNCHRONIZE = 0x00100000
    _WIN_FILE_SHARE_READ = 0x00000001
    _WIN_FILE_SHARE_WRITE = 0x00000002
    _WIN_FILE_SHARE_DELETE = 0x00000004
    _WIN_FILE_OPEN = 1
    _WIN_FILE_CREATE = 2
    _WIN_FILE_OPEN_IF = 3
    _WIN_FILE_DIRECTORY_FILE = 0x00000001
    _WIN_FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    _WIN_FILE_NON_DIRECTORY_FILE = 0x00000040
    _WIN_FILE_OPEN_REPARSE_POINT = 0x00200000
    _WIN_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _WIN_FILE_ATTRIBUTE_NORMAL = 0x00000080
    _WIN_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _WIN_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _WIN_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _WIN_OPEN_EXISTING = 3
    _WIN_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _WinUnicodeString(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        ]

    class _WinObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(_WinUnicodeString)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        ]

    class _WinIoStatusBlock(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]

    class _WinByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    class _WinFileRenameInfo(ctypes.Structure):
        _fields_ = [
            ("ReplaceIfExists", wintypes.BOOL),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", wintypes.WCHAR * 1),
        ]

    class _WinFileDispositionInfo(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOL)]

    class _WinFileDispositionInfoEx(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD)]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")
    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _CreateFileW.restype = wintypes.HANDLE
    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL
    _GetFileInformationByHandle = _kernel32.GetFileInformationByHandle
    _GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_WinByHandleFileInformation),
    ]
    _GetFileInformationByHandle.restype = wintypes.BOOL
    _SetFileInformationByHandle = _kernel32.SetFileInformationByHandle
    _SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _SetFileInformationByHandle.restype = wintypes.BOOL
    _FlushFileBuffers = _kernel32.FlushFileBuffers
    _FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _FlushFileBuffers.restype = wintypes.BOOL
    _NtCreateFile = _ntdll.NtCreateFile
    _NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_WinObjectAttributes),
        ctypes.POINTER(_WinIoStatusBlock),
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
    ]
    _NtCreateFile.restype = ctypes.c_long
    _NtSetInformationFile = _ntdll.NtSetInformationFile
    _NtSetInformationFile.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_WinIoStatusBlock),
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.c_int,
    ]
    _NtSetInformationFile.restype = ctypes.c_long
    _RtlNtStatusToDosError = _ntdll.RtlNtStatusToDosError
    _RtlNtStatusToDosError.argtypes = [ctypes.c_long]
    _RtlNtStatusToDosError.restype = wintypes.ULONG

    def _win_open_absolute_directory(
        path: Path, *, create: bool = False
    ) -> OwnedDirectory:
        # The volume handle is the only absolute open. Every component after it
        # is opened relative to the still-retained parent handle.
        if len(path.drive) != 2 or path.drive[1] != ":" or path.anchor.startswith("\\\\"):
            raise SecureFilesystemError(
                errno.EPERM, "virtual roots require one local drive anchor"
            )
        anchor = Path(path.anchor)
        components = path.parts[1:]
        current_handle = _CreateFileW(
            str(anchor),
            _WIN_GENERIC_READ | _WIN_SYNCHRONIZE,
            _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE,
            None,
            _WIN_OPEN_EXISTING,
            _WIN_FILE_FLAG_BACKUP_SEMANTICS | _WIN_FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if current_handle == _WIN_INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            anchor_info = _win_handle_information(current_handle)
            _win_require_directory(anchor_info)
            for component in components:
                _validate_leaf(component)
                child_handle = _win_nt_open(
                    current_handle,
                    component,
                    desired_access=_WIN_GENERIC_READ | _WIN_SYNCHRONIZE,
                    disposition=_WIN_FILE_OPEN_IF if create else _WIN_FILE_OPEN,
                    options=(
                        _WIN_FILE_DIRECTORY_FILE
                        | _WIN_FILE_OPEN_REPARSE_POINT
                        | _WIN_FILE_SYNCHRONOUS_IO_NONALERT
                    ),
                    share=_WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE,
                )
                try:
                    child_info = _win_handle_information(child_handle)
                    _win_require_directory(child_info)
                except Exception:
                    _win_close_handle(child_handle)
                    raise
                _win_close_handle(current_handle)
                current_handle = child_handle
            final_info = _win_handle_information(current_handle)
            return OwnedDirectory(path, current_handle, _win_identity(final_info))
        except Exception:
            _win_close_handle(current_handle)
            raise

    def _win_nt_open(
        root_handle: int,
        name: str,
        *,
        desired_access: int,
        disposition: int,
        options: int,
        share: int,
    ) -> int:
        name_buffer = ctypes.create_unicode_buffer(name)
        name_bytes = len(name.encode("utf-16-le"))
        unicode_name = _WinUnicodeString(
            name_bytes,
            name_bytes + 2,
            ctypes.cast(name_buffer, wintypes.LPWSTR),
        )
        attributes = _WinObjectAttributes(
            ctypes.sizeof(_WinObjectAttributes),
            wintypes.HANDLE(root_handle),
            ctypes.pointer(unicode_name),
            0x40,  # OBJ_CASE_INSENSITIVE; internal names are collision checked.
            None,
            None,
        )
        io_status = _WinIoStatusBlock()
        result = wintypes.HANDLE()
        status = _NtCreateFile(
            ctypes.byref(result),
            desired_access,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            _WIN_FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            options,
            None,
            0,
        )
        if status < 0:
            code = int(_RtlNtStatusToDosError(status))
            if code in {2, 3}:
                raise FileNotFoundError(code, os.strerror(code), name)
            if code in {80, 183}:
                raise FileExistsError(code, os.strerror(code), name)
            raise OSError(code, os.strerror(code), name)
        return int(result.value)

    def _win_handle_information(handle: int) -> _WinByHandleFileInformation:
        info = _WinByHandleFileInformation()
        if not _GetFileInformationByHandle(wintypes.HANDLE(handle), ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        return info

    def _win_identity(info: _WinByHandleFileInformation) -> tuple[int, ...]:
        return (
            int(info.dwVolumeSerialNumber),
            int(info.nFileIndexHigh),
            int(info.nFileIndexLow),
        )

    def _win_require_directory(info: _WinByHandleFileInformation) -> None:
        if (
            not info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_DIRECTORY
            or info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise SecureFilesystemError(errno.EPERM, "directory is a reparse point")

    def _win_require_regular(info: _WinByHandleFileInformation) -> None:
        if (
            info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_DIRECTORY
            or info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT
            or info.nNumberOfLinks != 1
        ):
            raise SecureFilesystemError(errno.EPERM, "regular file identity is ambiguous")

    def _win_rename_handle(handle: int, target_root: int, target_name: str) -> None:
        encoded = target_name.encode("utf-16-le")
        offset = _WinFileRenameInfo.FileName.offset
        buffer = ctypes.create_string_buffer(offset + len(encoded))
        info = _WinFileRenameInfo.from_buffer(buffer)
        info.ReplaceIfExists = False
        info.RootDirectory = wintypes.HANDLE(target_root)
        info.FileNameLength = len(encoded)
        ctypes.memmove(ctypes.addressof(buffer) + offset, encoded, len(encoded))
        io_status = _WinIoStatusBlock()
        status = _NtSetInformationFile(
            wintypes.HANDLE(handle),
            ctypes.byref(io_status),
            buffer,
            len(buffer),
            10,  # FileRenameInformation
        )
        if status < 0:
            code = int(_RtlNtStatusToDosError(status))
            if code in {80, 183}:
                raise FileExistsError(code, os.strerror(code), target_name)
            raise OSError(code, os.strerror(code), target_name)

    def _win_mark_delete(handle: int) -> None:
        extended = _WinFileDispositionInfoEx(0x1 | 0x2)  # DELETE | POSIX_SEMANTICS
        if _SetFileInformationByHandle(
            wintypes.HANDLE(handle),
            21,  # FileDispositionInfoEx
            ctypes.byref(extended),
            ctypes.sizeof(extended),
        ):
            return
        info = _WinFileDispositionInfo(True)
        if not _SetFileInformationByHandle(
            wintypes.HANDLE(handle),
            4,  # FileDispositionInfo
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

    def _win_assert_path_identity(directory: OwnedDirectory) -> None:
        current = _win_open_absolute_directory(directory.path)
        try:
            if current.identity != directory.identity:
                raise SecureFilesystemError(errno.EPERM, "directory path identity changed")
        finally:
            current.close()

    def _win_flush(handle: int) -> None:
        if not _FlushFileBuffers(wintypes.HANDLE(handle)):
            error = ctypes.get_last_error()
            # This helper is called only with an OwnedDirectory whose identity
            # was already verified. Windows commonly rejects directory flushes
            # with ACCESS_DENIED even though file fsync and handle-relative
            # rename remain supported.
            if error not in {1, 5, 6, 50}:
                raise ctypes.WinError(error)

    def _win_close_handle(handle: int) -> None:
        if handle and handle != _WIN_INVALID_HANDLE_VALUE:
            _CloseHandle(wintypes.HANDLE(handle))

else:
    def _win_close_handle(handle: int) -> None:  # pragma: no cover - platform guard
        raise AssertionError(handle)
