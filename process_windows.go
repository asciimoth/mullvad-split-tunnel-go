//go:build windows && (amd64 || arm64)

package splittunnel

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ResolveDevicePath resolves an existing executable using a file handle, so
// junctions and volume mappings are resolved by Windows instead of guessed by
// string replacement. This starter accepts absolute local drive-letter paths
// (including the extended prefix), rejects directories, and does not support
// UNC/network executable paths. The result is an exact path, not a file identity:
// future renames, hard links, replacements, or remounts need caller monitoring.
func ResolveDevicePath(path string) (string, error) {
	check := strings.TrimPrefix(path, "\\\\?\\")
	if len(check) < 3 || check[1] != ':' ||
		!((check[0] >= 'A' && check[0] <= 'Z') || (check[0] >= 'a' && check[0] <= 'z')) ||
		(check[2] != '\\' && check[2] != '/') || !filepath.IsAbs(path) ||
		strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("%w: expected an absolute local drive-letter path", ErrInvalidArgument)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return "", err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return "", fmt.Errorf("%w: executable path refers to a directory", ErrInvalidArgument)
	}
	const volumeNameNT = 2
	for size := uint32(260); size <= 32768; {
		buf := make([]uint16, size)
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], size, volumeNameNT)
		if err != nil {
			return "", err
		}
		if n >= size {
			if n >= 32768 {
				break
			}
			size = n + 1
			continue
		}
		result := windows.UTF16ToString(buf[:n])
		lower := strings.ToLower(result)
		if strings.HasPrefix(lower, "\\device\\mup\\") ||
			strings.HasPrefix(lower, "\\device\\lanmanredirector\\") {
			return "", fmt.Errorf("%w: network executable paths are unsupported", ErrInvalidArgument)
		}
		if _, err := encodePath(result, false); err != nil {
			return "", err
		}
		return result, nil
	}
	return "", fmt.Errorf("%w: resolved path exceeds driver length limit", ErrInvalidArgument)
}

// SnapshotProcesses obtains a Toolhelp process list and native image paths.
// Call after driver Initialize. Unqueryable processes remain in the snapshot
// with empty metadata and a warning. PID zero (the idle process) is omitted.
// Parent references that cannot be verified by creation times are cleared.
func SnapshotProcesses() (Snapshot, error) {
	var out Snapshot
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out, err
	}
	defer windows.CloseHandle(h)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	err = windows.Process32First(h, &entry)
	for err == nil {
		if entry.ProcessID != 0 {
			p := Process{PID: entry.ProcessID, ParentPID: entry.ParentProcessID}
			out.Warnings = append(out.Warnings, enrichProcess(&p)...)
			out.Processes = append(out.Processes, p)
		}
		if len(out.Processes) > maxRecords {
			return Snapshot{}, fmt.Errorf("%w: process snapshot exceeds record limit", ErrInvalidArgument)
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		err = windows.Process32Next(h, &entry)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return Snapshot{}, err
	}
	out.Processes = normalizeSnapshot(out.Processes)
	if len(out.Processes) == 0 {
		return Snapshot{}, fmt.Errorf("%w: empty process snapshot", ErrInvalidArgument)
	}
	return out, nil
}

func enrichProcess(p *Process) []ProcessWarning {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.PID)
	if err != nil {
		return []ProcessWarning{{p.PID, "OpenProcess", err}}
	}
	defer windows.CloseHandle(h)
	var warnings []ProcessWarning
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		warnings = append(warnings, ProcessWarning{p.PID, "GetProcessTimes", err})
	} else {
		p.CreationTime = uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	}
	p.ImagePath, err = processDevicePath(h)
	if err != nil {
		warnings = append(warnings, ProcessWarning{p.PID, "QueryFullProcessImageName", err})
	}
	return warnings
}

func processDevicePath(h windows.Handle) (string, error) {
	const processNameNative = 1
	for size := uint32(260); ; {
		buf := make([]uint16, size)
		n := size
		err := windows.QueryFullProcessImageName(h, processNameNative, &buf[0], &n)
		if err == nil {
			result := windows.UTF16ToString(buf[:n])
			if _, err := encodePath(result, false); err != nil {
				return "", err
			}
			return result, nil
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || size == 32768 {
			return "", err
		}
		size *= 2
		if size > 32768 {
			size = 32768
		}
	}
}
