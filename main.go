//go:build window
// +build windows

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	iphlpapiDll         = "iphlpapi.dll"
	tcpFn               = "GetExtendedTcpTable"
	udpFn               = "GetExtendedUdpTable"
	tcpTableOwnerPidAll = 5
)

func main() {

	moduleHandle, err := windows.LoadLibrary(iphlpapiDll)
	if err != nil {
		panic(err)
	}

	ptr, err := windows.GetProcAddress(moduleHandle, tcpFn)
	if err != nil {
		panic(err)
	}

	start := time.Now()
	res, err := getNetTable(ptr, false, windows.AF_INET, tcpTableOwnerPidAll)
	took := time.Now().Sub(start)
	fmt.Printf("Execution took %v : ", took)
	if err == nil {
		if res != nil && len(res) >= 4 {
			fmt.Printf("result len=%d dump:\n%s\n", len(res), hex.Dump(res))
			count := *(*uint32)(unsafe.Pointer(&res[0]))
			const structLen = 24
			for n, pos := uint32(0), 4; n < count && pos+structLen <= len(res); n, pos = n+1, pos+structLen {
				state := *(*uint32)(unsafe.Pointer(&res[pos]))
				if state < 1 || state > 12 {
					panic(state)
				}
				laddr := binary.BigEndian.Uint32(res[pos+4 : pos+8])
				lport := binary.BigEndian.Uint16(res[pos+8 : pos+10])
				raddr := binary.BigEndian.Uint32(res[pos+12 : pos+16])
				rport := binary.BigEndian.Uint16(res[pos+16 : pos+18])
				pid := *(*uint32)(unsafe.Pointer(&res[pos+20]))
				fmt.Printf("%5d = %d %08x:%d %08x:%d pid:%d\n", n, state, laddr, lport, raddr, rport, pid)
			}
		} else {
			fmt.Printf("nil result!\n")
		}
	} else {
		fmt.Printf("failed err = %v\n", err)
	}
}

func getNetTable(fn uintptr, order bool, family int, class int) ([]byte, error) {
	var sorted uintptr
	if order {
		sorted = 1
	}
	for size, ptr, addr := uint32(8), []byte(nil), uintptr(0); ; {
		err, _, _ := syscall.Syscall6(fn, 5, addr, uintptr(unsafe.Pointer(&size)), sorted, uintptr(family), uintptr(class), 0)
		if err == 0 {
			return ptr, nil
		} else if err == uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
			fmt.Printf("realloc to %d bytes", size)
			ptr = make([]byte, size)
			addr = uintptr(unsafe.Pointer(&ptr[0]))
		} else {
			return nil, fmt.Errorf("getNetTable failed: %v", err)
		}
	}
}
