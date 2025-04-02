//go:build windows
// +build windows

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
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

// Структура для хранения информации о соединении
type Connection struct {
	State       uint32
	LocalAddr   string
	LocalPort   uint16
	RemoteAddr  string
	RemotePort  uint16
	PID         uint32
	ProcessName string
}

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
	took := time.Since(start)
	fmt.Printf("Execution took %v : \n", took)

	if err != nil {
		fmt.Printf("failed err = %v\n", err)
		return
	}

	if res == nil || len(res) < 4 {
		fmt.Println("nil result!")
		return
	}

	fmt.Printf("result len=%d dump:\n%s\n", len(res), hex.Dump(res))
	count := *(*uint32)(unsafe.Pointer(&res[0]))
	const structLen = 24

	var connections []Connection

	// Обрабатываем результаты
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
		processName := getProcessName(pid)

		connections = append(connections, Connection{
			State:       state,
			LocalAddr:   ipToString(laddr),
			LocalPort:   lport,
			RemoteAddr:  ipToString(raddr),
			RemotePort:  rport,
			PID:         pid,
			ProcessName: processName,
		})
	}

	// Сортируем соединения по имени процесса
	sort.Slice(connections, func(i, j int) bool {
		return connections[i].ProcessName < connections[j].ProcessName
	})

	// Выводим результат
	for n, conn := range connections {
		fmt.Printf("%5d = %d %s:%d %s:%d pid:%d (%s)\n",
			n, conn.State, conn.LocalAddr, conn.LocalPort, conn.RemoteAddr, conn.RemotePort, conn.PID, conn.ProcessName)
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

func getProcessName(pid uint32) string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return "Unknown"
	}
	defer windows.CloseHandle(handle)

	var buf [windows.MAX_PATH]uint16
	err = windows.GetModuleBaseName(handle, 0, &buf[0], uint32(len(buf)))
	if err != nil {
		return "Unknown"
	}
	return syscall.UTF16ToString(buf[:])
}

// Преобразует uint32 IP в строку IPv4
func ipToString(ip uint32) string {
	ipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ipBytes, ip)
	return net.IP(ipBytes).String()
}
