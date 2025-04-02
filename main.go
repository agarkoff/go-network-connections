package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	iphlpapiDll         = "iphlpapi.dll"
	tcpFn               = "GetExtendedTcpTable"
	tcpTableOwnerPidAll = 5
)

// Карта для перевода числового состояния соединения в строковую константу
var tcpStateMap = map[uint32]string{
	1:  "CLOSED",
	2:  "LISTEN",
	3:  "SYN_SENT",
	4:  "SYN_RECEIVED",
	5:  "ESTABLISHED",
	6:  "FIN_WAIT_1",
	7:  "FIN_WAIT_2",
	8:  "CLOSE_WAIT",
	9:  "CLOSING",
	10: "LAST_ACK",
	11: "TIME_WAIT",
	12: "DELETE_TCB",
}

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
	// Добавляем аргумент командной строки для выбора метода сортировки
	sortBy := flag.String("sort", "process", "Sorting method: 'process' or 'ip'")
	flag.Parse()

	moduleHandle, err := windows.LoadLibrary(iphlpapiDll)
	if err != nil {
		fmt.Println("Failed to load library:", err)
		os.Exit(1)
	}

	ptr, err := windows.GetProcAddress(moduleHandle, tcpFn)
	if err != nil {
		fmt.Println("Failed to get function address:", err)
		os.Exit(1)
	}

	start := time.Now()
	res, err := getNetTable(ptr, false, windows.AF_INET, tcpTableOwnerPidAll)
	took := time.Since(start)
	fmt.Printf("Execution took %v : \n", took)

	if err != nil {
		fmt.Printf("Failed to get net table: %v\n", err)
		return
	}

	if res == nil || len(res) < 4 {
		fmt.Println("No results!")
		return
	}

	fmt.Printf("Result len=%d dump:\n%s\n", len(res), hex.Dump(res))
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

	// Выбираем метод сортировки
	if *sortBy == "ip" {
		fmt.Println("Sorting by local IP and port...")
		sort.Slice(connections, func(i, j int) bool {
			if connections[i].LocalAddr == connections[j].LocalAddr {
				return connections[i].LocalPort < connections[j].LocalPort
			}
			return connections[i].LocalAddr < connections[j].LocalAddr
		})
	} else {
		fmt.Println("Sorting by process name (default)...")
		sort.Slice(connections, func(i, j int) bool {
			pi, pj := connections[i].ProcessName, connections[j].ProcessName

			if pi == "Unknown" {
				return false
			}
			if pj == "Unknown" {
				return true
			}
			return strings.ToLower(pi) < strings.ToLower(pj)
		})
	}

	// Выводим результат
	fmt.Printf("%5s  %-12s  %-15s  %6s  %-15s  %6s  %5s  %-20s\n",
		"#", "State", "Local Address", "LPort", "Remote Address", "RPort", "PID", "Process")

	for n, conn := range connections {
		stateStr := tcpStateMap[conn.State] // Получаем строковое представление состояния
		fmt.Printf("%5d  %-12s  %-15s  %6d  %-15s  %6d  %5d  %-20s\n",
			n, stateStr, conn.LocalAddr, conn.LocalPort, conn.RemoteAddr, conn.RemotePort, conn.PID, conn.ProcessName)
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
			fmt.Printf("Reallocating to %d bytes", size)
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
