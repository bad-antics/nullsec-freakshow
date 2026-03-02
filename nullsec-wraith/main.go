package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const version = "1.0.0"

type PortResult struct {
	Port     int    `json:"port"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Latency  string `json:"latency,omitempty"`
}

type ScanResult struct {
	Host      string       `json:"host"`
	Timestamp string       `json:"timestamp"`
	OpenPorts []PortResult `json:"open_ports"`
	Duration  string       `json:"duration"`
}

var commonServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
	143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
	1080: "socks", 1433: "mssql", 1521: "oracle", 2049: "nfs",
	3306: "mysql", 3389: "rdp", 4444: "metasploit", 5432: "postgres",
	5900: "vnc", 6379: "redis", 6667: "irc", 8080: "http-proxy",
	8443: "https-alt", 8888: "http-alt", 9090: "web-mgmt",
	9200: "elasticsearch", 27017: "mongodb",
}

// Suspicious ephemeral / backdoor ports
var suspiciousPorts = map[int]string{
	4444: "metasploit-default", 4445: "metasploit-alt",
	5555: "adb-debug", 1337: "leet-backdoor",
	31337: "back-orifice", 12345: "netbus",
	65535: "high-port-backdoor", 54321: "reverse-shell-common",
	9001: "tor-relay", 6660: "irc-backdoor",
	8291: "mikrotik-winbox", 2222: "alt-ssh",
}

func scanPort(host string, port int, timeout time.Duration) *PortResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	elapsed := time.Since(start)

	if err != nil {
		return nil
	}
	conn.Close()

	result := &PortResult{
		Port:    port,
		State:   "open",
		Latency: elapsed.Round(time.Millisecond).String(),
	}

	if svc, ok := commonServices[port]; ok {
		result.Service = svc
	}
	if susp, ok := suspiciousPorts[port]; ok {
		result.Service = "⚠️ " + susp
	}

	return result
}

func ghostScan(host string, startPort, endPort int, timeout time.Duration, workers int) ScanResult {
	start := time.Now()
	result := ScanResult{
		Host:      host,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	ports := make(chan int, workers)
	var results []PortResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				if pr := scanPort(host, port, timeout); pr != nil {
					mu.Lock()
					results = append(results, *pr)
					mu.Unlock()
				}
			}
		}()
	}

	for p := startPort; p <= endPort; p++ {
		ports <- p
	}
	close(ports)
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	result.OpenPorts = results
	result.Duration = time.Since(start).Round(time.Millisecond).String()
	return result
}

func hauntScan(host string, interval time.Duration, rounds int, timeout time.Duration) {
	fmt.Printf("\n👻 WRAITH — Ephemeral Port Hunter\n")
	fmt.Printf("   Target: %s | Interval: %s | Rounds: %d\n\n", host, interval, rounds)

	portSets := make([]map[int]bool, 0, rounds)

	for r := 0; r < rounds; r++ {
		fmt.Printf("  ⏳ Round %d/%d scanning...", r+1, rounds)
		scan := ghostScan(host, 1, 1024, timeout, 200)
		current := make(map[int]bool)
		for _, p := range scan.OpenPorts {
			current[p.Port] = true
		}
		portSets = append(portSets, current)
		fmt.Printf(" %d open ports\n", len(current))

		if r > 0 {
			prev := portSets[r-1]
			// Appeared
			for p := range current {
				if !prev[p] {
					svc := commonServices[p]
					if s, ok := suspiciousPorts[p]; ok {
						svc = "⚠️ " + s
					}
					fmt.Printf("    👻 APPEARED: port %d (%s)\n", p, svc)
				}
			}
			// Disappeared
			for p := range prev {
				if !current[p] {
					svc := commonServices[p]
					fmt.Printf("    💨 VANISHED: port %d (%s)\n", p, svc)
				}
			}
		}

		if r < rounds-1 {
			time.Sleep(interval)
		}
	}
	fmt.Println()
}

func printUsage() {
	fmt.Printf(`
👻 nullsec-wraith v%s — Ephemeral Port Scanner (Go)
   Part of the nullsec freakshow suite.

Usage:
  wraith scan <host> [port-range]     Scan ports on a host
  wraith haunt <host> [rounds]        Multi-round scan to detect ephemeral ports
  wraith --json scan <host>           JSON output mode

Examples:
  wraith scan 192.168.1.1             Scan common ports
  wraith scan 10.0.0.1 1-65535        Full port scan
  wraith haunt 192.168.1.1 5          5 rounds of scanning for port changes
  wraith --json scan localhost        JSON output

`, version)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printUsage()
		return
	}

	jsonMode := false
	filtered := make([]string, 0)
	for _, a := range args {
		if a == "--json" {
			jsonMode = true
		} else if a == "--help" || a == "-h" {
			printUsage()
			return
		} else {
			filtered = append(filtered, a)
		}
	}
	args = filtered

	if len(args) < 2 {
		printUsage()
		return
	}

	cmd := args[0]
	host := args[1]
	timeout := 800 * time.Millisecond

	switch cmd {
	case "scan":
		startPort, endPort := 1, 1024
		if len(args) >= 3 {
			parts := strings.Split(args[2], "-")
			if len(parts) == 2 {
				s, _ := strconv.Atoi(parts[0])
				e, _ := strconv.Atoi(parts[1])
				if s > 0 {
					startPort = s
				}
				if e > 0 {
					endPort = e
				}
			}
		}

		if !jsonMode {
			fmt.Printf("\n👻 WRAITH — Ephemeral Port Scanner\n")
			fmt.Printf("   Target: %s | Range: %d-%d\n\n", host, startPort, endPort)
		}

		result := ghostScan(host, startPort, endPort, timeout, 200)

		if jsonMode {
			out, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(out))
		} else {
			if len(result.OpenPorts) == 0 {
				fmt.Println("  💨 No open ports found — the wraith saw nothing.")
			} else {
				fmt.Printf("  🔓 %d open ports found in %s:\n\n", len(result.OpenPorts), result.Duration)
				for _, p := range result.OpenPorts {
					svc := p.Service
					if svc == "" {
						svc = "unknown"
					}
					suspicious := ""
					if _, ok := suspiciousPorts[p.Port]; ok {
						suspicious = " ← SUSPICIOUS"
					}
					fmt.Printf("    %-6d %-20s %s%s\n", p.Port, svc, p.Latency, suspicious)
				}
			}
			fmt.Println()
		}

	case "haunt":
		rounds := 3
		if len(args) >= 3 {
			if r, err := strconv.Atoi(args[2]); err == nil && r > 0 {
				rounds = r
			}
		}
		hauntScan(host, 10*time.Second, rounds, timeout)

	default:
		printUsage()
	}
}
