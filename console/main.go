package main

import (
	"bufio"
	bytebuf "bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/covertdtls"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/event"
	sf "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/proxy/lib"
	"golang.org/x/sys/windows"
)

type Snapshot struct {
	Active       int          `json:"active"`
	Connections  int64        `json:"connections"`
	Failed       int64        `json:"failed"`
	InBytes      int64        `json:"download_bytes"`
	OutBytes     int64        `json:"upload_bytes"`
	NAT          string       `json:"nat"`
	Closed       int64        `json:"closed"`
	LastDuration float64      `json:"last_duration_seconds"`
	MaxDuration  float64      `json:"max_duration_seconds"`
	RelayChecked bool         `json:"relay_checked"`
	RelayReady   bool         `json:"relay_ready"`
	ChannelTest  ChannelTest  `json:"channel_test"`
	CountryCheck CountryCheck `json:"country_check"`
}
type Collector struct {
	sync.Mutex
	state       Snapshot
	vpnIP       net.IP
	paths       []event.EventOnProxyPeerPath
	pathWarning string
}

func (c *Collector) OnNewSnowflakeEvent(e event.SnowflakeEvent) {
	c.Lock()
	defer c.Unlock()
	switch v := e.(type) {
	case event.EventOnProxyPeerPath:
		if len(c.paths) >= 32 {
			c.paths = c.paths[1:]
		}
		c.paths = append(c.paths, v)
		c.checkPeerPaths()
	case event.EventOnProxyRelayStatus:
		c.state.RelayChecked = true
		c.state.RelayReady = v.Ready
	case event.EventOnProxyClientConnected:
		c.state.Active++
		c.state.Connections++
	case event.EventOnProxyConnectionOver:
		c.state.Closed++
		c.state.LastDuration = v.Duration.Seconds()
		c.state.MaxDuration = max(c.state.MaxDuration, c.state.LastDuration)
		if c.state.Active > 0 {
			c.state.Active--
		}
	case event.EventOnProxyConnectionFailed:
		c.state.Failed++
	case event.EventOnCurrentNATTypeDetermined:
		c.state.NAT = v.CurNATType
	case event.EventOnProxyStats:
		c.state.InBytes += v.RawInboundBytes
		c.state.OutBytes += v.RawOutboundBytes
	}
}
func (c *Collector) snapshot() Snapshot {
	c.Lock()
	defer c.Unlock()
	s := c.state
	if c.pathWarning != "" {
		s.CountryCheck.Warning = c.pathWarning
		s.CountryCheck.Checked = time.Now().Format(time.RFC3339)
	}
	return s
}
func worker(capacity int, root string, recheckCountry bool) error {
	log.SetOutput(io.Discard)
	vpn, err := installVPN(root)
	if err != nil {
		return err
	}
	d := event.NewSnowflakeEventDispatcher()
	c := &Collector{state: Snapshot{NAT: "checking"}, vpnIP: vpn.ip}
	d.AddSnowflakeEventListener(c)
	var outputLock sync.Mutex
	emit := func() {
		outputLock.Lock()
		defer outputLock.Unlock()
		if json.NewEncoder(os.Stdout).Encode(c.snapshot()) != nil {
			os.Exit(1)
		}
	}
	block := func(reason string) {
		c.Lock()
		c.state.CountryCheck.Warning = reason
		c.state.CountryCheck.Checked = time.Now().Format(time.RFC3339)
		c.Unlock()
		emit()
	}
	fail := func(reason string) { block(reason); fmt.Fprintln(os.Stderr, reason); os.Exit(2) }
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			emit()
		}
	}()
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			if err := vpn.alive(); err != nil {
				fail("Proxy stopped: VPN interface or route disappeared")
			}
			c.Lock()
			warning := c.pathWarning
			c.Unlock()
			if warning != "" {
				fail(warning)
			}
		}
	}()
	if recheckCountry {
		result := checkCountries(vpn)
		c.setCountryCheck(result)
		if reason := proxyBlockReason(result, ""); reason != "" {
			block(reason)
			return fmt.Errorf("%s", reason)
		}
		if !countryRecoveryPassed(result) {
			reason := "Exit-country recheck incomplete; waiting to retry"
			block(reason)
			return fmt.Errorf("%s", reason)
		}
	}
	go func() {
		startCountry := ""
		for {
			started := time.Now()
			result := checkCountries(vpn)
			if reason := proxyBlockReason(result, startCountry); reason != "" {
				c.setCountryCheck(result)
				fail(reason)
			}
			c.setCountryCheck(result)
			if startCountry == "" && result.Verified {
				startCountry = result.DirectCountry
			}
			time.Sleep(max(0, time.Until(started.Add(countryCheckInterval))))
		}
	}()
	go func() {
		client := &http.Client{Timeout: 16 * time.Second}
		for {
			next := time.Now().Add(randomTestInterval())
			testChannel(client, publicTargets, func(s ChannelTest) { s.Next = next.Format(time.RFC3339); c.setChannelTest(s) })
			time.Sleep(max(0, time.Until(next)))
		}
	}()
	cfg, err := covertdtls.ParseCovertDTLSConfigString("randomizemimic")
	if err != nil {
		return err
	}
	p := sf.SnowflakeProxy{Capacity: uint(capacity), EventDispatcher: d, SummaryInterval: time.Second, RequireKnownNAT: true,
		Interface: vpn.name, NetworkTransport: vpn, NATTypeMeasurementInterval: 5 * time.Minute,
		RelayDomainNamePattern: "snowflake.torproject.net$", CovertDTLSConfig: cfg}
	return p.Start()
}

type Saved struct {
	Capacity    int   `json:"capacity"`
	Connections int64 `json:"connections"`
	InBytes     int64 `json:"download_bytes"`
	OutBytes    int64 `json:"upload_bytes"`
}
type Status struct {
	Snapshot
	Capacity     int     `json:"capacity"`
	PID          int     `json:"pid"`
	Updated      string  `json:"updated"`
	Running      bool    `json:"running"`
	DownloadRate float64 `json:"download_bytes_per_second"`
	UploadRate   float64 `json:"upload_bytes_per_second"`
	Error        string  `json:"error,omitempty"`
	VPN          string  `json:"vpn_interface"`
	Waiting      bool    `json:"waiting_for_vpn"`
}
type child struct {
	cmd     *exec.Cmd
	done    chan error
	updates chan Snapshot
}

func startChild(exe, root string, limit int, job windows.Handle, recheckCountry bool) (*child, error) {
	cmd := exec.Command(exe, "-worker", "-capacity", strconv.Itoa(limit))
	if recheckCountry {
		cmd.Args = append(cmd.Args, "-recheck-country")
	}
	cmd.Dir = root
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var errorText bytebuf.Buffer
	cmd.Stderr = &errorText
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, h)
		windows.CloseHandle(h)
	}
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, fmt.Errorf("job: %w", err)
	}
	c := &child{cmd: cmd, done: make(chan error, 1), updates: make(chan Snapshot, 4)}
	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			var s Snapshot
			if json.Unmarshal(scanner.Bytes(), &s) == nil {
				select {
				case c.updates <- s:
				default:
				}
			}
		}
		err := cmd.Wait()
		if err != nil && errorText.Len() > 0 {
			err = fmt.Errorf("%w: %s", err, strings.TrimSpace(errorText.String()))
		}
		c.done <- err
	}()
	return c, nil
}
func stopChild(c *child) {
	if c != nil {
		if c.done == nil {
			return
		}
		c.cmd.Process.Kill()
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
		}
	}
}
func validLimit(s string) (int, error) {
	n, e := strconv.Atoi(strings.TrimSpace(s))
	if e != nil || n < 1 || n > 1000 {
		return 0, fmt.Errorf("Enter a number from 1 to 1000")
	}
	return n, nil
}
func addSnapshot(saved *Saved, prev *Snapshot, next Snapshot) {
	saved.Connections += max(0, next.Connections-prev.Connections)
	saved.InBytes += max(0, next.InBytes-prev.InBytes)
	saved.OutBytes += max(0, next.OutBytes-prev.OutBytes)
	*prev = next
}
func bytes(v float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}
func bar(n, limit int) string {
	filled := 0
	if limit > 0 {
		filled = min(30, n*30/limit)
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", 30-filled) + "]"
}
func setupConsole() {
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	kernel.NewProc("SetConsoleOutputCP").Call(65001)
	title, _ := windows.UTF16PtrFromString("Snowflake")
	kernel.NewProc("SetConsoleTitleW").Call(uintptr(unsafe.Pointer(title)))
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) == nil {
		windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
}
func keys(ch chan<- rune) {
	get := windows.NewLazySystemDLL("msvcrt.dll").NewProc("_getwch")
	for {
		r, _, _ := get.Call()
		if r == 0 || r == 224 {
			get.Call()
			continue
		}
		ch <- rune(r)
	}
}
func render(s Status, saved Saved, start time.Time, editing bool, input, note string) {
	nat := s.NAT
	if nat == "checking" || nat == "" {
		nat = "checking"
	}
	state := "RUNNING"
	if s.Active == 0 {
		state = "WAITING FOR USERS"
	}
	if !s.RelayChecked {
		state = "CHECKING CONNECTIVITY"
	} else if !s.RelayReady {
		state = "RELAY UNAVAILABLE; WAITING TO RETRY"
	}
	if !s.Running {
		state = "STOPPED"
	}
	if s.Error != "" {
		state = "ERROR"
	}
	if s.Waiting {
		state = "WAITING FOR VPN / AUTOMATIC RECHECK"
	}
	prompt := "L - capacity   |   Auto channel test: 40-60 s   |   Q - quit"
	if editing {
		prompt = "New capacity (1-1000): " + input + "_   Enter - apply, Esc - cancel"
	}
	googleLine, speedLine := channelLines(s.ChannelTest)
	lines := []string{
		"  SNOWFLAKE",
		"  " + strings.Repeat("─", 65),
		fmt.Sprintf("  %s   |   Uptime: %s", state, time.Since(start).Truncate(time.Second)),
		fmt.Sprintf("  Connected now: %d / %d   %s", s.Active, s.Capacity, bar(s.Active, s.Capacity)),
		"",
		fmt.Sprintf("  To users   ↓  %s/s", bytes(s.DownloadRate)),
		fmt.Sprintf("  From users  ↑  %s/s", bytes(s.UploadRate)),
		fmt.Sprintf("  Total relayed:  ↓ %s    ↑ %s", bytes(float64(saved.InBytes)), bytes(float64(saved.OutBytes))),
		fmt.Sprintf("  NAT: %s   |   Failed attempts this session: %d", nat, s.Failed),
		"  VPN tunnel: " + s.VPN + "  |  Proxy traffic: VPN only",
		countryLine(s.CountryCheck),
		googleLine, speedLine,
		"  Recommended: enable your VPN's kill switch.",
		"",
		"  " + prompt, "  " + note,
	}
	fmt.Print("\x1b[H")
	for _, line := range lines {
		fmt.Print("\x1b[2K", line, "\r\n")
	}
	fmt.Print("\x1b[J")
}
func run() error {
	isWorker := flag.Bool("worker", false, "")
	capacity := flag.Int("capacity", 0, "maximum simultaneous clients")
	headless := flag.Bool("headless", false, "run without interactive screen")
	duration := flag.Duration("duration", 0, "optional run duration")
	checkVPN := flag.Bool("check-vpn", false, "verify pinned VPN transport")
	checkCountry := flag.Bool("check-countries", false, "check VPN and direct exit countries")
	recheckCountry := flag.Bool("recheck-country", false, "require a successful exit-country recheck before recovery")
	flag.Parse()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	root := filepath.Dir(exe)
	if *checkCountry {
		v, e := installVPN(root)
		if e != nil {
			return e
		}
		s := checkCountries(v)
		fmt.Println(countryLine(s))
		fmt.Printf("Verified: %t; incomplete checks: %s\n", s.Verified, s.Error)
		return nil
	}
	if *checkVPN {
		v, e := installVPN(root)
		if e != nil {
			return e
		}
		client := &http.Client{Timeout: 25 * time.Second}
		resp, e := client.Get("https://snowflake-broker.torproject.net/")
		if e != nil {
			return e
		}
		resp.Body.Close()
		fmt.Printf("VPN-only OK: %s, broker HTTP %d\n", v.name, resp.StatusCode)
		ws, resp, e := websocket.DefaultDialer.Dial(sf.DefaultRelayURL, nil)
		if e != nil {
			return fmt.Errorf("WebSocket relay check: %w", e)
		}
		defer ws.Close()
		fmt.Printf("Relay WebSocket HTTP %d\n", resp.StatusCode)
		return nil
	}
	if *isWorker {
		return worker(*capacity, root, *recheckCountry)
	}
	name, _ := windows.UTF16PtrFromString("Local\\SnowflakeAutomationConsole")
	mutex, err := windows.CreateMutex(nil, false, name)
	if mutex != 0 {
		defer windows.CloseHandle(mutex)
	}
	if err != nil {
		return fmt.Errorf("application already running or unavailable: %w", err)
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(job)
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return err
	}
	saved := Saved{Capacity: 10}
	if *capacity != 0 {
		saved.Capacity = *capacity
	}
	if _, err = validLimit(strconv.Itoa(saved.Capacity)); err != nil {
		return err
	}
	c := &child{}
	defer func() { stopChild(c) }()
	status := Status{Capacity: saved.Capacity, PID: os.Getpid(), Waiting: true, VPN: "not detected"}
	status.NAT = "checking"
	var prev Snapshot
	started := time.Now()
	lastSample := time.Now()
	note := ""
	input := ""
	editing := false
	keyCh := make(chan rune, 16)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if !*headless {
		setupConsole()
		fmt.Print("\x1b[2J\x1b[?25l")
		defer fmt.Print("\x1b[?25h\r\n")
		go keys(keyCh)
	}
	refreshStatus := func() {
		status.Updated = time.Now().Format(time.RFC3339)
	}
	nextRetry := time.Now()
	mustRecheckCountry := false
	tryStart := func() {
		cfg, e := loadVPN(root)
		if e != nil {
			status.Waiting = true
			status.Running = false
			note = "Waiting for a VPN tunnel. Retrying automatically."
			nextRetry = time.Now().Add(5 * time.Second)
			return
		}
		startedChild, e := startChild(exe, root, saved.Capacity, job, mustRecheckCountry)
		if e != nil {
			status.Waiting = true
			status.Running = false
			note = "Unable to start proxy. Retrying automatically."
			nextRetry = time.Now().Add(15 * time.Second)
			return
		}
		c = startedChild
		prev = Snapshot{}
		lastSample = time.Now()
		status = Status{Capacity: saved.Capacity, PID: os.Getpid(), Running: true, VPN: cfg.Interface}
		status.NAT = "checking"
		note = ""
	}
	defer func() {
		status.Running = false
		status.Active = 0
		status.DownloadRate = 0
		status.UploadRate = 0
		refreshStatus()
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var deadline <-chan time.Time
	if *duration > 0 {
		timer := time.NewTimer(*duration)
		defer timer.Stop()
		deadline = timer.C
	}
	tryStart()
	refreshStatus()
	for {
		if !*headless {
			render(status, saved, started, editing, input, note)
		}
		select {
		case <-signals:
			return nil
		case <-deadline:
			return nil
		case e := <-c.done:
			status.Running = false
			status.Active = 0
			status.DownloadRate = 0
			status.UploadRate = 0
			status.Error = fmt.Sprintf("Proxy exited: %v", e)
			status.CountryCheck.Warning = status.Error
			status.CountryCheck.Checked = time.Now().Format(time.RFC3339)
			note = status.Error
			status.Waiting = true
			mustRecheckCountry = mustRecheckCountry || needsCountryRecheck(status.Error)
			nextRetry = time.Now().Add(15 * time.Second)
			refreshStatus()
			c.done = nil
			c.updates = nil
		case s := <-c.updates:
			elapsed := time.Since(lastSample).Seconds()
			status.DownloadRate = float64(max(0, s.InBytes-prev.InBytes)) / elapsed
			status.UploadRate = float64(max(0, s.OutBytes-prev.OutBytes)) / elapsed
			addSnapshot(&saved, &prev, s)
			status.Snapshot = s
			if s.RelayReady && s.NAT != "checking" {
				mustRecheckCountry = false
			}
			lastSample = time.Now()
			refreshStatus()
		case <-tick.C:
			if c.done == nil && !time.Now().Before(nextRetry) {
				tryStart()
			}
			refreshStatus()
		case key := <-keyCh:
			if editing {
				switch {
				case key == 27:
					editing = false
				case key == 8:
					if len(input) > 0 {
						input = input[:len(input)-1]
					}
				case key >= '0' && key <= '9':
					if len(input) < 4 {
						input += string(key)
					}
				case key == 13:
					limit, e := validLimit(input)
					if e != nil {
						note = e.Error()
						continue
					}
					if limit == saved.Capacity {
						editing = false
						continue
					}
					stopChild(c)
					// Drain cumulative snapshots before resetting the worker counters.
					draining := true
					for draining {
						select {
						case s := <-c.updates:
							addSnapshot(&saved, &prev, s)
						default:
							draining = false
						}
					}
					saved.Capacity = limit
					refreshStatus()
					c = &child{}
					tryStart()
					editing = false
					refreshStatus()
				}
			} else {
				switch key {
				case 'q', 'Q':
					return nil
				case 'l', 'L':
					editing = true
					input = ""
					note = "Enter a new capacity. Enter restarts active connections."
				}
			}
		}
	}
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if len(os.Args) == 1 {
			fmt.Println("Press Enter to close")
			bufio.NewReader(os.Stdin).ReadString('\n')
		}
		os.Exit(1)
	}
}

