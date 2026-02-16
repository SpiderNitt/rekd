package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"text/tabwriter"
	"time"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"gopkg.in/yaml.v3"
)

// Config Constants
const (
	EntropyThreshold  = 7.0
	EncRatioGate      = 0.7
	EncCumulativeGate = 1 * 1024 * 1024 // 1MB
)

var MagicHeaders = [][]byte{
	{0x50, 0x4b, 0x03, 0x04}, // Zip
	{0x1f, 0x8b},             // Gzip
	{0x89, 0x50, 0x4e, 0x47}, // PNG
	{0xff, 0xd8, 0xff},       // JPEG
}

// BPF Event Struct (Must match C struct)
type Event struct {
	Pid    uint32
	Size   uint32
	Copied uint32
	Comm   [16]byte
	Fname  [32]byte
	Data   [4096]byte
}

// Stats tracking
type ProcessStats struct {
	Comm       string
	BytesTotal uint64
	BytesEnc   uint64
	LastFile   string
}

var (
	stats        = make(map[uint32]*ProcessStats)
	exclusions   = make(map[string]bool)
	configFile   = "exclusions.yaml"
	logFile      string
	daemonMode   bool
	initConfig   bool
	csvLogHandle *os.File
)

type Config struct {
	Exclusions []string `yaml:"exclusions"`
}

func main() {
	flag.StringVar(&configFile, "config", "exclusions.yaml", "Path to config file")
	flag.StringVar(&logFile, "log", "", "Path to CSV log file")
	flag.BoolVar(&daemonMode, "daemon", false, "Run in background/headless mode")
	flag.BoolVar(&initConfig, "init-config", false, "Generate sample exclusions.yaml")
	flag.Parse()

	if initConfig {
		generateConfig()
		return
	}

	loadConfig()

	// Allow current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled BPF program into kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach Kprobe
	kp, err := link.Kprobe("vfs_write", objs.VfsWrite, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %v", err)
	}
	defer kp.Close()

	// Open Ringbuffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Setup logging
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		csvLogHandle = f
		defer csvLogHandle.Close()
		csvLogHandle.WriteString("ts,pid,comm,file,size,entropy,is_enc\n")
		fmt.Printf("[*] Logging to %s\n", logFile)
	}

	if !daemonMode {
		fmt.Println("[*] Running (Ctrl+C to stop)...")
		go uiLoop()
	} else {
		fmt.Printf("[*] Daemon started. PID: %d\n", os.Getpid())
	}

	// Main Event Loop
	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			log.Printf("read error: %v", err)
			continue
		}

		// Parse binary data into struct
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing error: %v", err)
			continue
		}

		processEvent(&event)
	}
}

func processEvent(e *Event) {
	comm := nullTermStr(e.Comm[:])
	
	if exclusions[comm] {
		return
	}

	fname := nullTermStr(e.Fname[:])
	payload := e.Data[:e.Copied]
	
	ent := calculateEntropy(payload)
	isEnc := ent >= EntropyThreshold
	
	// Write to CSV
	if csvLogHandle != nil {
		encInt := 0
		if isEnc {
			encInt = 1
		}
		line := fmt.Sprintf("%f,%d,%s,%s,%d,%.4f,%d\n", 
			float64(time.Now().UnixNano())/1e9, e.Pid, comm, fname, e.Size, ent, encInt)
		csvLogHandle.WriteString(line)
	}

	// Update Stats
	if _, ok := stats[e.Pid]; !ok {
		stats[e.Pid] = &ProcessStats{Comm: comm}
	}
	s := stats[e.Pid]
	s.BytesTotal += uint64(e.Size)
	s.LastFile = fname
	if isEnc {
		s.BytesEnc += uint64(e.Size) // Approximate using total size if chunk is high entropy
	}
}

func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	
	// Check magic headers to skip known compressed formats
	for _, magic := range MagicHeaders {
		if bytes.HasPrefix(data, magic) {
			return 0
		}
	}

	freq := make(map[byte]float64)
	for _, b := range data {
		freq[b]++
	}

	var ent float64
	l := float64(len(data))
	for _, count := range freq {
		p := count / l
		ent -= p * math.Log2(p)
	}
	return ent
}

// UI Loop
func uiLoop() {
	// Trap SigInt
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c:
			fmt.Println("\n[*] Stopping...")
			os.Exit(0)
		case <-ticker.C:
			renderTable()
		}
	}
}

func renderTable() {
	// Simple TUI replacement for 'rich'
	fmt.Print("\033[H\033[2J") // Clear screen
	fmt.Println("=== vfs_write Encrypted IO Scanner ===")
	
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "PID\tCOMM\tTotal(MB)\tEnc(MB)\tEnc(%)\tLast File")
	
	// Sort by Encrypted Bytes
	type pItem struct {
		pid uint32
		s   *ProcessStats
	}
	var items []pItem
	for pid, s := range stats {
		items = append(items, pItem{pid, s})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].s.BytesEnc > items[j].s.BytesEnc
	})

	for _, it := range items {
		s := it.s
		ratio := 0.0
		if s.BytesTotal > 0 {
			ratio = float64(s.BytesEnc) / float64(s.BytesTotal)
		}
		
		// Highlight logic
		prefix := ""
		if ratio >= EncRatioGate && s.BytesEnc >= EncCumulativeGate {
			prefix = "(!)" // Visual alert
		}

		fmt.Fprintf(w, "%s%d\t%s\t%.2f\t%.2f\t%.1f\t%s\n", 
			prefix, it.pid, s.Comm, 
			float64(s.BytesTotal)/1e6, 
			float64(s.BytesEnc)/1e6, 
			ratio*100, 
			s.LastFile)
	}
	w.Flush()
}

// Helpers
func nullTermStr(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx == -1 {
		return string(b)
	}
	return string(b[:idx])
}

func loadConfig() {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return
	}
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("Error reading config: %v", err)
		return
	}
	var c Config
	yaml.Unmarshal(data, &c)
	for _, ex := range c.Exclusions {
		exclusions[ex] = true
	}
}

func generateConfig() {
	c := Config{
		Exclusions: []string{"code", "slack", "spotify", "firefox", "chrome"},
	}
	data, _ := yaml.Marshal(&c)
	os.WriteFile("exclusions.yaml", data, 0644)
	fmt.Println("[*] Generated exclusions.yaml")
}
