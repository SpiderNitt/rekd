package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"rekd/internal/bpf"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	EntropyThreshold = 7.5
	MaxCopySize      = 1536
	NumWorkers       = 4
	MapGCInterval    = 30 * time.Second
	MapGCTTL         = 2 * time.Minute
)

// --- Logic Types ---

type ProcessStats struct {
	Comm       string
	BytesTotal uint64
	BytesEnc   uint64
	LastFile   string
	LastSeen   time.Time
}

type UpdatePayload struct {
	Pid   uint32
	Comm  string
	Fname string
	Size  uint32
	IsEnc bool
}

var (
	statsMu    sync.RWMutex
	stats      = make(map[uint32]*ProcessStats)
	entropyLUT [MaxCopySize + 1]float64
	daemonMode bool
)

// --- TUI Types & Styles ---

type viewItem struct {
	pid      uint32
	comm     string
	totalMB  float64
	encMB    float64
	ratio    float64
	lastFile string
}

type tickMsg time.Time

var (
	baseStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240"))

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1).
			MarginBottom(1)

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262")).
			Italic(true)
)

// --- Bubble Tea Model ---

type model struct {
	table    table.Model
	pidCount int
}

func newModel() model {
	columns := []table.Column{
		{Title: "PID", Width: 8},
		{Title: "COMM", Width: 15},
		{Title: "Total (MB)", Width: 12},
		{Title: "Enc (MB)", Width: 12},
		{Title: "Enc %", Width: 8},
		{Title: "Last File", Width: 35},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(20),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	return model{table: t}
}

func (m model) Init() tea.Cmd {
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	case tickMsg:
		statsMu.RLock()
		m.pidCount = len(stats)
		items := make([]viewItem, 0, len(stats))
		for pid, s := range stats {
			ratio := 0.0
			if s.BytesTotal > 0 {
				ratio = float64(s.BytesEnc) / float64(s.BytesTotal)
			}
			items = append(items, viewItem{
				pid:      pid,
				comm:     s.Comm,
				totalMB:  float64(s.BytesTotal) / 1e6,
				encMB:    float64(s.BytesEnc) / 1e6,
				ratio:    ratio * 100,
				lastFile: s.LastFile,
			})
		}
		statsMu.RUnlock()

		sort.Slice(items, func(i, j int) bool {
			return items[i].encMB > items[j].encMB
		})

		displayLimit := 20
		if len(items) < displayLimit {
			displayLimit = len(items)
		}

		rows := make([]table.Row, 0, displayLimit)
		for i := 0; i < displayLimit; i++ {
			it := items[i]
			rows = append(rows, table.Row{
				fmt.Sprintf("%d", it.pid),
				it.comm,
				fmt.Sprintf("%.2f", it.totalMB),
				fmt.Sprintf("%.2f", it.encMB),
				fmt.Sprintf("%.1f%%", it.ratio),
				it.lastFile,
			})
		}

		m.table.SetRows(rows)
		return m, tick()

	case tea.WindowSizeMsg:
		m.table.SetWidth(msg.Width)
		m.table.SetHeight(msg.Height - 10)
	}

	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m model) View() string {
	return lipgloss.JoinVertical(lipgloss.Left,
		titleStyle.Render("OPTIMIZED VFS_WRITE SCANNER"),
		fmt.Sprintf("Active PIDs: %d | Refresh: 2s\n", m.pidCount),
		baseStyle.Render(m.table.View()),
		statusStyle.Render("\n Quit • Scroll"),
	) + "\n"
}

// --- Main Program Logic ---

func main() {
	flag.BoolVar(&daemonMode, "daemon", false, "Run in background mode (no TUI)")
	flag.Parse()

	initLUT()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	objs := bpf.BpfObjects{}
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed loading BPF objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.AttachTracing(link.TracingOptions{Program: objs.VfsWriteFentry})
	if err != nil {
		log.Fatalf("Failed to attach fentry: %v", err)
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ringbuf: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eventsChan := make(chan []byte, 10000)
	updatesChan := make(chan UpdatePayload, 10000)

	var wgWorkers sync.WaitGroup
	var wgAgg sync.WaitGroup

	// Start Aggregator
	wgAgg.Add(1)
	go statsAggregator(updatesChan, &wgAgg)

	// Start Workers
	for i := 0; i < NumWorkers; i++ {
		wgWorkers.Add(1)
		go worker(eventsChan, updatesChan, &wgWorkers)
	}

	// Wait for workers to finish, then safely close the updates channel
	go func() {
		wgWorkers.Wait()
		close(updatesChan)
	}()

	// Ringbuffer Drain Goroutine
	var wgReader sync.WaitGroup
	wgReader.Add(1)
	go func() {
		defer wgReader.Done()
		defer close(eventsChan)
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			eventsChan <- record.RawSample
		}
	}()

	if daemonMode {
		fmt.Println("[*] Running in daemon mode. Press Ctrl+C to stop.")
		<-ctx.Done()
	} else {
		p := tea.NewProgram(newModel(), tea.WithAltScreen())

		// Graceful Shutdown Coordinator
		go func() {
			<-ctx.Done()
			rd.Close()
			p.Quit()
		}()

		if _, err := p.Run(); err != nil {
			log.Fatalf("Error running TUI: %v", err)
		}
	}

	stop()
	wgReader.Wait()
	wgAgg.Wait()
}

// --- Logic Helpers ---

func worker(eventsChan <-chan []byte, updatesChan chan<- UpdatePayload, wg *sync.WaitGroup) {
	defer wg.Done()

	expectedSize := int(unsafe.Sizeof(bpf.BpfEventT{}))

	for rawData := range eventsChan {
		if len(rawData) < expectedSize {
			continue
		}

		event := (*bpf.BpfEventT)(unsafe.Pointer(&rawData[0]))

		pLen := int(event.Copied)
		if pLen > MaxCopySize {
			pLen = MaxCopySize
		}

		// Calculate entropy on the slice
		ent := calculateFastEntropy(event.Data[:pLen])

		// Pass slices of the int8 arrays to nullTermStr
		updatesChan <- UpdatePayload{
			Pid:   event.Pid,
			Comm:  nullTermStr(event.Comm[:]),
			Fname: nullTermStr(event.Fname[:]),
			Size:  event.Size,
			IsEnc: ent >= EntropyThreshold,
		}
	}
}

func statsAggregator(updatesChan <-chan UpdatePayload, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(MapGCInterval)
	defer ticker.Stop()

	for {
		select {
		case u, ok := <-updatesChan:
			if !ok {
				return
			}
			statsMu.Lock()
			s, ok := stats[u.Pid]
			if !ok {
				s = &ProcessStats{Comm: u.Comm}
				stats[u.Pid] = s
			}
			s.BytesTotal += uint64(u.Size)
			s.LastFile = u.Fname
			s.LastSeen = time.Now()
			if u.IsEnc {
				s.BytesEnc += uint64(u.Size)
				if daemonMode && s.BytesEnc > 1e6 { // Log if encrypted writes exceed 1MB in daemon mode
					log.Printf("[!] High Entropy Write Detected: PID=%d COMM=%s FILE=%s\n", u.Pid, u.Comm, u.Fname)
				}
			}
			statsMu.Unlock()

		case <-ticker.C:
			now := time.Now()
			statsMu.Lock()
			for pid, s := range stats {
				if now.Sub(s.LastSeen) > MapGCTTL {
					delete(stats, pid)
				}
			}
			statsMu.Unlock()
		}
	}
}

func calculateFastEntropy(data []byte) float64 {
	length := len(data)
	if length == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var sum float64
	for _, c := range counts {
		if c > 0 {
			sum += entropyLUT[c]
		}
	}
	fLen := float64(length)
	return math.Log2(fLen) - (sum / fLen)
}

func initLUT() {
	entropyLUT[0] = 0
	for i := 1; i <= MaxCopySize; i++ {
		entropyLUT[i] = float64(i) * math.Log2(float64(i))
	}
}

// Updated to handle []int8 which bpf2go generates for char arrays
func nullTermStr(b []int8) string {
	if len(b) == 0 {
		return ""
	}

	// Safely cast []int8 to []byte using unsafe.Slice
	// This avoids allocating a new slice or copying if we just want to scan it
	ptr := unsafe.Pointer(&b[0])
	asBytes := unsafe.Slice((*byte)(ptr), len(b))

	idx := bytes.IndexByte(asBytes, 0)
	if idx == -1 {
		return string(asBytes)
	}
	return string(asBytes[:idx])
}
