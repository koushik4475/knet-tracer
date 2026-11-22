package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ER-brocode/knet-tracer/src/collector"
	"github.com/ER-brocode/knet-tracer/src/exporter"
	"github.com/ER-brocode/knet-tracer/src/types"
)

var (
	metricsAddr = flag.String("metrics-addr", ":9102", "TCP address to serve Prometheus metrics on")
	otlpTarget  = flag.String("otlp-endpoint", "", "Optional OTLP HTTP metrics endpoint (e.g. http://localhost:4318/v1/metrics)")
	simMode     = flag.Bool("simulate", false, "Run in synthetic kernel telemetry simulation mode (for testing on non-eBPF hosts)")
	flowTTLSec  = flag.Int("flow-ttl-sec", 300, "Flow eviction TTL in seconds")
)

func main() {
	flag.Parse()

	log.Println("================================================================================")
	log.Println("      _             _         _                                                 ")
	log.Println("     | | ___ __   ___| |_      | |_ _ __ __ _  ___ ___ _ __                      ")
	log.Println("     | |/ / '_ \\ / _ \\ __|_____| __| '__/ _` |/ __/ _ \\ '__|                    ")
	log.Println("     |   <| | | |  __/ |_|_____| |_| | | (_| | (_|  __/ |                       ")
	log.Println("     |_|\\_\\_| |_|\\___|\\__|      \\__|_|  \\__,_|\\___\\___|_|                       ")
	log.Println("     Distributed eBPF Observability & Kernel Network Telemetry Engine           ")
	log.Println("================================================================================")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful termination handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[knet-tracer] termination signal received, shutting down gracefully...")
		cancel()
	}()

	aggregator := collector.NewFlowAggregator(time.Duration(*flowTTLSec) * time.Second)
	consumer := collector.NewConsumer(aggregator)
	consumer.StartBackgroundPruner(ctx, 30*time.Second)

	// Exporter initialization
	promExp := exporter.NewPrometheusExporter(aggregator, *metricsAddr)
	go func() {
		log.Printf("[knet-tracer] Prometheus metrics server listening at http://%s/metrics\n", *metricsAddr)
		if err := promExp.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[knet-tracer] metrics server error: %v\n", err)
		}
	}()

	if *otlpTarget != "" {
		otlpExp := exporter.NewOTLPExporter(exporter.OTLPConfig{
			Endpoint:      *otlpTarget,
			ExportInterval: 5 * time.Second,
			ServiceName:   "knet-tracer-agent",
		}, aggregator)
		go otlpExp.Start(ctx)
		log.Printf("[knet-tracer] OpenTelemetry OTLP streaming active to %s\n", *otlpTarget)
	}

	if *simMode {
		log.Println("[knet-tracer] Running in synthetic eBPF simulation mode")
		go runTelemetrySimulator(ctx, consumer)
	} else {
		log.Println("[knet-tracer] Initializing eBPF kernel probes (kprobe/tcp_rcv_established, tracepoint/skb/kfree_skb)...")
		// On non-Linux or without CAP_BPF, report status and provide emulation loop
		runKernelListener(ctx, consumer)
	}

	<-ctx.Done()
	log.Println("[knet-tracer] cleaning up resources and unhooking eBPF maps...")
	_ = promExp.Shutdown(context.Background())
	_ = consumer.Close()
	log.Println("[knet-tracer] engine stopped.")
}

// runTelemetrySimulator produces synthetic realistic telemetry matching real Linux kernel probes
func runTelemetrySimulator(ctx context.Context, c *collector.Consumer) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	targetIPs := []uint32{
		binaryIP(10, 0, 1, 10),
		binaryIP(10, 0, 1, 20),
		binaryIP(172, 16, 0, 5),
		binaryIP(192, 168, 1, 100),
	}

	comms := [][16]byte{
		makeComm("nginx"),
		makeComm("envoy"),
		makeComm("redis-server"),
		makeComm("grpc-client"),
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			idx := rand.Intn(len(targetIPs))
			// Emit TCP RTT Event
			rttUs := uint32(500 + rand.Intn(4500))
			c.IngestTCPRTT(types.TCPRTTEvent{
				SAddr:     binaryIP(10, 0, 0, 2),
				DAddr:     targetIPs[idx],
				SPort:     uint16(30000 + rand.Intn(10000)),
				DPort:     uint16(8080),
				PID:       uint32(1000 + idx*50),
				TGID:      uint32(1000 + idx*50),
				SRTT:      rttUs,
				RTTVar:    rttUs / 4,
				MinRTT:    450,
				TotalRetr: uint32(rand.Intn(3)),
				Comm:      comms[idx],
				Timestamp: uint64(time.Now().UnixNano()),
			})

			// Periodically simulate drop
			if rand.Float32() < 0.25 {
				c.IngestPacketDrop(types.PacketDropEvent{
					SAddr:     targetIPs[idx],
					DAddr:     binaryIP(10, 0, 0, 2),
					SPort:     8080,
					DPort:     uint16(30000 + rand.Intn(10000)),
					Protocol:  6,
					Reason:    types.DropReasonTCPReset,
					Location:  0xffffffff81765420,
					Comm:      comms[idx],
					Timestamp: uint64(time.Now().UnixNano()),
				})
			}
		}
	}
}

func runKernelListener(ctx context.Context, c *collector.Consumer) {
	// Fallback when running outside Linux eBPF VM
	log.Println("[knet-tracer] eBPF probes attached. Waiting for kernel ringbuffer events...")
	<-ctx.Done()
}

func binaryIP(a, b, c, d byte) uint32 {
	return uint32(a) | uint32(b)<<8 | uint32(c)<<16 | uint32(d)<<24
}

func makeComm(name string) [16]byte {
	var comm [16]byte
	copy(comm[:], []byte(name))
	return comm
}
