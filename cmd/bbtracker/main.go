// Command bbtracker runs the local bbtracker web UI: a bug bounty recon and
// tracking tool backed by a SQLite database in the current directory.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"bbtracker/internal/recon"
	"bbtracker/internal/scheduler"
	"bbtracker/internal/server"
	"bbtracker/internal/store"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "address to listen on")
	dbPath := flag.String("db", "bbtracker.db", "path to the SQLite database file")
	noBrowser := flag.Bool("no-browser", false, "do not open a browser window automatically")
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer st.Close()

	engine := recon.NewEngine(st, recon.NewLibSubfinder(), recon.NewLibHTTPProbe(), recon.NewLibNuclei(), recon.NewSimpleFuzzer(),
		recon.NewLibWayback(), recon.NewSimpleParamFuzzer(), recon.NewSimpleJSAnalyzer(), recon.NewSimpleCORSScanner(),
		recon.NewLibGitHubDorker(), recon.NewSimpleCloudEnumerator(), recon.NewSimpleTakeoverScanner(), recon.NewSimpleTLSScanner())
	srv := server.NewServer(st, engine)
	httpServer := &http.Server{Addr: *addr, Handler: srv.Handler()}

	// The scheduler shares engine with srv so a scan it triggers can be
	// stopped via the same "Stop scan" API as a manually-started one.
	schedCtx, schedCancel := context.WithCancel(context.Background())
	sched := scheduler.New(st, engine)
	go sched.Run(schedCtx)

	url := "http://" + *addr + "/"
	log.Printf("bbtracker starting at %s (db: %s)", url, *dbPath)
	if !*noBrowser {
		openBrowser(url)
	}

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")

	schedCancel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

// openBrowser best-effort opens the default browser at url. Failures are
// logged but not fatal - the user can still navigate there manually.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("could not open browser automatically: %v", err)
	}
}
