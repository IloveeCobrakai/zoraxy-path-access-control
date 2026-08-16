package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	plugin "github.com/IloveeCobrakai/zoraxy-path-access-control/mod/zoraxy_plugin"
)

//go:embed www/index.html
var uiTemplate []byte

//go:embed www/forbidden.html
var forbiddenTemplate []byte

func main() {
	cfg, err := plugin.ServeAndRecvSpec()
	if err != nil {
		log.Fatal("configuration error: ", err)
	}

	service := plugin.NewService(cfg, plugin.Assets{
		IndexHTML:     uiTemplate,
		ForbiddenHTML: forbiddenTemplate,
	}, "path_access_rules.json")
	defer service.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	service.Start(ctx)

	server := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", cfg.Port),
		Handler:           service.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("Path Access Control listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
