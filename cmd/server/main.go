package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"threat-service/internal/app"
)

func main() {
	cfg, err := app.LoadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}
