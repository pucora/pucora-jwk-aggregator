package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pucora/pucora-jwk-aggregator/aggregator"
)

// HandlerRegisterer is the symbol the plugin loader will try to load.
var HandlerRegisterer = registerer("jwk-aggregator")

type registerer string

var logger Logger

func (registerer) RegisterLogger(v interface{}) {
	l, ok := v.(Logger)
	if !ok {
		return
	}
	logger = l
	logger.Debug(fmt.Sprintf("[PLUGIN: %s] Logger loaded", HandlerRegisterer))
}

func (r registerer) RegisterHandlers(f func(
	name string,
	handler func(context.Context, map[string]interface{}, http.Handler) (http.Handler, error),
)) {
	f(string(r), r.registerHandlers)
}

func (r registerer) registerHandlers(ctx context.Context, extra map[string]interface{}, next http.Handler) (http.Handler, error) {
	raw, ok := extra["jwk-aggregator"]
	if !ok {
		return next, nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var cfg aggregator.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	srv := aggregator.NewServer(cfg)
	if err := srv.Start(ctx); err != nil {
		return nil, err
	}
	if logger != nil {
		logger.Info(fmt.Sprintf("[PLUGIN: %s] JWK aggregator listening on http://127.0.0.1:%d", r, cfg.Port))
	}
	return next, nil
}

func main() {}

type Logger interface {
	Debug(v ...interface{})
	Info(v ...interface{})
	Warning(v ...interface{})
	Error(v ...interface{})
	Critical(v ...interface{})
	Fatal(v ...interface{})
}
