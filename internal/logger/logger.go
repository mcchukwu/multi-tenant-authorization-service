package logger

import (
	"log/slog"
	"os"
)

var log = slog.New(slog.NewJSONHandler(os.Stdout, nil))

func Info(msg string, args ...any)  { log.Info(msg, args...) }
func Warn(msg string, args ...any)  { log.Warn(msg, args...) }
func Error(msg string, args ...any) { log.Error(msg, args...) }
