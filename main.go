/*
'sprout' es una base para el desarrollo de prácticas en clase con Go.

Se puede compilar con "go build" en el directorio donde resida main.go
o "go build -o nombre" para que el ejecutable tenga un nombre distinto

curso: 			**rellenar**
asignatura: 	**antes de**
estudiantes: 	**entregar**
*/
package main

import (
	"log"
	"os"
	"strings"
	"time"

	"sprout/pkg/client"
	"sprout/pkg/remoteservice"
	"sprout/pkg/server"
	"sprout/pkg/ui"
)

func main() {

	// Creamos un logger con prefijo 'main' para identificar
	// los mensajes en la consola.
	log := log.New(os.Stdout, "[main] ", log.LstdFlags)

	ensureRemoteDefaults(log)

	log.Println("Iniciando servicio remoto de logs/backups...")
	go func() {
		if err := remoteservice.Run(); err != nil {
			log.Fatalf("Error del servicio remoto: %v\n", err)
		}
	}()

	// Inicia servidor en goroutine.
	log.Println("Iniciando servidor...")
	go func() {
		if err := server.Run(); err != nil {
			log.Fatalf("Error del servidor: %v\n", err)
		}
	}()

	// Esperamos un tiempo prudencial a que arranque el servidor.
	const totalSteps = 20
	for i := 1; i <= totalSteps; i++ {
		ui.PrintProgressBar(i, totalSteps, 30)
		time.Sleep(100 * time.Millisecond)
	}

	// Inicia cliente.
	log.Println("Iniciando cliente...")
	client.Run()
}

func ensureRemoteDefaults(logger *log.Logger) {
	remoteAddr := os.Getenv("SPROUT_REMOTE_SERVICE_ADDR")
	if remoteAddr == "" {
		remoteAddr = "127.0.0.1:8081"
		_ = os.Setenv("SPROUT_REMOTE_SERVICE_ADDR", remoteAddr)
	}

	baseURL := normalizeLocalURL(remoteAddr)
	if os.Getenv("SPROUT_REMOTE_LOG_URL") == "" {
		_ = os.Setenv("SPROUT_REMOTE_LOG_URL", baseURL+"/logs")
	}
	if os.Getenv("SPROUT_REMOTE_BACKUP_URL") == "" {
		_ = os.Setenv("SPROUT_REMOTE_BACKUP_URL", baseURL+"/backups")
	}

	logger.Printf("servicio remoto configurado en %s", baseURL)
}

func normalizeLocalURL(addr string) string {
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return strings.TrimRight(addr, "/")
	}
	if strings.HasPrefix(addr, ":") {
		return "https://localhost" + addr
	}
	if strings.Contains(addr, ":") {
		return "https://" + addr
	}
	return "https://localhost:" + addr
}
