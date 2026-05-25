/*
curso: 			2025-2026
asignatura: 	Seguridad del Diseño de Software
estudiantes:
- Casado López, Carlos María
- García Belando, Pablo
- Jiménez Martínez, Alejandro
- Seva Berenguer, Marcos
- Tornero Fuster, Manuel José
*/
package main

import (
	"log"
	"os"
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
