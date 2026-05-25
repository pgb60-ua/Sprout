package backups

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sprout/pkg/server"
	"sprout/pkg/remotecommon"
	"sprout/pkg/ui"
)

type backupInfo struct {
	Name      string
	Path      string
	CreatedAt time.Time
	SizeBytes int64
}

func Run() {
	backupRoot := "data/remote/backups"
	targetDir := "data"

	fmt.Println("AVISO: La restauración sobrescribirá server.db y los ficheros actuales.")
	fmt.Println("El servidor debe estar detenido antes de continuar para evitar corrupción de datos.")
	if !ui.Confirm("¿Confirmas que el servidor está detenido y deseas continuar?") {
		fmt.Println("Restauración cancelada.")
		return
	}

	entries, err := os.ReadDir(backupRoot)
	if err != nil {
		fmt.Printf("Error leyendo directorio de backups: %v\n", err)
		return
	}
	if len(entries) == 0 {
		fmt.Println("No hay backups disponibles para restaurar")
		return
	}

	var backupsList []backupInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		
		fullPath := filepath.Join(backupRoot, e.Name())
		var size int64
		_ = filepath.WalkDir(fullPath, func(_ string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if !d.IsDir() {
				info, errInfo := d.Info()
				if errInfo == nil {
					size += info.Size()
				}
			}
			return nil
		})
		
		t := time.Now()
		parts := strings.SplitN(e.Name(), "-", 2)
		if len(parts) > 0 {
			if pt, tErr := time.Parse("20060102T150405.000000000Z", parts[0]); tErr == nil {
				t = pt
			}
		}
		
		backupsList = append(backupsList, backupInfo{
			Name:      e.Name(),
			Path:      fullPath,
			CreatedAt: t,
			SizeBytes: size,
		})
	}

	sort.Slice(backupsList, func(i, j int) bool {
		if backupsList[i].CreatedAt.Equal(backupsList[j].CreatedAt) {
			return backupsList[i].Name > backupsList[j].Name
		}
		return backupsList[i].CreatedAt.After(backupsList[j].CreatedAt)
	})

	options := make([]string, len(backupsList))
	for i, b := range backupsList {
		options[i] = fmt.Sprintf("%s  [%s]  %s", b.Name, b.CreatedAt.UTC().Format("2006-01-02 15:04:05"), humanSize(b.SizeBytes))
	}
	options = append(options, "Cancelar")

	choice := ui.PrintMenu("Backups disponibles:", options)
	if choice == len(options) {
		fmt.Println("Opción cancelada.")
		return
	}

	sel := backupsList[choice-1].Path
	
	tmpDir, err := os.MkdirTemp(filepath.Dir(targetDir), "sprout-restore-*")
	if err != nil {
		fmt.Printf("Error creando directorio temporal: %v\n", err)
		return
	}
	defer os.RemoveAll(tmpDir)

	if err := os.MkdirAll(filepath.Join(tmpDir, "files"), 0755); err != nil {
		fmt.Printf("Error creando directorios temporales: %v\n", err)
		return
	}
	
	dbSrc, err := os.ReadFile(filepath.Join(sel, "server.db"))
	if err != nil {
		fmt.Printf("El backup no contiene server.db o no se pudo leer: %v\n", err)
		return
	}
	
	if decDB, errDec := server.DecryptUserdata(remotecommon.GetDEK(), dbSrc); errDec == nil {
		dbSrc = decDB
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "server.db"), dbSrc, 0600); err != nil {
		fmt.Printf("Error escribiendo server.db: %v\n", err)
		return
	}

	err = filepath.WalkDir(filepath.Join(sel, "files"), func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) && p == filepath.Join(sel, "files") {
				return nil
			}
			return walkErr
		}
		if !d.IsDir() {
			rel, relErr := filepath.Rel(filepath.Join(sel, "files"), p)
			if relErr != nil {
				return relErr
			}
			dst := filepath.Join(tmpDir, "files", rel)
			if dirErr := os.MkdirAll(filepath.Dir(dst), 0755); dirErr != nil {
				return dirErr
			}
			b, readErr := os.ReadFile(p)
			if readErr != nil {
				return readErr
			}
			
			if decFile, errDec := server.DecryptUserdata(remotecommon.GetDEK(), b); errDec == nil {
				b = decFile
			}

			if writeErr := os.WriteFile(dst, b, 0600); writeErr != nil {
				return writeErr
			}
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error copiando archivos: %v\n", err)
		return
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		fmt.Printf("Error verificando directorio destino: %v\n", err)
		return
	}

	for _, name := range []string{"server.db", "files"} {
		if err := os.RemoveAll(filepath.Join(targetDir, name)); err != nil {
			fmt.Printf("Error limpiando antiguo %s: %v\n", name, err)
			return
		}
		if err := os.Rename(filepath.Join(tmpDir, name), filepath.Join(targetDir, name)); err != nil {
			fmt.Printf("Error moviendo %s restaurado: %v\n", name, err)
			return
		}
	}
	
	fmt.Println("Backup restaurado correctamente.")
}

func humanSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	digits := []string{"KiB", "MiB", "GiB", "TiB"}
	value := float64(bytes)
	for _, suffix := range digits {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f %s", value, digits[len(digits)-1])
}
