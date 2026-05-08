package backups

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type backupInfo struct {
	Name      string
	Path      string
	CreatedAt time.Time
	SizeBytes int64
}

func Run() {
	fs := flag.NewFlagSet("backups", flag.ContinueOnError)
	backupDir := fs.String("backup", "", "ruta de la carpeta del backup a restaurar")
	backupRoot := fs.String("root", "data/remote/backups", "directorio raiz donde estan los backups")
	targetDir := fs.String("target", "data", "directorio raiz de datos original")
	wipe := fs.Bool("wipe", true, "borra los datos actuales antes de restaurar")
	fs.Parse(nil)

	selectedBackup := strings.TrimSpace(*backupDir)
	if selectedBackup == "" {
		backupsList, err := listBackups(*backupRoot)
		if err != nil {
			log.Fatal(err)
		}
		if len(backupsList) == 0 {
			log.Fatal("no hay backups disponibles para restaurar")
		}

		selectedBackup, err = chooseBackup(backupsList)
		if err != nil {
			log.Fatal(err)
		}
	}

	if err := restoreBackup(selectedBackup, *targetDir, *wipe); err != nil {
		log.Fatal("Error restaurando backup: ", err)
	}
	fmt.Println("Backup restaurado correctamente.")
}

func listBackups(root string) ([]backupInfo, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no existe el directorio de backups: %s", root)
		}
		return nil, fmt.Errorf("no se pudieron listar backups: %w", err)
	}

	backupsList := make([]backupInfo, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		fullPath := filepath.Join(root, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		backupsList = append(backupsList, backupInfo{
			Name:      entry.Name(),
			Path:      fullPath,
			CreatedAt: backupTimestamp(entry.Name(), info.ModTime()),
			SizeBytes: dirSize(fullPath),
		})
	}

	sort.Slice(backupsList, func(i, j int) bool {
		if backupsList[i].CreatedAt.Equal(backupsList[j].CreatedAt) {
			return backupsList[i].Name > backupsList[j].Name
		}
		return backupsList[i].CreatedAt.After(backupsList[j].CreatedAt)
	})

	return backupsList, nil
}

func chooseBackup(backupsList []backupInfo) (string, error) {
	fmt.Println("Backups disponibles:")
	for i, backup := range backupsList {
		fmt.Printf("%d) %s  [%s]  %s\n", i+1, backup.Name, backup.CreatedAt.UTC().Format("2006-01-02 15:04:05"), humanSize(backup.SizeBytes))
	}

	fmt.Print("Elige un numero: ")
	reader := bufio.NewReader(os.Stdin)
	var choice int
	if _, err := fmt.Fscan(reader, &choice); err != nil {
		return "", fmt.Errorf("no se pudo leer la opcion seleccionada: %w", err)
	}
	if choice < 1 || choice > len(backupsList) {
		return "", fmt.Errorf("opcion fuera de rango: %d", choice)
	}

	return backupsList[choice-1].Path, nil
}

func backupTimestamp(name string, fallback time.Time) time.Time {
	parts := strings.SplitN(name, "-", 2)
	if len(parts) == 0 {
		return fallback
	}
	parsed, err := time.Parse("20060102T150405.000000000Z", parts[0])
	if err != nil {
		return fallback
	}
	return parsed
}

func dirSize(root string) int64 {
	var size int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, walkErr error) error {
		if walkErr == nil && info != nil && !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

func humanSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	digits := []string{"KiB", "MiB", "GiB", "TiB"}
	value := float64(bytes)
	for i, suffix := range digits {
		value /= unit
		if value < unit || i == len(digits)-1 {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%d B", bytes)
}

func restoreBackup(backupDir, targetDir string, wipe bool) error {
	backupDirAbs, err := filepath.Abs(backupDir)
	if err != nil { return fmt.Errorf("no se pudo resolver la ruta del backup: %w", err) }
	
	targetDirAbs, err := filepath.Abs(targetDir)
	if err != nil { return fmt.Errorf("no se pudo resolver el directorio de destino: %w", err) }

	os.MkdirAll(targetDirAbs, 0755)

	if wipe {
		os.RemoveAll(filepath.Join(targetDirAbs, "server.db"))
		os.RemoveAll(filepath.Join(targetDirAbs, "files"))
	}

	os.MkdirAll(filepath.Join(targetDirAbs, "files"), 0755)
	
	dbSrc, err := os.ReadFile(filepath.Join(backupDirAbs, "server.db"))
	if err != nil {
		return fmt.Errorf("el backup no contiene server.db o no se pudo leer: %w", err)
	}
	if err := os.WriteFile(filepath.Join(targetDirAbs, "server.db"), dbSrc, 0600); err != nil {
		return fmt.Errorf("no se pudo restaurar server.db: %w", err)
	}

	filepath.WalkDir(filepath.Join(backupDirAbs, "files"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(filepath.Join(backupDirAbs, "files"), p)
			dst := filepath.Join(targetDirAbs, "files", rel)
			os.MkdirAll(filepath.Dir(dst), 0755)
			b, _ := os.ReadFile(p)
			os.WriteFile(dst, b, 0600)
		}
		return nil
	})
	return nil
}
