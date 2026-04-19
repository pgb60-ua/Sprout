package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	backupDir := flag.String("backup", "", "ruta de la carpeta del backup a restaurar")
	backupRoot := flag.String("root", "data/remote/backups", "directorio raiz donde estan los backups")
	targetDir := flag.String("target", "data", "directorio raiz de datos original")
	wipe := flag.Bool("wipe", true, "borra los datos actuales antes de restaurar")
	flag.Parse()

	selectedBackup := strings.TrimSpace(*backupDir)
	if selectedBackup == "" {
		backups, err := listBackups(*backupRoot)
		if err != nil {
			log.Fatal(err)
		}
		if len(backups) == 0 {
			log.Fatal("no hay backups disponibles para restaurar")
		}

		selectedBackup, err = chooseBackup(backups)
		if err != nil {
			log.Fatal(err)
		}
	}

	if err := restoreBackup(selectedBackup, *targetDir, *wipe); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Backup restaurado correctamente.")
}

type backupInfo struct {
	Name      string
	Path      string
	CreatedAt time.Time
	SizeBytes int64
}

func listBackups(root string) ([]backupInfo, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no existe el directorio de backups: %s", root)
		}
		return nil, fmt.Errorf("no se pudieron listar backups: %w", err)
	}

	backups := make([]backupInfo, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		fullPath := filepath.Join(root, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		backups = append(backups, backupInfo{
			Name:      entry.Name(),
			Path:      fullPath,
			CreatedAt: backupTimestamp(entry.Name(), info.ModTime()),
			SizeBytes: dirSize(fullPath),
		})
	}

	sort.Slice(backups, func(i, j int) bool {
		if backups[i].CreatedAt.Equal(backups[j].CreatedAt) {
			return backups[i].Name > backups[j].Name
		}
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})

	return backups, nil
}

func chooseBackup(backups []backupInfo) (string, error) {
	fmt.Println("Backups disponibles:")
	for i, backup := range backups {
		fmt.Printf("%d) %s  [%s]  %s\n", i+1, backup.Name, backup.CreatedAt.UTC().Format("2006-01-02 15:04:05"), humanSize(backup.SizeBytes))
	}

	fmt.Print("Elige un numero: ")
	reader := bufio.NewReader(os.Stdin)
	var choice int
	if _, err := fmt.Fscan(reader, &choice); err != nil {
		return "", fmt.Errorf("no se pudo leer la opcion seleccionada: %w", err)
	}
	if choice < 1 || choice > len(backups) {
		return "", fmt.Errorf("opcion fuera de rango: %d", choice)
	}

	return backups[choice-1].Path, nil
}

func backupTimestamp(name string, fallback time.Time) time.Time {
	parts := strings.SplitN(name, "-", 2)
	if len(parts) == 0 {
		return fallback
	}
	timestamp := parts[0]
	parsed, err := time.Parse("20060102T150405.000000000Z", timestamp)
	if err != nil {
		return fallback
	}
	return parsed
}

func dirSize(root string) int64 {
	var size int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil {
			return walkErr
		}
		if !info.IsDir() {
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
	if err != nil {
		return fmt.Errorf("no se pudo resolver la ruta del backup: %w", err)
	}
	backupServerDB := filepath.Join(backupDirAbs, "server.db")
	backupFilesDir := filepath.Join(backupDirAbs, "files")

	if _, err := os.Stat(backupServerDB); err != nil {
		return fmt.Errorf("el backup no contiene server.db: %w", err)
	}

	targetDirAbs, err := filepath.Abs(targetDir)
	if err != nil {
		return fmt.Errorf("no se pudo resolver el directorio de destino: %w", err)
	}
	if err := os.MkdirAll(targetDirAbs, 0755); err != nil {
		return fmt.Errorf("no se pudo crear el directorio de destino: %w", err)
	}

	targetDB := filepath.Join(targetDirAbs, "server.db")
	targetFiles := filepath.Join(targetDirAbs, "files")

	if wipe {
		if err := os.RemoveAll(targetDB); err != nil {
			return fmt.Errorf("no se pudo borrar la DB actual: %w", err)
		}
		if err := os.RemoveAll(targetFiles); err != nil {
			return fmt.Errorf("no se pudieron borrar los ficheros actuales: %w", err)
		}
	}

	if err := copyFile(backupServerDB, targetDB); err != nil {
		return fmt.Errorf("no se pudo restaurar server.db: %w", err)
	}

	if _, err := os.Stat(backupFilesDir); err == nil {
		if err := copyTree(backupFilesDir, targetFiles); err != nil {
			return fmt.Errorf("no se pudieron restaurar los ficheros: %w", err)
		}
	}

	return nil
}

func copyTree(srcRoot, dstRoot string) error {
	return filepath.Walk(srcRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		relPath, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(dstRoot, relPath)
		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode().Perm())
		}

		return copyFile(path, dstPath)
	})
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	if err := dstFile.Sync(); err != nil {
		return err
	}

	return dstFile.Close()
}
