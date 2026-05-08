package backups

import (
	"fmt"
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
	backupRoot, targetDir := "data/remote/backups", "data"
	entries, err := os.ReadDir(backupRoot)
	if err != nil || len(entries) == 0 {
		fmt.Println("No hay backups disponibles para restaurar")
		return
	}

	var backupsList []backupInfo
	for _, e := range entries {
		if !e.IsDir() { continue }
		fullPath := filepath.Join(backupRoot, e.Name())
		
		var size int64
		filepath.WalkDir(fullPath, func(_ string, d os.DirEntry, _ error) error {
			if d != nil && !d.IsDir() { if info, err := d.Info(); err == nil { size += info.Size() } }
			return nil
		})
		
		t := time.Now()
		if p := strings.SplitN(e.Name(), "-", 2); len(p) > 0 {
			if pt, err := time.Parse("20060102T150405.000000000Z", p[0]); err == nil { t = pt }
		}
		backupsList = append(backupsList, backupInfo{Name: e.Name(), Path: fullPath, CreatedAt: t, SizeBytes: size})
	}

	sort.Slice(backupsList, func(i, j int) bool {
		if backupsList[i].CreatedAt.Equal(backupsList[j].CreatedAt) { return backupsList[i].Name > backupsList[j].Name }
		return backupsList[i].CreatedAt.After(backupsList[j].CreatedAt)
	})

	fmt.Println("Backups disponibles:")
	for i, b := range backupsList {
		szStr := fmt.Sprintf("%d B", b.SizeBytes)
		for v, j, u := float64(b.SizeBytes), 0, []string{"KiB", "MiB", "GiB"}; v >= 1024 && j < len(u); j++ {
			v /= 1024
			szStr = fmt.Sprintf("%.1f %s", v, u[j])
		}
		fmt.Printf("%d) %s  [%s]  %s\n", i+1, b.Name, b.CreatedAt.UTC().Format("2006-01-02 15:04:05"), szStr)
	}

	fmt.Print("Elige un numero: ")
	var choice int
	if _, err := fmt.Scanln(&choice); err != nil || choice < 1 || choice > len(backupsList) {
		fmt.Println("Opción inválida o cancelada.")
		return
	}

	sel := backupsList[choice-1].Path
	os.RemoveAll(filepath.Join(targetDir, "server.db"))
	os.RemoveAll(filepath.Join(targetDir, "files"))
	os.MkdirAll(filepath.Join(targetDir, "files"), 0755)
	
	if dbSrc, err := os.ReadFile(filepath.Join(sel, "server.db")); err != nil {
		fmt.Printf("El backup no contiene server.db o no se pudo leer: %v\n", err)
		return
	} else {
		os.WriteFile(filepath.Join(targetDir, "server.db"), dbSrc, 0600)
	}

	filepath.WalkDir(filepath.Join(sel, "files"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(filepath.Join(sel, "files"), p)
			dst := filepath.Join(targetDir, "files", rel)
			os.MkdirAll(filepath.Dir(dst), 0755)
			if b, err := os.ReadFile(p); err == nil { os.WriteFile(dst, b, 0600) }
		}
		return nil
	})
	
	fmt.Println("Backup restaurado correctamente.")
}
