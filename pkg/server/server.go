// El paquete server contiene el código del servidor.
// Interactúa con el cliente mediante una API JSON/HTTP
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"sprout/pkg/api"
	"sprout/pkg/store"
	"sprout/pkg/utils"
)

// server encapsula el estado de nuestro servidor
type server struct {
	db            store.Store // base de datos
	log           *log.Logger // logger para mensajes de error e información
	mu            sync.Mutex  // Para exclusion a la hora de lectura y escritura
	loginAttempts map[string]*loginAttempt
	pendingTOTP   map[string]pendingTOTPLogin // No le pongo el * porque no lo modifico una vez añadido
}

type session struct {
	Token     string
	ExpiresAt time.Time
}

const sessionDuration = 24 * time.Hour
const lengthToken = 16
const temporalTokenDuration = 2 * time.Minute

// Run inicia la base de datos y arranca el servidor HTTP.
func Run() error {

	// Crear la carpeta 'data' en caso de que no exista.
	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("error creando la carpeta 'data': %w", err)
	}

	// Abrimos la base de datos usando el motor bbolt
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error abriendo base de datos: %v", err)
	}

	// Creamos nuestro servidor con su logger con prefijo 'srv'
	srv := &server{
		db:            db,
		log:           log.New(os.Stdout, "[srv] ", log.LstdFlags),
		loginAttempts: make(map[string]*loginAttempt),
		pendingTOTP:   make(map[string]pendingTOTPLogin),
	}

	// Al terminar, cerramos la base de datos
	defer srv.db.Close()

	// Construimos un mux y asociamos /api a nuestro apiHandler,
	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	// Iniciamos el servidor HTTP.
	httpSrv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return httpSrv.ListenAndServe()
}

// apiHandler decodifica la solicitud JSON, la despacha
// a la función correspondiente y devuelve la respuesta JSON.
func (s *server) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Limitamos el tamaño del body para evitar sorpresas.
	// (No es una medida de seguridad "de verdad"; sólo robustez.)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB

	// Decodificamos la solicitud en una estructura api.Request
	var req api.Request
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}
	// Evitamos que se enví­en múltiples objetos JSON concatenados.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}

	// Despacho según la acción solicitada
	var res api.Response
	switch req.Action {
	case api.ActionRegister:
		res = s.registerUser(req)
	case api.ActionLogin:
		res = s.loginUser(req)
	case api.ActionFetchData:
		res = s.fetchData(req)
	case api.ActionUpdateData:
		res = s.updateData(req)
	case api.ActionLogout:
		res = s.logoutUser(req)
	// FILES
	case api.ActionCreateFile:
		res = s.createFile(req)
	case api.ActionDeleteFile:
		res = s.deleteFile(req)
	case api.ActionModifyFile:
		res = s.modifyFile(req)
	case api.ActionReadFile:
		res = s.readFile(req)
	case api.ActionCreateDir:
		res = s.createDir(req)
	case api.ActionDeleteDir:
		res = s.deleteDir(req)
	case api.ActionListFiles:
		res = s.listFiles(req)
	// TOTP
	case api.ActionTOTPSetup:
		res = s.tOTPSetup(req)
	case api.ActionLoginTOTP:
		res = s.loginTOTP(req)
	case api.ActionTOTPConfirm:
		res = s.tOTPConfirm(req)
	default:
		res = api.Response{Success: false, Message: "Acción desconocida"}
	}

	// Enviamos la respuesta en formato JSON
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// registerUser registra un nuevo usuario, si no existe.
// - Guardamos la contraseña en el namespace 'auth'
// - Creamos entrada vací­a en 'userdata' para el usuario
func (s *server) registerUser(req api.Request) api.Response {
	// Validación básica
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	if err := utils.ValidateUsername(req.Username); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	if err := utils.ValidatePassword(req.Password); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	// Verificamos si ya existe el usuario en 'auth'
	exists, err := s.userExists(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar usuario"}
	}
	if exists {
		return api.Response{Success: false, Message: "El usuario ya existe"}
	}

	hash, err := utils.HashPassword(req.Password)
	if err != nil {
		return api.Response{Success: false, Message: fmt.Sprintf("Error al hashear contraseña: %v", err)}
	}

	// Almacenamos la contraseña en el namespace 'auth' (clave=nombre, valor=contraseña)
	if err := s.db.Put("auth", []byte(req.Username), []byte(hash)); err != nil {
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}

	// Creamos una entrada vací­a para los datos en 'userdata'
	if err := s.db.Put("userdata", []byte(req.Username), []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	return api.Response{Success: true, Message: "Usuario registrado"}
}

// loginUser valida credenciales en el namespace 'auth' y genera un token en 'sessions'.
func (s *server) loginUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	if err := utils.ValidateUsername(req.Username); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	if err := s.CheckLoginAllowed(req.Username); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	// Recogemos la contraseña guardada en 'auth'
	storedPass, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		utils.VerifyPassword(req.Password, utils.DummyHash)
		s.RegisterLoginFailure(req.Username)
		return api.Response{Success: false, Message: "Credenciales invalidos"}
	}

	// Comparamos
	valid, err := utils.VerifyPassword(req.Password, string(storedPass))
	if err != nil || !valid {
		s.RegisterLoginFailure(req.Username)
		return api.Response{Success: false, Message: "Credenciales invalidos"}
	}

	s.ClearLoginFailures(req.Username)

	// Compruebo si tiene TOTP activo
	td, err := s.getTOTPData(req.Username)
	if err == nil && td.Enabled {
		tempToken, err := utils.NewRandomToken(lengthToken)
		if err != nil {
			return api.Response{Success: false, Message: "Error al generar token temporal"}
		}
		s.mu.Lock()
		s.pendingTOTP[tempToken] = pendingTOTPLogin{
			Username:  req.Username,
			ExpiresAt: time.Now().Add(temporalTokenDuration),
		}
		s.mu.Unlock()
		return api.Response{
			Success:      true,
			Message:      "Contraseña correcta, introduce el codigo TOTP",
			RequiresTOTP: true,
			TempToken:    tempToken,
		}
	}

	//Sin TOTP - creo la sesion
	// Generamos un nuevo token, lo guardamos en 'sessions'
	token, err := utils.NewRandomToken(lengthToken)
	if err != nil {
		return api.Response{Success: false, Message: "No se pudo crear un token"}
	}

	sess := session{
		Token:     token,
		ExpiresAt: time.Now().Add(sessionDuration),
	}

	data, err := json.Marshal(sess)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar token"}
	}

	if err := s.db.Put("sessions", []byte(req.Username), []byte(data)); err != nil {
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

	return api.Response{Success: true, Message: "Login exitoso", Token: token, TOTPEnabled: false}
}

// fetchData verifica el token y retorna el contenido del namespace 'userdata'.
func (s *server) fetchData(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada", SessionExpired: true}
	}

	// Obtenemos los datos asociados al usuario desde 'userdata'
	rawData, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
	}

	return api.Response{
		Success: true,
		Message: "Datos privados de " + req.Username,
		Data:    string(rawData),
	}
}

// updateData cambia el contenido de 'userdata' (los "datos" del usuario)
// después de validar el token.
func (s *server) updateData(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada", SessionExpired: true}
	}

	// Escribimos el nuevo dato en 'userdata'
	if err := s.db.Put("userdata", []byte(req.Username), []byte(req.Data)); err != nil {
		return api.Response{Success: false, Message: "Error al actualizar datos del usuario"}
	}

	return api.Response{Success: true, Message: "Datos de usuario actualizados"}
}

// logoutUser borra la sesión en 'sessions', invalidando el token.
func (s *server) logoutUser(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada", SessionExpired: true}
	}

	// Borramos la entrada en 'sessions'
	if err := s.db.Delete("sessions", []byte(req.Username)); err != nil {
		return api.Response{Success: false, Message: "Error al cerrar sesión"}
	}

	return api.Response{Success: true, Message: "Sesión cerrada correctamente"}
}

// userExists comprueba si existe un usuario con la clave 'username'
// en 'auth'. Si no se encuentra, retorna false.
func (s *server) userExists(username string) (bool, error) {
	_, err := s.db.Get("auth", []byte(username))
	if err != nil {
		// Si no existe namespace o la clave, no es un error "real".
		if errors.Is(err, store.ErrNamespaceNotFound) || errors.Is(err, store.ErrKeyNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isTokenValid comprueba que el token almacenado en 'sessions'
// coincida con el token proporcionado.
func (s *server) isTokenValid(username, token string) bool {
	storedSession, err := s.db.Get("sessions", []byte(username))
	if err != nil {
		return false
	}

	var sess session
	if err := json.Unmarshal(storedSession, &sess); err != nil {
		return false
	}

	if time.Now().After(sess.ExpiresAt) {
		s.db.Delete("sessions", []byte(username))
		return false
	}
	return sess.Token == token
}

// safePath valida el path para evitar Path Traversal.
// Restringe el acceso unicamente al directorio asignado para el usuario en data/files/<username>.
func (s *server) safePath(username, reqPath string) (string, error) {
	baseDir := filepath.Join("data", "files", username)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return "", err
	}
	baseDirAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}

	targetPath := filepath.Join(baseDir, reqPath)
	targetPathAbs, err := filepath.Abs(targetPath)
	if err != nil {
		return "", err
	}

	// Prevenir path traversal
	if !strings.HasPrefix(targetPathAbs, baseDirAbs) {
		return "", errors.New("acceso denegado o path inválido")
	}
	return targetPathAbs, nil
}

func (s *server) createFile(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}
	if req.Path == "" {
		return api.Response{Success: false, Message: "Falta el path del fichero"}
	}
	path, err := s.safePath(req.Username, req.Path)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	err = os.WriteFile(path, []byte(req.Data), 0644)
	if err != nil {
		return api.Response{Success: false, Message: "Error al crear el fichero"}
	}

	return api.Response{Success: true, Message: "Fichero creado con éxito"}
}

func (s *server) deleteFile(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}
	if req.Path == "" {
		return api.Response{Success: false, Message: "Falta el path del fichero"}
	}
	path, err := s.safePath(req.Username, req.Path)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return api.Response{Success: false, Message: "El fichero no existe o es un directorio"}
	}

	if err := os.Remove(path); err != nil {
		return api.Response{Success: false, Message: "Error al borrar fichero"}
	}

	return api.Response{Success: true, Message: "Fichero borrado con éxito"}
}

func (s *server) modifyFile(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}
	if req.Path == "" {
		return api.Response{Success: false, Message: "Falta el path del fichero"}
	}
	path, err := s.safePath(req.Username, req.Path)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return api.Response{Success: false, Message: "El fichero no existe o es un directorio"}
	}

	err = os.WriteFile(path, []byte(req.Data), 0644)
	if err != nil {
		return api.Response{Success: false, Message: "Error al modificar el fichero"}
	}

	return api.Response{Success: true, Message: "Fichero modificado con éxito"}
}

func (s *server) readFile(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}
	if req.Path == "" {
		return api.Response{Success: false, Message: "Falta el path del fichero"}
	}
	path, err := s.safePath(req.Username, req.Path)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return api.Response{Success: false, Message: "Error al leer el fichero"}
	}

	return api.Response{Success: true, Message: "Fichero leído con éxito", Data: string(data)}
}

func (s *server) createDir(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}
	if req.Path == "" {
		return api.Response{Success: false, Message: "Falta el path del directorio"}
	}
	path, err := s.safePath(req.Username, req.Path)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	err = os.MkdirAll(path, 0755)
	if err != nil {
		return api.Response{Success: false, Message: "Error al crear el directorio"}
	}

	return api.Response{Success: true, Message: "Directorio creado con éxito"}
}

func (s *server) deleteDir(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}
	if req.Path == "" {
		return api.Response{Success: false, Message: "Falta el path del directorio"}
	}
	path, err := s.safePath(req.Username, req.Path)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return api.Response{Success: false, Message: "El directorio no existe o no es un directorio"}
	}

	if err := os.RemoveAll(path); err != nil {
		return api.Response{Success: false, Message: "Error al borrar directorio"}
	}

	return api.Response{Success: true, Message: "Directorio borrado con éxito"}
}

func (s *server) listFiles(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	path, err := s.safePath(req.Username, req.Path)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	var files []string
	entries, err := os.ReadDir(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return api.Response{Success: true, Message: "Directorio vacío", Files: []string{}}
		}
		return api.Response{Success: false, Message: "Error al listar ficheros"}
	}

	for _, entry := range entries {
		suffix := ""
		if entry.IsDir() {
			suffix = "/"
		}
		files = append(files, entry.Name()+suffix)
	}

	return api.Response{Success: true, Message: "Listado correcto", Files: files}
}
