// El paquete server contiene el codigo del servidor.
// Interactua con el cliente mediante una API JSON/HTTP
package server

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"sprout/pkg/api"
	"sprout/pkg/netcfg"
	"sprout/pkg/roles"
	"sprout/pkg/store"
	"sprout/pkg/utils"
)

// server encapsula el estado de nuestro servidor
type server struct {
	db            store.Store // base de datos
	log           *log.Logger // logger para mensajes de error e informacion
	mu            sync.Mutex  // Para exclusion a la hora de lectura y escritura
	loginAttempts map[string]*loginAttempt
	pendingTOTP   map[string]pendingTOTPLogin // No le pongo el * porque no lo modifico una vez añadido
	sessionKeys   map[string][]byte
	pendingKey    map[string]pendingKeyLogin
	roles         *roles.RoleStore
}

type session struct {
	Token     string
	ExpiresAt time.Time
}

const sessionDuration = 24 * time.Hour
const lengthToken = 16
const temporalTokenDuration = 2 * time.Minute
const fileTimestampNamespace = "file_timestamps"

// Run inicia la base de datos y arranca el servidor HTTPS.
func Run() error {
	cfg := netcfg.Load()

	// Crear la carpeta 'data' en caso de que no exista.
	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("error creando la carpeta 'data': %w", err)
	}

	// Abrimos la base de datos usando el motor bbolt
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error abriendo base de datos: %v", err)
	}

	// Creamos RoleStore y los roles por defecto
	rs := roles.NewRoleStore(db)

	for _, name := range []string{roles.AdminRole, roles.DefaultRole} {
		exists, err := rs.RoleExists(name)
		if err != nil {
			return fmt.Errorf("error comprobando rol %q: %w", name, err)
		}
		if !exists {
			if err := rs.CreateRole(name); err != nil {
				return fmt.Errorf("error creando rol %q: %w", name, err)
			}
		}
	}

	if cfg.AdminUser != "" {
		_, err := db.Get("auth", []byte(cfg.AdminUser))
		if errors.Is(err, store.ErrKeyNotFound) || errors.Is(err, store.ErrNamespaceNotFound) {
			log.Printf("[srv] SPROUT_ADMIN=%q pero el usuario no existe aún en la DB", cfg.AdminUser)
		} else if err != nil {
			log.Printf("[srv] error comprobando usuario admin %q: %v", cfg.AdminUser, err)
		} else {
			ok, err := rs.HasRole(cfg.AdminUser, roles.AdminRole)
			if err != nil {
				log.Printf("[srv] error comprobando rol admin de %q: %v", cfg.AdminUser, err)
			} else if !ok {
				if err := rs.AssignRole(cfg.AdminUser, roles.AdminRole); err != nil {
					log.Printf("[srv] no se pudo asignar rol admin a %q: %v", cfg.AdminUser, err)
				} else {
					log.Printf("[srv] rol admin asignado a %q", cfg.AdminUser)
				}
			}
		}
	}

	// Creamos nuestro servidor con su logger con prefijo 'srv'
	srv := &server{
		db:            db,
		log:           log.New(os.Stdout, "[srv] ", log.LstdFlags),
		loginAttempts: make(map[string]*loginAttempt),
		pendingTOTP:   make(map[string]pendingTOTPLogin),
		sessionKeys:   make(map[string][]byte),
		pendingKey:    make(map[string]pendingKeyLogin),
		roles:         rs,
	}

	// Al terminar, cerramos la base de datos
	defer srv.db.Close()

	// Construimos un mux y asociamos /api a nuestro apiHandler,
	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	// Iniciamos el servidor HTTP.
	httpSrv := &http.Server{
		Addr:              cfg.ServerAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	if _, err := os.Stat(cfg.TLSCertFile); err != nil {
		return fmt.Errorf("certificado TLS no disponible en %q: %w", cfg.TLSCertFile, err)
	}
	if _, err := os.Stat(cfg.TLSKeyFile); err != nil {
		return fmt.Errorf("clave TLS no disponible en %q: %w", cfg.TLSKeyFile, err)
	}

	srv.log.Printf("Servidor HTTPS escuchando en %s", cfg.ServerAddr)
	return httpSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
}

// apiHandler decodifica la solicitud JSON, la despacha
// a la funcion correspondiente y devuelve la respuesta JSON.
func (s *server) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metodo no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Limitamos el tamano del body para evitar sorpresas.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB

	var req api.Request
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}

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
	case api.ActionTOTPDisable:
		res = s.totpDisable(req)
	// Public private key
	case api.ActionKeySetup:
		res = s.keySetup(req)
	case api.ActionKeyDisable:
		res = s.keyDisable(req)
	case api.ActionLoginKey:
		res = s.loginKey(req)
	case api.ActionVerifyPassword:
		res = s.verifyPassword(req)
	// Roles management
	case api.ActionAssignRole:
		res = s.assignRole(req)
	case api.ActionRemoveRole:
		res = s.removeRole(req)
	case api.ActionListRoles:
		res = s.listRoles(req)
	case api.ActionGetUserRoles:
		res = s.getUserRoles(req)
	case api.ActionCreateRole:
		res = s.createRole(req)
	case api.ActionDeleteRole:
		res = s.deleteRole(req)

	default:
		res = api.Response{Success: false, Message: "Accion desconocida"}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// registerUser registra un nuevo usuario, si no existe.
func (s *server) registerUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	if err := utils.ValidateUsername(req.Username); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	if err := utils.ValidatePassword(req.Password); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	exists, err := s.userExists(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar usuario"}
	}
	if exists {
		return api.Response{Success: false, Message: "El usuario ya existe"}
	}

	hash, err := utils.HashPassword(req.Password)
	if err != nil {
		return api.Response{Success: false, Message: fmt.Sprintf("Error al hashear contrasena: %v", err)}
	}

	cryptoMeta, dek, err := generateUserCryptoMetadata(req.Password)
	if err != nil {
		return api.Response{Success: false, Message: "Error al inicializar cifrado del usuario"}
	}

	cryptoMetaBytes, err := json.Marshal(cryptoMeta)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar cifrado del usuario"}
	}

	if err := s.db.Put("auth", []byte(req.Username), []byte(hash)); err != nil {
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}

	if err := s.db.Put(cryptoNamespace, []byte(req.Username), cryptoMetaBytes); err != nil {
		return api.Response{Success: false, Message: "Error al guardar metadatos criptograficos"}
	}

	encryptedUserdata, err := encryptUserdata(dek, []byte(""))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar datos iniciales del usuario"}
	}

	if err := s.db.Put("userdata", []byte(req.Username), encryptedUserdata); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	if err := s.roles.AssignRole(req.Username, roles.DefaultRole); err != nil {
		return api.Response{Success: false, Message: "Error al asignar rol por defecto"}
	}

	return api.Response{Success: true, Message: "Usuario registrado"}
}

// loginUser valida credenciales y desbloquea la clave en memoria.
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

	storedPass, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		utils.VerifyPassword(req.Password, utils.DummyHash)
		s.RegisterLoginFailure(req.Username)
		return api.Response{Success: false, Message: "Credenciales invalidos"}
	}

	valid, err := utils.VerifyPassword(req.Password, string(storedPass))
	if err != nil || !valid {
		s.RegisterLoginFailure(req.Username)
		return api.Response{Success: false, Message: "Credenciales invalidos"}
	}

	cryptoMetaBytes, err := s.db.Get(cryptoNamespace, []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al recuperar credenciales criptograficas"}
	}

	dek, err := unwrapUserDEK(req.Password, cryptoMetaBytes)
	if err != nil {
		return api.Response{Success: false, Message: "Error al desbloquear los datos del usuario"}
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
		s.storeSessionKey(req.Username, dek)
		return api.Response{
			Success:      true,
			Message:      "Contraseña correcta, introduce el codigo TOTP",
			RequiresTOTP: true,
			TempToken:    tempToken,
		}
	}

	// Compruebo si tiene public private key
	kd, err := s.getKeyAuthData(req.Username)
	if err == nil && kd.Enabled {
		challenge, err := utils.NewRandomToken(32)
		if err != nil {
			return api.Response{Success: false, Message: "Error al generar challenge"}
		}
		tempToken, err := utils.NewRandomToken(lengthToken)
		if err != nil {
			return api.Response{Success: false, Message: "Error al generar token temporal"}
		}
		s.mu.Lock()
		s.pendingKey[tempToken] = pendingKeyLogin{
			Username:  req.Username,
			Challenge: []byte(challenge),
			ExpiresAt: time.Now().Add(temporalTokenDuration),
		}
		s.mu.Unlock()
		s.storeSessionKey(req.Username, dek)
		return api.Response{Success: true, RequiresKey: true, TempToken: tempToken, Challenge: []byte(challenge)}
	}

	//Sin TOTP ni clave publica - creo la sesion
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
		return api.Response{Success: false, Message: "Error al crear sesion"}
	}

	s.storeSessionKey(req.Username, dek)
	isAdmin, _ := s.roles.HasRole(req.Username, roles.AdminRole)

	return api.Response{Success: true, Message: "Login exitoso", Token: token, TOTPEnabled: false, IsAdmin: isAdmin}
}

// fetchData verifica el token y retorna el contenido descifrado.
func (s *server) fetchData(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}

	rawData, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
	}

	dek, ok := s.getSessionKey(req.Username)
	if !ok {
		return api.Response{Success: false, Message: "Sesion inconsistente: vuelve a iniciar sesion", SessionExpired: true}
	}

	plaintext, err := decryptUserdata(dek, rawData)
	if err != nil {
		return api.Response{Success: false, Message: "Error al descifrar datos del usuario"}
	}

	return api.Response{
		Success: true,
		Message: "Datos privados de " + req.Username,
		Data:    string(plaintext),
	}
}

// updateData cifra y actualiza los datos privados del usuario.
func (s *server) updateData(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}

	dek, ok := s.getSessionKey(req.Username)
	if !ok {
		return api.Response{Success: false, Message: "Sesion inconsistente: vuelve a iniciar sesion", SessionExpired: true}
	}

	encrypted, err := encryptUserdata(dek, []byte(req.Data))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar datos del usuario"}
	}

	if err := s.db.Put("userdata", []byte(req.Username), encrypted); err != nil {
		return api.Response{Success: false, Message: "Error al actualizar datos del usuario"}
	}

	return api.Response{Success: true, Message: "Datos de usuario actualizados"}
}

// logoutUser borra la sesion y la clave en memoria.
func (s *server) logoutUser(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}

	if err := s.db.Delete("sessions", []byte(req.Username)); err != nil {
		return api.Response{Success: false, Message: "Error al cerrar sesion"}
	}

	s.clearSessionKey(req.Username)
	return api.Response{Success: true, Message: "Sesion cerrada correctamente"}
}

// userExists comprueba si existe un usuario en 'auth'.
func (s *server) userExists(username string) (bool, error) {
	_, err := s.db.Get("auth", []byte(username))
	if err != nil {
		if errors.Is(err, store.ErrNamespaceNotFound) || errors.Is(err, store.ErrKeyNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isTokenValid comprueba que el token almacenado coincida con el proporcionado.
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
		_ = s.db.Delete("sessions", []byte(username))
		s.clearSessionKey(username)
		return false
	}
	return sess.Token == token
}

// safePath valida el path para evitar Path Traversal.
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

	if !strings.HasPrefix(targetPathAbs, baseDirAbs) {
		return "", errors.New("acceso denegado o path invalido")
	}
	return targetPathAbs, nil
}

func (s *server) createFile(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
	}
	if req.Path == "" {
		return api.Response{Success: false, Message: "Falta el path del fichero"}
	}
	path, err := s.safePath(req.Username, req.Path)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	dek, ok := s.getSessionKey(req.Username)
	if !ok {
		return api.Response{Success: false, Message: "Sesion inconsistente: vuelve a iniciar sesion"}
	}

	encrypted, err := encryptFileData(dek, req.Path, []byte(req.Data))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el fichero"}
	}

	if err := os.WriteFile(path, encrypted, 0644); err != nil {
		return api.Response{Success: false, Message: "Error al crear el fichero"}
	}

	if err := s.storeFileTimestamp(req.Username, req.Path, path, dek); err != nil {
		return api.Response{Success: false, Message: "Fichero creado, pero no se pudo guardar su timestamp"}
	}

	return api.Response{Success: true, Message: "Fichero creado con exito"}
}

func (s *server) deleteFile(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
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
	_ = s.db.Delete(fileTimestampNamespace, fileTimestampKey(req.Username, req.Path))

	return api.Response{Success: true, Message: "Fichero borrado con exito"}
}

func (s *server) modifyFile(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
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

	dek, ok := s.getSessionKey(req.Username)
	if !ok {
		return api.Response{Success: false, Message: "Sesion inconsistente: vuelve a iniciar sesion"}
	}

	if err := s.checkFileTimestamp(req.Username, req.Path, path, dek); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	encrypted, err := encryptFileData(dek, req.Path, []byte(req.Data))
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el fichero"}
	}

	if err := os.WriteFile(path, encrypted, 0644); err != nil {
		return api.Response{Success: false, Message: "Error al modificar el fichero"}
	}

	if err := s.storeFileTimestamp(req.Username, req.Path, path, dek); err != nil {
		return api.Response{Success: false, Message: "Fichero modificado, pero no se pudo actualizar su timestamp"}
	}

	return api.Response{Success: true, Message: "Fichero modificado con exito"}
}

func (s *server) readFile(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
	}
	if req.Path == "" {
		return api.Response{Success: false, Message: "Falta el path del fichero"}
	}
	path, err := s.safePath(req.Username, req.Path)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	dek, ok := s.getSessionKey(req.Username)
	if !ok {
		return api.Response{Success: false, Message: "Sesion inconsistente: vuelve a iniciar sesion"}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return api.Response{Success: false, Message: "Error al leer el fichero"}
	}

	if err := s.checkFileTimestamp(req.Username, req.Path, path, dek); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	plaintext, err := decryptFileData(dek, req.Path, data)
	if err != nil {
		return api.Response{Success: false, Message: "Error al descifrar el fichero"}
	}

	return api.Response{Success: true, Message: "Fichero leido con exito", Data: string(plaintext)}
}

func (s *server) createDir(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
	}
	if req.Path == "" {
		return api.Response{Success: false, Message: "Falta el path del directorio"}
	}
	path, err := s.safePath(req.Username, req.Path)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	if err := os.MkdirAll(path, 0755); err != nil {
		return api.Response{Success: false, Message: "Error al crear el directorio"}
	}

	return api.Response{Success: true, Message: "Directorio creado con exito"}
}

func (s *server) deleteDir(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
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

	return api.Response{Success: true, Message: "Directorio borrado con exito"}
}

func (s *server) listFiles(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada"}
	}

	path, err := s.safePath(req.Username, req.Path)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	var files []string
	entries, err := os.ReadDir(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return api.Response{Success: true, Message: "Directorio vacio", Files: []string{}}
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

func fileTimestampKey(username, reqPath string) []byte {
	return []byte(username + "\x00" + reqPath)
}

func (s *server) storeFileTimestamp(username, reqPath, absPath string, baseDEK []byte) error {
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("no se pudo leer el timestamp del fichero: %w", err)
	}

	timestampRaw := []byte(strconv.FormatInt(info.ModTime().UnixNano(), 10))
	timestampKey, err := deriveSubkey(baseDEK, "timestamp:"+reqPath, dekLen)
	if err != nil {
		return fmt.Errorf("no se pudo derivar clave para timestamp: %w", err)
	}

	ciphertext, nonce, err := encryptWithGCM(timestampKey, timestampRaw)
	if err != nil {
		return fmt.Errorf("no se pudo cifrar el timestamp del fichero: %w", err)
	}

	blobBytes, err := json.Marshal(gcmBlob{
		Version:    cryptoVersion,
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return fmt.Errorf("no se pudo serializar el timestamp cifrado: %w", err)
	}

	return s.db.Put(fileTimestampNamespace, fileTimestampKey(username, reqPath), blobBytes)
}

func (s *server) checkFileTimestamp(username, reqPath, absPath string, baseDEK []byte) error {
	stored, err := s.db.Get(fileTimestampNamespace, fileTimestampKey(username, reqPath))
	if err != nil {
		return fmt.Errorf("el timestamp del fichero no coincide o no existe en la base de datos: %w", err)
	}

	timestampKey, err := deriveSubkey(baseDEK, "timestamp:"+reqPath, dekLen)
	if err != nil {
		return fmt.Errorf("no se pudo derivar clave para validar timestamp: %w", err)
	}

	var blob gcmBlob
	if err := json.Unmarshal(stored, &blob); err != nil {
		return fmt.Errorf("el timestamp almacenado del fichero no es valido: %w", err)
	}
	if blob.Version != cryptoVersion {
		return fmt.Errorf("version de timestamp cifrado no soportada: %d", blob.Version)
	}

	nonce, err := base64.RawStdEncoding.DecodeString(blob.Nonce)
	if err != nil {
		return fmt.Errorf("nonce de timestamp invalido: %w", err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(blob.Ciphertext)
	if err != nil {
		return fmt.Errorf("ciphertext de timestamp invalido: %w", err)
	}

	timestampRaw, err := decryptWithGCM(timestampKey, nonce, ciphertext)
	if err != nil {
		return fmt.Errorf("no se pudo descifrar el timestamp almacenado del fichero: %w", err)
	}

	storedUnixNano, err := strconv.ParseInt(string(timestampRaw), 10, 64)
	if err != nil {
		return fmt.Errorf("el timestamp almacenado del fichero es invalido: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("no se pudo leer el timestamp actual del fichero: %w", err)
	}

	if info.ModTime().UnixNano() != storedUnixNano {
		return fmt.Errorf("el fichero ha sido modificado fuera de Sprout")
	}

	return nil
}

func (s *server) storeSessionKey(username string, dek []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sessionKeys == nil {
		s.sessionKeys = make(map[string][]byte)
	}

	keyCopy := make([]byte, len(dek))
	copy(keyCopy, dek)
	s.sessionKeys[username] = keyCopy
}

func (s *server) getSessionKey(username string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dek, ok := s.sessionKeys[username]
	if !ok {
		return nil, false
	}

	keyCopy := make([]byte, len(dek))
	copy(keyCopy, dek)
	return keyCopy, true
}

func (s *server) clearSessionKey(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if dek, ok := s.sessionKeys[username]; ok {
		for i := range dek {
			dek[i] = 0
		}
		delete(s.sessionKeys, username)
	}
}

func (s *server) verifyPassword(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}

	data, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			return api.Response{Success: false, Message: "Contraseña incorrecta"}
		}
		s.log.Printf("error obteniendo credenciales de %q: %v", req.Username, err)
		return api.Response{Success: false, Message: "Error verificando contraseña"}
	}

	ok, err := utils.VerifyPassword(req.Password, string(data))
	if err != nil || !ok {
		return api.Response{Success: false, Message: "Contraseña incorrecta"}
	}

	return api.Response{Success: true, Message: "Contraseña correcta"}
}
