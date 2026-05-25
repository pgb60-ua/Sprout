// El paquete client contiene la lógica de interacción con el usuario
// así como de comunicación con el servidor.
package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"sprout/pkg/api"
	"sprout/pkg/backups"
	"sprout/pkg/logs"
	"sprout/pkg/netcfg"
	"sprout/pkg/ui"
	"sprout/pkg/utils"

	"github.com/skip2/go-qrcode"
)

// client estructura interna no exportada que controla
// el estado de la sesión (usuario, token) y logger.
type client struct {
	log            *log.Logger
	currentUser    string
	authToken      string
	totpEnabled    bool // Para saber si tiene el totp enabled y cambiar el texto y opciones
	keyAuthEnabled bool // Para saber si tiene la firma publica - privada enabled y cambiar el texto y opciones
	messageKey     []byte
	httpClient     *http.Client
	apiEndpoint    string
	isAdmin        bool
}

// Run es la única función exportada de este paquete.
// Crea un cliente interno y ejecuta el bucle principal.
func Run() {
	cfg := netcfg.Load()

	httpClient, err := newSecureHTTPClient(cfg.TLSCAFile)
	if err != nil {
		log.New(os.Stdout, "[cli] ", log.LstdFlags).Printf("No se pudo inicializar cliente HTTPS: %v\n", err)
		return
	}

	// Creamos un logger con prefijo 'cli' para identificar
	// los mensajes en la consola.
	c := &client{
		log:         log.New(os.Stdout, "[cli] ", log.LstdFlags),
		httpClient:  httpClient,
		apiEndpoint: cfg.APIEndpoint,
	}
	c.runLoop()
}

// runLoop maneja la lógica del menú principal.
// Se muestran distintas opciones en función de si hay un usuario con sesión activa
func (c *client) runLoop() {
	for {
		ui.ClearScreen()

		// Construimos un título que muestre el usuario activo, si lo hubiera.
		var title string
		if c.currentUser == "" {
			title = "Menú"
		} else {
			title = fmt.Sprintf("Menú (%s)", c.currentUser)
		}

		// Generamos las opciones dinámicamente, según si hay un login activo.
		var options []string
		if c.currentUser == "" {
			// Usuario NO logueado: Registro, Login, Salir
			options = []string{
				"Registrar usuario",
				"Iniciar sesión",
				"Salir",
			}
		} else {
			totpOption := "Activar TOTP"
			if c.totpEnabled {
				totpOption = "Gestionar TOTP"
			}
			keyOption := "Activar clave publica"
			if c.keyAuthEnabled {
				keyOption = "Desactivar clave publica"
			}

			// Usuario activo: Ver datos, Actualizar datos, TOTP, ficheros, panel admin, Logout, Salir
			options = []string{
				"Ver datos",
				"Actualizar datos",
				totpOption,
				"Mensajes",
				keyOption,
				"Gestión de ficheros",
			}
			if c.isAdmin {
				options = append(options, "Administración")
			}
			options = append(options, "Cerrar sesión", "Salir")
		}

		// Mostramos el menú y obtenemos la elección del usuario.
		choice := ui.PrintMenu(title, options)

		// Hay que mapear la opción elegida según si está logueado o no.
		if c.currentUser == "" {
			// Caso NO logueado
			switch choice {
			case 1:
				c.registerUser()
			case 2:
				c.loginUser()
			case 3:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		} else {
			// Caso logueado
			switch choice {
			case 1:
				c.fetchData()
			case 2:
				c.updateData()
			case 3:
				c.manageTOTP()
			case 4:
				c.messageMenu()
			case 5:
				c.manageKey()
			case 6:
				c.fileManagerMenu()
			case 7:
				if c.isAdmin {
					c.adminMenu()
				} else {
					c.logoutUser()
				}
			case 8:
				if c.isAdmin {
					c.logoutUser()
				} else {
					// Opción Salir
					c.log.Println("Saliendo del cliente...")
					return
				}
			case 9:
				if c.isAdmin {
					// Opción Salir
					c.log.Println("Saliendo del cliente...")
					return
				}
			}
		}

		// Pausa para que el usuario vea resultados.
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
func (c *client) registerUser() {
	ui.ClearScreen()
	fmt.Println("** Registro de usuario **")

	username := ui.ReadInput("Nombre de usuario")
	password, err := ui.ReadPassword("Contraseña")

	if err != nil {
		c.log.Println("No se ha podido obtener la contraseña, registro cancelado: ", err)
		return
	}

	publicKey, privateKey, err := utils.GenerateMessageKeyPair()
	if err != nil {
		c.log.Println("No se han podido generar claves de mensajes:", err)
		return
	}
	encodedPublicKey, err := utils.EncodeMessagePublicKey(publicKey)
	if err != nil {
		c.log.Println("No se ha podido codificar la clave publica de mensajes:", err)
		return
	}

	// Enviamos la acción al servidor
	res := c.sendRequest(api.Request{
		Action:           api.ActionRegister,
		Username:         username,
		Password:         password,
		MessagePublicKey: encodedPublicKey,
	})

	// Mostramos resultado
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, probamos loguear automáticamente.
	if res.Success {
		if err := utils.EncryptMessagePrivateKey(privateKey, password, username); err != nil {
			fmt.Println("Usuario registrado, pero no se pudo guardar la clave privada de mensajes:", err)
		}

		c.log.Println("Registro exitoso; intentando login automático...")

		loginRes := c.sendRequest(api.Request{
			Action:   api.ActionLogin,
			Username: username,
			Password: password,
		})
		if loginRes.Success {
			c.currentUser = username
			c.authToken = loginRes.Token
			c.isAdmin = loginRes.IsAdmin
			c.totpEnabled = loginRes.TOTPEnabled
			c.keyAuthEnabled = loginRes.KeyAuthEnabled
			c.messageKey = copyBytes(privateKey)
			fmt.Println("Login automático exitoso. Token guardado.")
		} else {
			fmt.Println("No se ha podido hacer login automático:", loginRes.Message)
		}
	}
}

// loginUser pide credenciales y realiza un login en el servidor.
func (c *client) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Inicio de sesión **")

	username := ui.ReadInput("Nombre de usuario")
	password, err := ui.ReadPassword("Contraseña")

	if err != nil {
		c.log.Println("No se ha podido obtener la contraseña, registro cancelado: ", err)
		return
	}

	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: password,
	})

	if !res.Success {
		fmt.Println("Error de inicio de sesión: ", res.Message)
		return
	}

	// Segundo factor TOTP
	if res.RequiresTOTP {
		code := ui.ReadInput("Introduce el codigo TOTP")
		totopRes := c.sendRequest(api.Request{
			Action:    api.ActionLoginTOTP,
			TempToken: res.TempToken,
			TOTPCode:  code,
		})
		fmt.Println("Éxito:", totopRes.Success)
		fmt.Println("Mensaje:", totopRes.Message)
		if totopRes.Success {
			c.isAdmin = totopRes.IsAdmin
			c.currentUser = username
			c.authToken = totopRes.Token
			c.totpEnabled = true
			c.keyAuthEnabled = totopRes.KeyAuthEnabled
			c.unlockMessageKey(password, username)
		}
		return
	}

	// Si tiene clave publica
	if res.RequiresKey {

		// Descifro la clave privada del disco
		priv, err := utils.DecryptPrivateKey(password, username)
		if err != nil {
			fmt.Println("Error al descifrar la clave privada:", err)
			return
		}

		// Firmo el challenge
		signature := ed25519.Sign(priv, res.Challenge)

		// Envio la firma al servidor
		r := c.sendRequest(api.Request{
			Action:    api.ActionLoginKey,
			TempToken: res.TempToken,
			Signature: signature,
		})
		fmt.Println("Éxito: ", r.Success)
		fmt.Println("Mensaje: ", r.Message)
		if r.Success {
			c.currentUser = username
			c.isAdmin = r.IsAdmin
			c.authToken = r.Token
			c.keyAuthEnabled = r.KeyAuthEnabled
			c.unlockMessageKey(password, username)
		}
		return
	}

	// Sin TOTP ni clave publica
	c.currentUser = username
	c.isAdmin = res.IsAdmin
	c.authToken = res.Token
	c.totpEnabled = res.TOTPEnabled
	c.keyAuthEnabled = res.KeyAuthEnabled
	c.unlockMessageKey(password, username)
	fmt.Println("Sesión iniciada con éxito. Token guardado.")
}

// fetchData pide datos privados al servidor.
// El servidor devuelve la data asociada al usuario logueado.
func (c *client) fetchData() {
	ui.ClearScreen()
	fmt.Println("** Obtener datos del usuario **")

	// Chequeo básico de que haya sesión
	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Hacemos la request con ActionFetchData
	res := c.sendRequest(api.Request{
		Action:   api.ActionFetchData,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, mostramos la data recibida
	if res.Success {
		fmt.Println("Tus datos:", res.Data)
	}

	if !res.Success && res.SessionExpired {
		c.handleSessionExpired(res)
	}
}

// updateData pide nuevo texto y lo envía al servidor con ActionUpdateData.
func (c *client) updateData() {
	ui.ClearScreen()
	fmt.Println("** Actualizar datos del usuario **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Leemos la nueva Data
	newData := ui.ReadInput("Introduce el contenido que desees almacenar")

	// Enviamos la solicitud de actualización
	res := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     newData,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	if !res.Success && res.SessionExpired {
		c.handleSessionExpired(res)
	}
}

// logoutUser llama a la acción logout en el servidor, y si es exitosa,
// borra la sesión local (currentUser/authToken).
func (c *client) logoutUser() {
	ui.ClearScreen()
	fmt.Println("** Cerrar sesión **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado.")
		return
	}

	// Llamamos al servidor con la acción ActionLogout
	res := c.sendRequest(api.Request{
		Action:   api.ActionLogout,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, limpiamos la sesión local.
	if res.Success {
		clearBytes(c.messageKey)
		c.isAdmin = false
		c.currentUser = ""
		c.authToken = ""
		c.totpEnabled = false
		c.keyAuthEnabled = false
		c.messageKey = nil
	}

	if !res.Success && res.SessionExpired {
		c.handleSessionExpired(res)
	}
}

func (c *client) unlockMessageKey(password, username string) {
	key, err := utils.DecryptMessagePrivateKey(password, username)
	if err != nil {
		clearBytes(c.messageKey)
		c.messageKey = nil
		fmt.Println("Aviso: no se pudo desbloquear la clave privada de mensajes:", err)
		return
	}
	clearBytes(c.messageKey)
	c.messageKey = key
}

func (c *client) handleSessionExpired(res api.Response) {
	if !res.SessionExpired {
		return
	}
	fmt.Println("Sesión expirada. Vuelve a iniciar sesión.")
	clearBytes(c.messageKey)
	c.currentUser = ""
	c.authToken = ""
	c.totpEnabled = false
	c.keyAuthEnabled = false
	c.isAdmin = false
	c.messageKey = nil
}

func copyBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func clearBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// sendRequest envía un POST JSON a la URL del servidor y
// devuelve la respuesta decodificada. Se usa para todas las acciones.
func (c *client) sendRequest(req api.Request) api.Response {
	jsonData, err := json.Marshal(req)
	if err != nil {
		c.log.Println("No se ha podido serializar la petición JSON:", err)
		return api.Response{Success: false, Message: "Error interno del cliente"}
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.apiEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		c.log.Println("No se ha podido construir la petición HTTP:", err)
		return api.Response{Success: false, Message: "Error interno del cliente"}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		fmt.Println("Error al contactar con el servidor:", err)
		return api.Response{Success: false, Message: "Error de conexión"}
	}
	defer resp.Body.Close()

	// Leemos el body de respuesta y lo desempaquetamos en un api.Response.
	// Si el servidor ha respondido con un error HTTP, intentamos igualmente
	// descodificar un api.Response para mostrar el mensaje.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.log.Println("No se ha podido leer la respuesta:", err)
		return api.Response{Success: false, Message: "Respuesta inválida del servidor"}
	}
	var res api.Response
	if err := json.Unmarshal(body, &res); err != nil {
		c.log.Println("No se ha podido descodificar la respuesta JSON:", err)
		return api.Response{Success: false, Message: "Respuesta inválida del servidor"}
	}
	return res
}

func (c *client) maybeOfferDeleteOutOfSyncFile(path string, res api.Response) {
	if path == "" || res.Success || !isTimestampMismatchMessage(res.Message) {
		return
	}

	if !ui.Confirm("El fichero parece haber sido modificado fuera de Sprout. ¿Quieres borrarlo?") {
		return
	}

	deleteRes := c.sendRequest(api.Request{
		Action:   api.ActionDeleteFile,
		Username: c.currentUser,
		Token:    c.authToken,
		Path:     path,
	})
	if !deleteRes.Success {
		fmt.Println("No se pudo borrar el fichero:", deleteRes.Message)
		return
	} else {
		fmt.Println("Éxito:", deleteRes.Success)
		fmt.Println("Mensaje:", deleteRes.Message)
	}

}

func isTimestampMismatchMessage(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "timestamp") || strings.Contains(lower, "modificado fuera")
}

func newSecureHTTPClient(caFile string) (*http.Client, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer la CA en %q: %w", caFile, err)
	}

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("el fichero %q no contiene certificados PEM validos", caFile)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		},
	}

	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}, nil
}

func (c *client) accessRemoteLogs() {
	ui.ClearScreen()
	fmt.Println("** Acceso a logs remotos **")

	logs.Run()

	fmt.Println("Visor de logs finalizado.")
}

func (c *client) accessRemoteBackups() bool {
	ui.ClearScreen()
	fmt.Println("** Acceso a backups **")

	if !ui.Confirm("¿Quieres continuar") {
		return false
	}

	backups.Run()
	return true
}

// fileManagerMenu permite al usuario gestionar archivos y carpetas.
func (c *client) fileManagerMenu() {
	for {
		ui.ClearScreen()
		title := "Gestión de ficheros y carpetas"
		options := []string{
			"Listar directorio",
			"Crear fichero",
			"Borrar fichero",
			"Modificar fichero",
			"Visualizar fichero",
			"Crear carpeta",
			"Borrar carpeta",
			"Ver metadatos",
			"Ver comentarios",
			"Añadir comentario",
			"Borrar comentario",
			"Modificar permisos lógicos",
			"Modificar rol/grupo",
			"Modificar tags",
			"Filtrar por tag",
			"Ver mis carpetas compartidas",
			"Gestionar carpeta compartida",
			"Volver al menú principal",
		}

		choice := ui.PrintMenu(title, options)
		switch choice {
		case 1: // Listar directorio
			path := ui.ReadInput("Introduce el directorio a listar (deja vací­o para la raí­z)")
			if !c.ensureLogicalPermission(path, true, 'r', "listar el directorio") {
				break
			}
			res := c.sendRequest(api.Request{
				Action:   api.ActionListFiles,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success && len(res.Files) > 0 {
				fmt.Println("Contenido:")
				for _, f := range res.Files {
					fmt.Println("-", f)
				}
			}
		case 2: // Crear fichero
			path := ui.ReadInput("Introduce la ruta/nombre del nuevo fichero")
			if !c.ensureParentLogicalPermission(path, 'w', "crear el fichero") {
				break
			}
			data := ui.ReadInput("Introduce el contenido del fichero")
			res := c.sendRequest(api.Request{
				Action:   api.ActionCreateFile,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
				Data:     data,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
		case 3: // Borrar fichero
			path := ui.ReadInput("Introduce la ruta/nombre del fichero a borrar")
			if !c.ensureLogicalPermission(path, true, 'w', "borrar el fichero") {
				break
			}
			res := c.sendRequest(api.Request{
				Action:   api.ActionDeleteFile,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
		case 4: // Modificar fichero
			path := ui.ReadInput("Introduce la ruta/nombre del fichero a modificar")
			if !c.ensureLogicalPermission(path, true, 'w', "modificar el fichero") {
				break
			}
			data := ui.ReadMultiline("Introduce el nuevo contenido del fichero, el contenido actual se sobrescribirá.")
			res := c.sendRequest(api.Request{
				Action:   api.ActionModifyFile,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
				Data:     data,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			c.maybeOfferDeleteOutOfSyncFile(path, res)
		case 5: // Visualizar fichero
			path := ui.ReadInput("Introduce la ruta/nombre del fichero a visualizar")
			if !c.ensureLogicalPermission(path, true, 'r', "visualizar el fichero") {
				break
			}
			res := c.sendRequest(api.Request{
				Action:   api.ActionReadFile,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success {
				fmt.Println("--- Contenido ---")
				fmt.Println(res.Data)
				fmt.Println("-----------------")
			} else {
				c.maybeOfferDeleteOutOfSyncFile(path, res)
			}
		case 6: // Crear carpeta
			path := ui.ReadInput("Introduce la ruta/nombre de la nueva carpeta")
			if isClientRootPath(path) {
				fmt.Println("Éxito: false")
				fmt.Println("Mensaje: no se puede operar sobre la carpeta raíz del usuario")
				break
			}
			if !c.ensureParentLogicalPermission(path, 'w', "crear la carpeta") {
				break
			}
			res := c.sendRequest(api.Request{
				Action:   api.ActionCreateDir,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
		case 7: // Borrar carpeta
			path := ui.ReadInput("Introduce la ruta/nombre de la carpeta a borrar")
			if isClientRootPath(path) {
				fmt.Println("Éxito: false")
				fmt.Println("Mensaje: no se puede operar sobre la carpeta raíz del usuario")
				break
			}
			if !c.ensureLogicalPermission(path, true, 'w', "borrar la carpeta") {
				break
			}
			res := c.sendRequest(api.Request{
				Action:   api.ActionDeleteDir,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
		case 8: // Ver metadatos
			path := ui.ReadInput("Introduce la ruta/nombre del fichero o carpeta")
			res := c.sendRequest(api.Request{
				Action:   api.ActionGetFileMetadata,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success && res.FileMetadata != nil {
				printFileMetadata(*res.FileMetadata)
			} else {
				c.maybeOfferDeleteOutOfSyncFile(path, res)
			}
		case 9: // Ver comentarios
			path := ui.ReadInput("Introduce la ruta/nombre del fichero o carpeta")
			if !c.ensureLogicalPermission(path, true, 'r', "ver comentarios") {
				break
			}
			res := c.sendRequest(api.Request{
				Action:   api.ActionListFileComments,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success && res.FileMetadata != nil {
				printFileComments(*res.FileMetadata)
			} else {
				c.maybeOfferDeleteOutOfSyncFile(path, res)
			}
		case 10: // Añadir comentario
			path := ui.ReadInput("Introduce la ruta/nombre del fichero o carpeta")
			if !c.ensureLogicalPermission(path, true, 'r', "comentar el fichero o carpeta") {
				break
			}
			comment := ui.ReadMultiline("Introduce el comentario")
			res := c.sendRequest(api.Request{
				Action:      api.ActionAddFileComment,
				Username:    c.currentUser,
				Token:       c.authToken,
				Path:        path,
				CommentText: comment,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success && res.FileMetadata != nil {
				printFileMetadata(*res.FileMetadata)
			} else {
				c.maybeOfferDeleteOutOfSyncFile(path, res)
			}
		case 11: // Borrar comentario
			path := ui.ReadInput("Introduce la ruta/nombre del fichero o carpeta")
			if !c.ensureLogicalPermission(path, true, 'r', "borrar comentario") {
				break
			}
			listRes := c.sendRequest(api.Request{
				Action:   api.ActionListFileComments,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
			})
			fmt.Println("Éxito:", listRes.Success)
			fmt.Println("Mensaje:", listRes.Message)
			if !listRes.Success || listRes.FileMetadata == nil {
				c.maybeOfferDeleteOutOfSyncFile(path, listRes)
				break
			}
			if c.currentUser == listRes.FileMetadata.Owner {
				if !printFileComments(*listRes.FileMetadata) {
					break
				}
			} else {
				if !printOwnFileComments(*listRes.FileMetadata, c.currentUser) {
					break
				}
			}
			commentID := ui.ReadInput("Introduce el ID del comentario")
			res := c.sendRequest(api.Request{
				Action:    api.ActionDeleteFileComment,
				Username:  c.currentUser,
				Token:     c.authToken,
				Path:      path,
				CommentID: commentID,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success && res.FileMetadata != nil {
				printFileComments(*res.FileMetadata)
			} else {
				c.maybeOfferDeleteOutOfSyncFile(path, res)
			}
		case 12: // Modificar permisos lógicos
			path := ui.ReadInput("Introduce la ruta/nombre del fichero o carpeta")
			if isClientRootPath(path) {
				fmt.Println("Éxito: false")
				fmt.Println("Mensaje: no se puede modificar la carpeta raíz del usuario")
				break
			}
			permissions := ui.ReadInput("Introduce permisos en formato rwx------")
			res := c.sendRequest(api.Request{
				Action:   api.ActionUpdateFileMetadata,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
				Data:     permissions,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success && res.FileMetadata != nil {
				printFileMetadata(*res.FileMetadata)
			} else {
				c.maybeOfferDeleteOutOfSyncFile(path, res)
			}
		case 13: // Modificar rol/grupo
			path := ui.ReadInput("Introduce la ruta/nombre del fichero o carpeta")
			if isClientRootPath(path) {
				fmt.Println("Éxito: false")
				fmt.Println("Mensaje: no se puede modificar la carpeta raíz del usuario")
				break
			}
			role := ui.ReadInput("Introduce el rol/grupo asociado")
			res := c.sendRequest(api.Request{
				Action:   api.ActionUpdateFileMetadata,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
				Role:     role,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success && res.FileMetadata != nil {
				printFileMetadata(*res.FileMetadata)
			} else {
				c.maybeOfferDeleteOutOfSyncFile(path, res)
			}
		case 14: // Modificar tags
			path := ui.ReadInput("Introduce la ruta/nombre del fichero o carpeta")
			if isClientRootPath(path) {
				fmt.Println("Éxito: false")
				fmt.Println("Mensaje: no se puede modificar la carpeta raíz del usuario")
				break
			}
			tags := parseTagList(ui.ReadInput("Introduce los tags separados por comas"))
			req := api.Request{
				Action:   api.ActionUpdateFileMetadata,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
			}
			if len(tags) == 0 {
				req.ClearTags = true
			} else {
				req.Tags = tags
			}
			res := c.sendRequest(req)
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success && res.FileMetadata != nil {
				printFileMetadata(*res.FileMetadata)
			} else {
				c.maybeOfferDeleteOutOfSyncFile(path, res)
			}
		case 15: // Filtrar por tag
			path := ui.ReadInput("Introduce la carpeta raíz a filtrar (deja vacío para la raíz)")
			tag := ui.ReadInput("Introduce el tag a buscar")
			res := c.sendRequest(api.Request{
				Action:   api.ActionFilterFilesByTag,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
				Tag:      tag,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success && len(res.FileEntries) > 0 {
				printTaggedEntriesTree(path, res.FileEntries)
			}
		case 16: // Ver mis carpetas compartidas
			res := c.sendRequest(api.Request{
				Action:   api.ActionListSharedFolders,
				Username: c.currentUser,
				Token:    c.authToken,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success {
				fmt.Println("Carpetas compartidas:", res.SharedFolders)
			}
		case 17: // Gestionar carpeta compartida
			c.sharedFolderMenu("compartida_" + c.currentUser)
		case 18: // Volver al menú principal
			return
		}
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

func (c *client) sharedFolderMenu(path string) {
	for {
		ui.ClearScreen()
		choice := ui.PrintMenu("Gestión de carpeta compartida", []string{
			"Añadir usuario",
			"Quitar usuario",
			"Ver miembros",
			"Volver",
		})
		switch choice {
		case 1:
			target := ui.ReadInput("Nombre de usuario a añadir")
			res := c.sendRequest(api.Request{
				Action:     api.ActionSharedFolderAddMember,
				Username:   c.currentUser,
				Token:      c.authToken,
				Path:       path,
				TargetUser: target,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success {
				fmt.Println("Miembros actuales:", res.Roles)
			}
		case 2:
			target := ui.ReadInput("Nombre de usuario a quitar")
			res := c.sendRequest(api.Request{
				Action:     api.ActionSharedFolderRemoveMember,
				Username:   c.currentUser,
				Token:      c.authToken,
				Path:       path,
				TargetUser: target,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success {
				fmt.Println("Miembros actuales:", res.Roles)
			}
		case 3:
			res := c.sendRequest(api.Request{
				Action:   api.ActionSharedFolderListMembers,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			if res.Success {
				fmt.Println("Miembros:", res.Roles)
			}
		case 4:
			return
		}
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

func (c *client) ensureLogicalPermission(path string, includeTarget bool, permission byte, operation string) bool {
	tree, ok := c.loadClientPermissionTree(path, includeTarget)
	if !ok {
		return false
	}
	printPermissionTree(tree)
	if !hasClientPermissionThroughTree(tree, c.currentUser, permission) {
		fmt.Println("Éxito: false")
		fmt.Println("Mensaje: permiso denegado para " + operation)
		return false
	}
	return true
}

func (c *client) ensureParentLogicalPermission(path string, permission byte, operation string) bool {
	parent := parentClientPath(path)
	tree, ok := c.loadClientPermissionTree(parent, true)
	if !ok {
		return false
	}
	printPermissionTree(tree)
	if !hasClientPermissionThroughTree(tree, c.currentUser, permission) {
		fmt.Println("Éxito: false")
		fmt.Println("Mensaje: permiso denegado para " + operation)
		return false
	}
	return true
}

func (c *client) loadClientPermissionTree(path string, includeTarget bool) ([]api.FileMetadata, bool) {
	tree := []api.FileMetadata{{
		Path:        "",
		Name:        c.currentUser,
		IsDir:       true,
		Owner:       c.currentUser,
		Permissions: "rwx------",
	}}
	prefixes := clientPathPrefixes(path)
	if !includeTarget && len(prefixes) > 0 {
		prefixes = prefixes[:len(prefixes)-1]
	}
	for _, prefix := range prefixes {
		res := c.sendRequest(api.Request{
			Action:   api.ActionGetFileMetadata,
			Username: c.currentUser,
			Token:    c.authToken,
			Path:     prefix,
		})
		if !res.Success {
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
			c.maybeOfferDeleteOutOfSyncFile(prefix, res)
			return nil, false
		}
		if res.FileMetadata == nil {
			fmt.Println("Éxito: false")
			fmt.Println("Mensaje: respuesta sin metadatos")
			return nil, false
		}
		tree = append(tree, *res.FileMetadata)
	}
	return tree, true
}

func printPermissionTree(tree []api.FileMetadata) {
	fmt.Println("--- Permisos efectivos ---")
	for i, meta := range tree {
		indent := strings.Repeat("  ", i)
		path := meta.Path
		if path == "" {
			path = meta.Name + "/"
		} else if meta.IsDir {
			path += "/"
		}
		fmt.Printf("%s%s (%s)\n", indent, path, meta.Permissions)
	}
	fmt.Println("--------------------------")
}

func printTaggedEntriesTree(root string, entries []api.FileEntry) {
	fmt.Println("--- Resultados del filtro por tag ---")
	root = normalizeClientPath(root)
	for _, entry := range entries {
		meta := entry.Metadata
		if meta == nil {
			continue
		}
		relativePath := strings.TrimPrefix(meta.Path, root)
		relativePath = strings.TrimPrefix(relativePath, "/")
		depth := 0
		if relativePath != "" {
			depth = strings.Count(relativePath, "/")
		}
		indent := strings.Repeat("  ", depth)
		path := meta.Path
		if path == "" {
			path = meta.Name + "/"
		} else if meta.IsDir {
			path += "/"
		}
		fmt.Printf("%s%s (%s)\n", indent, path, meta.Permissions)
	}
	fmt.Println("------------------------------------")
}

func hasClientPermissionThroughTree(tree []api.FileMetadata, username string, permission byte) bool {
	for _, meta := range tree {
		if !hasClientLogicalPermission(meta, username, permission) {
			return false
		}
	}
	return true
}

func hasClientLogicalPermission(meta api.FileMetadata, username string, permission byte) bool {
	if len(meta.Permissions) < 6 {
		return false
	}
	offset := 3 // grupo: permisos efectivos para miembros no propietarios
	if username == meta.Owner {
		offset = 0
	}
	switch permission {
	case 'r':
		return meta.Permissions[offset] == 'r'
	case 'w':
		return meta.Permissions[offset+1] == 'w'
	case 'x':
		return meta.Permissions[offset+2] == 'x'
	default:
		return false
	}
}

func clientPathPrefixes(path string) []string {
	normalized := normalizeClientPath(path)
	if normalized == "" {
		return nil
	}
	parts := strings.Split(normalized, "/")
	prefixes := make([]string, 0, len(parts))
	for i := range parts {
		prefixes = append(prefixes, strings.Join(parts[:i+1], "/"))
	}
	return prefixes
}

func parentClientPath(path string) string {
	normalized := normalizeClientPath(path)
	if normalized == "" || !strings.Contains(normalized, "/") {
		return ""
	}
	return normalized[:strings.LastIndex(normalized, "/")]
}

func normalizeClientPath(path string) string {
	normalized := strings.Trim(strings.ReplaceAll(strings.TrimSpace(path), "\\", "/"), "/")
	if normalized == "." {
		return ""
	}
	return normalized
}

func isClientRootPath(path string) bool {
	return normalizeClientPath(path) == ""
}

func printFileMetadata(meta api.FileMetadata) {
	itemType := "fichero"
	if meta.IsDir {
		itemType = "directorio"
	}
	fmt.Println("--- Metadatos ---")
	fmt.Println("Ruta:", meta.Path)
	fmt.Println("Nombre:", meta.Name)
	fmt.Println("Tipo:", itemType)
	fmt.Println("Tamaño:", meta.Size)
	fmt.Println("Propietario:", meta.Owner)
	if meta.Role != "" {
		fmt.Println("Rol/grupo:", meta.Role)
	}
	if len(meta.Tags) > 0 {
		fmt.Println("Tags:", strings.Join(meta.Tags, ", "))
	} else {
		fmt.Println("Tags: ninguno")
	}
	if len(meta.Comments) > 0 {
		fmt.Println("Comentarios:")
		for _, comment := range meta.Comments {
			text := strings.ReplaceAll(comment.Text, "\n", " ")
			fmt.Printf("- %s | %s | %s\n", text, comment.Author, comment.CreatedAt.Format(time.RFC3339))
		}
	} else {
		fmt.Println("Comentarios: ninguno")
	}
	fmt.Println("Permisos:", meta.Permissions)
	fmt.Println("Creado:", meta.CreatedAt.Format(time.RFC3339))
	fmt.Println("Modificado:", meta.ModifiedAt.Format(time.RFC3339))
	if !meta.AccessedAt.IsZero() {
		fmt.Println("Accedido:", meta.AccessedAt.Format(time.RFC3339))
	}
	fmt.Println("Plataforma:", meta.Platform)
	fmt.Println("-----------------")
}

func printFileComments(meta api.FileMetadata) bool {
	fmt.Println("--- Comentarios ---")
	fmt.Println("Ruta:", meta.Path)
	if len(meta.Comments) == 0 {
		fmt.Println("Sin comentarios")
		fmt.Println("-------------------")
		return false
	}
	for _, comment := range meta.Comments {
		fmt.Printf("- %s | %s | %s\n", comment.ID, comment.Author, comment.CreatedAt.Format(time.RFC3339))
		fmt.Println("  " + strings.ReplaceAll(comment.Text, "\n", "\n  "))
	}
	fmt.Println("-------------------")
	return true
}

func printOwnFileComments(meta api.FileMetadata, username string) bool {
	fmt.Println("--- Tus comentarios ---")
	fmt.Println("Ruta:", meta.Path)
	found := false
	for _, comment := range meta.Comments {
		if comment.Author != username {
			continue
		}
		found = true
		fmt.Printf("- %s | %s | %s\n", comment.ID, comment.Author, comment.CreatedAt.Format(time.RFC3339))
		fmt.Println("  " + strings.ReplaceAll(comment.Text, "\n", "\n  "))
	}
	if !found {
		fmt.Println("No tienes comentarios en esta ruta")
	}
	fmt.Println("-----------------------")
	return found
}

func parseTagList(input string) []string {
	parts := strings.Split(input, ",")
	tags := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		tag := strings.TrimSpace(part)
		if tag == "" {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		tags = append(tags, tag)
	}
	return tags
}

func (c *client) manageTOTP() {
	ui.ClearScreen()

	// Si no tiene el totp activo
	if !c.totpEnabled {
		c.setupTOTP()
		return
	}

	// Si tiene totp
	choice := ui.PrintMenu("Gestión TOTP", []string{
		"Reactivar TOTP",
		"Desactivar TOTP",
	})

	switch choice {
	case 1:
		c.setupTOTP()
	case 2:
		c.disableTOTP()
	}
}

func (c *client) setupTOTP() {
	ui.ClearScreen()
	fmt.Println("** Activar TOTP **")

	// Si ya tiene TOTP activo, pregunta qué hacer
	if c.totpEnabled {
		choice := ui.PrintMenu("Ya tienes TOTP activo", []string{
			"Usar secreto actual (reescanear)",
			"Generar nuevo secreto",
		})

		if choice == 1 {
			// Solo muestra el QR del secreto actual, sin confirmación
			res := c.sendRequest(api.Request{
				Action:   api.ActionTOTPSetup,
				Username: c.currentUser,
				Token:    c.authToken,
			})
			if !res.Success {
				fmt.Println("Error:", res.Message)
				return
			}
			qr, err := qrcode.New(res.OTPAuthURI, qrcode.Medium)
			if err != nil {
				fmt.Println("URI TOTP:", res.OTPAuthURI)
			} else {
				fmt.Println(qr.ToSmallString(false))
			}
			return
		}
	}

	// Pido el secreto al servidor
	res := c.sendRequest(api.Request{
		Action:         api.ActionTOTPSetup,
		Username:       c.currentUser,
		Token:          c.authToken,
		ForceNewSecret: c.totpEnabled,
	})
	if !res.Success {
		fmt.Println("Error:", res.Message)
		return
	}
	qr, err := qrcode.New(res.OTPAuthURI, qrcode.Medium)
	fmt.Println("URI TOTP:", res.OTPAuthURI)
	if err != nil {
		fmt.Println("URI TOTP:", res.OTPAuthURI)
	} else {
		fmt.Println(qr.ToSmallString(false))
	}

	for {
		code := ui.ReadInput("Introduce el codigo de tu app (o 'cancelar')")
		if code == "cancelar" {
			return
		}
		confirmRes := c.sendRequest(api.Request{
			Action:   api.ActionTOTPConfirm,
			Username: c.currentUser,
			Token:    c.authToken,
			TOTPCode: code,
		})

		fmt.Println("Mensaje:", confirmRes.Message)
		if confirmRes.Success {
			c.totpEnabled = true
			fmt.Println("TOTP activado correctamente")
			return
		}
	}
}

func (c *client) disableTOTP() {
	ui.ClearScreen()
	fmt.Println("** Desactivar TOTP **")

	code := ui.ReadInput("Introduce tu código TOTP actual para confirmar")
	res := c.sendRequest(api.Request{
		Action:   api.ActionTOTPDisable,
		Username: c.currentUser,
		Token:    c.authToken,
		TOTPCode: code,
	})

	fmt.Println("Mensaje:", res.Message)
	if res.Success {
		c.totpEnabled = false
		fmt.Println("TOTP desactivado correctamente")
	}
}

func (c *client) setupKey() {

	// Pido contraseña y la verifico porque luego se usará para cifrar
	password, err := ui.ReadPassword("Introduce tu contraseña de acceso")
	if err != nil {
		fmt.Println("Error leyendo la contraseña")
		return
	}
	confirm, err := ui.ReadPassword("Confirma tu contraseña")
	if err != nil {
		fmt.Println("Error leyendo la contraseña")
		return
	}
	if password != confirm {
		fmt.Println("Las contraseñas no coinciden")
		return
	}

	// Verifico contra el servidor
	res := c.sendRequest(api.Request{
		Action:   api.ActionVerifyPassword,
		Username: c.currentUser,
		Token:    c.authToken,
		Password: password,
	})
	if res.SessionExpired {
		c.currentUser = ""
		c.authToken = ""
		c.totpEnabled = false
		c.keyAuthEnabled = false
		c.isAdmin = false
		fmt.Println("Sesión expirada")
		return
	}
	if !res.Success {
		fmt.Println("Contraseña incorrecta")
		return
	}

	// Genero par de claves
	pub, priv, err := utils.GenerateKeyPair()
	if err != nil {
		fmt.Println("Error al generar el par de claves: ", err)
		return
	}

	// Envio la clave publica al servidor
	res = c.sendRequest(api.Request{
		Action:    api.ActionKeySetup,
		Username:  c.currentUser,
		Token:     c.authToken,
		PublicKey: pub,
	})
	fmt.Println("Éxito: ", res.Success)
	fmt.Println("Mensaje: ", res.Message)
	if res.SessionExpired {
		c.currentUser = ""
		c.authToken = ""
		c.totpEnabled = false
		c.keyAuthEnabled = false
		fmt.Println("Sesión expirada")
		return
	}
	if !res.Success {
		return
	}

	// Cifro y guardo clave privada en disco
	if err := utils.EncryptPrivateKey(priv, password, c.currentUser); err != nil {
		fmt.Println("Error al guardar la clave privada: ", err)
		return
	}

	c.keyAuthEnabled = true
}

func (c *client) disableKey() {
	res := c.sendRequest(api.Request{
		Action:   api.ActionKeyDisable,
		Username: c.currentUser,
		Token:    c.authToken,
	})
	fmt.Println("Éxito: ", res.Success)
	fmt.Println("Mensaje: ", res.Message)
	if res.Success {
		if err := os.Remove(utils.KeyPath(c.currentUser)); err != nil && !os.IsNotExist(err) {
			fmt.Println("Error al eliminar la clave privada local:", err)
			return
		}
		c.keyAuthEnabled = false
	}

}

func (c *client) manageKey() {
	if c.keyAuthEnabled {
		c.disableKey()
	} else {
		c.setupKey()
	}
}

func (c *client) adminMenu() {
	for {
		ui.ClearScreen()
		choice := ui.PrintMenu("Administración", []string{
			"Acceder a logs",
			"Acceder a backups",
			"Listar roles",
			"Crear rol",
			"Eliminar rol",
			"Ver roles de usuario",
			"Asignar rol a usuario",
			"Quitar rol a usuario",
			"Volver",
		})
		switch choice {
		case 1:
			c.accessRemoteLogs()
		case 2:
			if c.accessRemoteBackups() {
				return
			}
		case 3:
			res := c.sendRequest(api.Request{Action: api.ActionListRoles, Username: c.currentUser, Token: c.authToken})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Roles:", res.Roles)
		case 4:
			role := ui.ReadInput("Nombre del nuevo rol")
			res := c.sendRequest(api.Request{Action: api.ActionCreateRole, Username: c.currentUser, Token: c.authToken, Role: role})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
		case 5:
			role := ui.ReadInput("Nombre del rol a eliminar")
			res := c.sendRequest(api.Request{Action: api.ActionDeleteRole, Username: c.currentUser, Token: c.authToken, Role: role})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
		case 6:
			target := ui.ReadInput("Nombre de usuario")
			res := c.sendRequest(api.Request{Action: api.ActionGetUserRoles, Username: c.currentUser, Token: c.authToken, TargetUser: target})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Roles de", target+":", res.Roles)
		case 7:
			target := ui.ReadInput("Nombre de usuario")
			role := ui.ReadInput("Rol a asignar")
			res := c.sendRequest(api.Request{Action: api.ActionAssignRole, Username: c.currentUser, Token: c.authToken, TargetUser: target, Role: role})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
		case 8:
			target := ui.ReadInput("Nombre de usuario")
			role := ui.ReadInput("Rol a quitar")
			res := c.sendRequest(api.Request{Action: api.ActionRemoveRole, Username: c.currentUser, Token: c.authToken, TargetUser: target, Role: role})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
		case 9:
			return
		}
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}
