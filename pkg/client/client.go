// El paquete client contiene la lógica de interacción con el usuario
// así como de comunicación con el servidor.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"sprout/pkg/api"
	"sprout/pkg/ui"

	"github.com/skip2/go-qrcode"
)

// client estructura interna no exportada que controla
// el estado de la sesión (usuario, token) y logger.
type client struct {
	log         *log.Logger
	currentUser string
	authToken   string
	totpEnabled bool // Para saber si tiene el totp enabled y cambiar el texto y opciones
	httpClient  *http.Client
}

// Run es la única función exportada de este paquete.
// Crea un cliente interno y ejecuta el bucle principal.
func Run() {
	// Creamos un logger con prefijo 'cli' para identificar
	// los mensajes en la consola.
	c := &client{
		log: log.New(os.Stdout, "[cli] ", log.LstdFlags),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
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

			// Usuario activo: Ver datos, Actualizar datos, TOTP, ficheros, logs, backups, Logout, Salir
			options = []string{
				"Ver datos",
				"Actualizar datos",
				totpOption,
				"Gestión de ficheros",
				"Acceder a logs",
				"Acceder a backups",
				"Cerrar sesión",
				"Salir",
			}
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
				c.fileManagerMenu()
			case 5:
				c.accessRemoteLogs()
			case 6:
				if c.accessRemoteBackups() {
					return
				}
			case 7:
				c.logoutUser()
			case 8:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
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

	// Enviamos la acción al servidor
	res := c.sendRequest(api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Password: password,
	})

	// Mostramos resultado
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, probamos loguear automáticamente.
	if res.Success {
		c.log.Println("Registro exitoso; intentando login automático...")

		loginRes := c.sendRequest(api.Request{
			Action:   api.ActionLogin,
			Username: username,
			Password: password,
		})
		if loginRes.Success {
			c.currentUser = username
			c.authToken = loginRes.Token
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

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	if !res.Success {
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
			c.currentUser = username
			c.authToken = totopRes.Token
			c.totpEnabled = true
		}
		return
	}

	// Sin TOTP
	c.currentUser = username
	c.authToken = res.Token
	c.totpEnabled = res.TOTPEnabled
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
		fmt.Println("Sesión expirada. Vuelve a iniciar sesión.")
		c.currentUser = ""
		c.authToken = ""
		c.totpEnabled = false
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
		fmt.Println("Sesión expirada. Vuelve a iniciar sesión.")
		c.currentUser = ""
		c.authToken = ""
		c.totpEnabled = false
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
		c.currentUser = ""
		c.authToken = ""
		c.totpEnabled = false
	}

	if !res.Success && res.SessionExpired {
		fmt.Println("Sesión expirada. Vuelve a iniciar sesión.")
		c.currentUser = ""
		c.authToken = ""
		c.totpEnabled = false
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

	httpReq, err := http.NewRequest(http.MethodPost, "http://localhost:8080/api", bytes.NewBuffer(jsonData))
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

func (c *client) accessRemoteLogs() {
	ui.ClearScreen()
	fmt.Println("** Acceso a logs remotos **")

	if err := c.runExternalCommand("go", "run", "./logs"); err != nil {
		fmt.Println("No se pudieron abrir los logs remotos:", err)
		return
	}

	fmt.Println("Visor de logs finalizado.")
}

func (c *client) accessRemoteBackups() bool {
	ui.ClearScreen()
	fmt.Println("** Acceso a backups **")
	fmt.Println("Se cerrará el programa principal para restaurar el backup.")

	if !ui.Confirm("¿Quieres continuar") {
		return false
	}

	if err := c.runExternalCommand("go", "run", "./backups"); err != nil {
		fmt.Println("No se pudo iniciar la restauración de backups:", err)
		return false
	}

	fmt.Println("Restaurador de backups iniciado. Cerrando el programa principal...")
	return true
}

func (c *client) runExternalCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
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
			"Volver al menú principal",
		}

		choice := ui.PrintMenu(title, options)
		switch choice {
		case 1: // Listar directorio
			path := ui.ReadInput("Introduce el directorio a listar (deja vací­o para la raí­z)")
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
		case 5: // Visualizar fichero
			path := ui.ReadInput("Introduce la ruta/nombre del fichero a visualizar")
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
			}
		case 6: // Crear carpeta
			path := ui.ReadInput("Introduce la ruta/nombre de la nueva carpeta")
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
			res := c.sendRequest(api.Request{
				Action:   api.ActionDeleteDir,
				Username: c.currentUser,
				Token:    c.authToken,
				Path:     path,
			})
			fmt.Println("Éxito:", res.Success)
			fmt.Println("Mensaje:", res.Message)
		case 8: // Volver al menú principal
			return
		}
		ui.Pause("Pulsa [Enter] para continuar...")
	}
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
