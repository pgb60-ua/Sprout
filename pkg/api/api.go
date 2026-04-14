// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

const (
	ActionRegister   = "register"
	ActionLogin      = "login"
	ActionFetchData  = "fetchData"
	ActionUpdateData = "updateData"
	ActionLogout     = "logout"

	// File and folder management actions
	ActionCreateFile = "createFile"
	ActionDeleteFile = "deleteFile"
	ActionModifyFile = "modifyFile"
	ActionReadFile   = "readFile"
	ActionCreateDir  = "createDir"
	ActionDeleteDir  = "deleteDir"
	ActionListFiles  = "listFiles"
)

type Request struct {
	Action   string `json:"action"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
	Data     string `json:"data,omitempty"`
	Path     string `json:"path,omitempty"`
}

type Response struct {
	Success bool     `json:"success"`
	Message string   `json:"message"`
	Token   string   `json:"token,omitempty"`
	Data    string   `json:"data,omitempty"`
	Files   []string `json:"files,omitempty"`
}
