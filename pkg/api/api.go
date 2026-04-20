// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

const (
	ActionRegister   = "register"
	ActionLogin      = "login"
	ActionFetchData  = "fetchData"
	ActionUpdateData = "updateData"
	ActionLogout     = "logout"

	// TOTP
	ActionTOTPSetup   = "totpSetup"
	ActionTOTPConfirm = "totpConfirm"
	ActionLoginTOTP   = "loginTOTP"
	ActionTOTPDisable = "totpDisable"

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
	Action         string `json:"action"`
	Username       string `json:"username"`
	Password       string `json:"password,omitempty"`
	Token          string `json:"token,omitempty"`
	Data           string `json:"data,omitempty"`
	Path           string `json:"path,omitempty"`
	TOTPCode       string `json:"totp_code,omitempty"`
	TempToken      string `json:"temp_token,omitempty"`
	ForceNewSecret bool   `json:"force_new_secret,omitempty"`
}

type Response struct {
	Success        bool     `json:"success"`
	Message        string   `json:"message"`
	Token          string   `json:"token,omitempty"`
	Data           string   `json:"data,omitempty"`
	SessionExpired bool     `json:"session_expired,omitempty"`
	Files          []string `json:"files,omitempty"`
	RequiresTOTP   bool     `json:"requires_totp,omitempty"`
	TempToken      string   `json:"temp_token,omitempty"`
	OTPAuthURI     string   `json:"otpauth_uri,omitempty"`
	TOTPEnabled    bool     `json:"totp_enabled,omitempty"`
}
