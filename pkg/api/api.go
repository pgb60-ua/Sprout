// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

const (
	ActionRegister   = "register"
	ActionLogin      = "login"
	ActionFetchData  = "fetchData"
	ActionUpdateData = "updateData"
	ActionLogout     = "logout"

	// Messaging
	ActionGetPublicKey     = "getPublicKey"
	ActionSendMessage      = "sendMessage"
	ActionListMessages     = "listMessages"
	ActionReadMessage      = "readMessage"
	ActionListSentMessages = "listSentMessages"

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
	Recipient      string `json:"recipient,omitempty"`
	MessageID      string `json:"message_id,omitempty"`
	PublicKey      string `json:"public_key,omitempty"`
	Ciphertext     string `json:"ciphertext,omitempty"`
	TOTPCode       string `json:"totp_code,omitempty"`
	TempToken      string `json:"temp_token,omitempty"`
	ForceNewSecret bool   `json:"force_new_secret,omitempty"`
}

type MessageSummary struct {
	ID        string `json:"id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	CreatedAt string `json:"created_at"`
}

type Response struct {
	Success        bool             `json:"success"`
	Message        string           `json:"message"`
	Token          string           `json:"token,omitempty"`
	Data           string           `json:"data,omitempty"`
	SessionExpired bool             `json:"session_expired,omitempty"`
	Files          []string         `json:"files,omitempty"`
	Messages       []MessageSummary `json:"messages,omitempty"`
	MessageID      string           `json:"message_id,omitempty"`
	PublicKey      string           `json:"public_key,omitempty"`
	Ciphertext     string           `json:"ciphertext,omitempty"`
	Sender         string           `json:"sender,omitempty"`
	Recipient      string           `json:"recipient,omitempty"`
	CreatedAt      string           `json:"created_at,omitempty"`
	RequiresTOTP   bool             `json:"requires_totp,omitempty"`
	TempToken      string           `json:"temp_token,omitempty"`
	OTPAuthURI     string           `json:"otpauth_uri,omitempty"`
	TOTPEnabled    bool             `json:"totp_enabled,omitempty"`
}
