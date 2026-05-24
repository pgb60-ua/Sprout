// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

import "time"

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

	// private and public key
	ActionKeySetup       = "keySetup"
	ActionKeyDisable     = "keyDisable"
	ActionLoginKey       = "loginKey"
	ActionVerifyPassword = "verifyPassword"

	// File and folder management actions
	ActionCreateFile = "createFile"
	ActionDeleteFile = "deleteFile"
	ActionModifyFile = "modifyFile"
	ActionReadFile   = "readFile"
	ActionCreateDir  = "createDir"
	ActionDeleteDir  = "deleteDir"
	ActionListFiles  = "listFiles"

	// File metadata management actions
	ActionGetFileMetadata    = "getFileMetadata"
	ActionUpdateFileMetadata = "updateFileMetadata"

	// Role management
	ActionAssignRole   = "assignRole"
	ActionRemoveRole   = "removeRole"
	ActionListRoles    = "listRoles"
	ActionGetUserRoles = "getUserRoles"
	ActionCreateRole   = "createRole"
	ActionDeleteRole   = "deleteRole"
)

type Request struct {
	Action           string `json:"action"`
	Username         string `json:"username"`
	Password         string `json:"password,omitempty"`
	Token            string `json:"token,omitempty"`
	Data             string `json:"data,omitempty"`
	Path             string `json:"path,omitempty"`
	Recipient        string `json:"recipient,omitempty"`
	MessageID        string `json:"message_id,omitempty"`
	Ciphertext       string `json:"ciphertext,omitempty"`
	MessagePublicKey string `json:"message_public_key,omitempty"`
	TOTPCode         string `json:"totp_code,omitempty"`
	TempToken        string `json:"temp_token,omitempty"`
	ForceNewSecret   bool   `json:"force_new_secret,omitempty"`
	PublicKey        []byte `json:"public_key,omitempty"`
	Signature        []byte `json:"signature,omitempty"`
	Role             string `json:"role,omitempty"`
	TargetUser       string `json:"target_user,omitempty"`
}

type MessageSummary struct {
	ID        string `json:"id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	CreatedAt string `json:"created_at"`
}

type FileMetadata struct {
	Path        string    `json:"path"`
	Name        string    `json:"name"`
	IsDir       bool      `json:"is_dir"`
	Size        int64     `json:"size"`
	Owner       string    `json:"owner"`
	Role        string    `json:"role,omitempty"`
	Permissions string    `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	ModifiedAt  time.Time `json:"modified_at"`
	AccessedAt  time.Time `json:"accessed_at,omitempty"`
	Platform    string    `json:"platform"`
}

type FileEntry struct {
	Name     string        `json:"name"`
	Path     string        `json:"path"`
	Metadata *FileMetadata `json:"metadata,omitempty"`
}

type Response struct {
	Success        bool             `json:"success"`
	Message        string           `json:"message"`
	Token          string           `json:"token,omitempty"`
	Data           string           `json:"data,omitempty"`
	SessionExpired bool             `json:"session_expired,omitempty"`
	Files          []string         `json:"files,omitempty"`
	FileMetadata   *FileMetadata    `json:"file_metadata,omitempty"`
	FileEntries    []FileEntry      `json:"file_entries,omitempty"`
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
	Challenge      []byte           `json:"challenge,omitempty"`
	KeyAuthEnabled bool             `json:"key_auth_enabled,omitempty"`
	RequiresKey    bool             `json:"requires_key,omitempty"`
	Roles          []string         `json:"roles,omitempty"`
	IsAdmin        bool             `json:"is_admin,omitempty"`
}
