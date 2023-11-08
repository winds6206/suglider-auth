package utils

var CodeMap map[int64]string

func init() {
	ResponseStatusCode()
}

func ResponseStatusCode() {
	CodeMap = map[int64]string{
		200: "Successfully.",
		1001: "Wrong with the data format trasnfer from POST.",
		1002: "Failed to execute SQL syntax.",
		1003: "No search this user.",
		1004: "Invalid password.",
		1005: "Failed to create session value JSON data.",
		1006: "User ID not found.",
		1007: "Totp code verify failed.",
		1008: "Generate TOTP key failed.",
		1009: "Failed to save QRcode.",
		1010: "Encode PNG failed.",
		1011: "Check whether the user_id exists or not failed.",
		1012: "Update totp table failed.",
		1013: "Insert totp table failed.",
	}
}
