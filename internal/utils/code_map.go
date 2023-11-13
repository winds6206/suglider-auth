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
		1014: "Generate the JWT string failed.",
		1015: "JWT signature is invalid.",
		1016: "Parse JWT claim data failed.",
		1017: "Token is invalid.",
		1018: "Generate new JWT failed.",
		1019: "Cookie key is not found.",
		1020: "Get cookie key failed.",
	}
}
