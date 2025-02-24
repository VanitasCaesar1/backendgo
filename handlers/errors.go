package handlers

// Structured Error Responses
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func NewErrorResponse(code string, message string, details ...any) ErrorResponse {
	var detail any
	if len(details) > 0 {
		detail = details
	}
	return ErrorResponse{
		Code:    code,
		Message: message,
		Details: detail,
	}
}
