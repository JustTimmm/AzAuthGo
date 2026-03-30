package azuriom

type AuthResponse struct {
	ID            int    `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Money         int    `json:"money"`
	Role          Role   `json:"role"`
	Banned        bool   `json:"banned"`
	UUID          string `json:"uuid"`
	AccessToken   string `json:"access_token"`
	CreatedAt     string `json:"created_at"`
}

type Role struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

type ErrorResponse struct {
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}
