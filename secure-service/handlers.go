package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// RegisterHandler обрабатывает регистрацию нового пользователя
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Валидируем username, email, password
	if err := validateRegisterRequest(&req); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Проверяем, что пользователь с таким email не существует
	exists, err := UserExistsByEmail(req.Email)
	if err != nil {
		sendErrorResponse(w, "Database error", http.StatusInternalServerError)
		return
	}
	if exists {
		sendErrorResponse(w, "User with this email already exists", http.StatusConflict)
		return
	}

	// Хешируем пароль
	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		sendErrorResponse(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Добавляем пользователя в БД
	user, err := CreateUser(req.Email, req.Username, passwordHash)
	if err != nil {
		sendErrorResponse(w, fmt.Sprintf("Failed to create user: %v", err), http.StatusInternalServerError)
		return
	}

	// Получаем токен
	token, err := GenerateToken(*user)
	if err != nil {
		sendErrorResponse(w, "Failed to get token", http.StatusInternalServerError)
		return
	}

	// Возвращаем ответ
	response := map[string]interface{}{
		"message": "User registered successfully",
		"token":   token,
		"user": map[string]interface{}{
			"id":        user.ID,
			"email":     user.Email,
			"username":  user.Username,
			"createdAt": user.CreatedAt,
		},
	}

	sendJSONResponse(w, response, http.StatusCreated)
}

// LoginHandler обрабатывает вход пользователя
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Парсим JSON
	var req LoginRequest
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Валидируем входные данные
	if err := validateLoginRequest(&req); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Дополнительная проверка формата email
	if err := ValidateEmail(req.Email); err != nil {
		sendErrorResponse(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Ищем пользователя
	user, err := GetUserByEmail(req.Email)
	if err != nil {
		sendErrorResponse(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Проверяем пароль
	if !CheckPassword(req.Password, user.PasswordHash) {
		sendErrorResponse(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Генерируем токен
	token, err := GenerateToken(*user)
	if err != nil {
		sendErrorResponse(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Возвращаем ответ
	response := map[string]interface{}{
		"message": "Login successful",
		"token":   token,
		"user": map[string]interface{}{
			"id":        user.ID,
			"email":     user.Email,
			"username":  user.Username,
			"createdAt": user.CreatedAt,
		},
	}

	sendJSONResponse(w, response, http.StatusOK)
}

// ProfileHandler возвращает профиль текущего пользователя
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Получаем ID пользователя из контекста
	userID, ok := GetUserIDFromContext(r)
	if !ok {
		sendErrorResponse(w, "User ID not found in context", http.StatusInternalServerError)
		return
	}

	// Получаем данные пользователя из БД
	user, err := GetUserByID(userID)
	if err != nil {
		sendErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}

	// Возвращаем данные пользователя
	response := map[string]interface{}{
		"id":        user.ID,
		"email":     user.Email,
		"username":  user.Username,
		"createdAt": user.CreatedAt,
	}

	sendJSONResponse(w, response, http.StatusOK)
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем подключение к БД
	if db != nil {
		if err := db.Ping(); err != nil {
			sendErrorResponse(w, "Database connection failed", http.StatusServiceUnavailable)
			return
		}
	}

	// Возвращаем статус OK
	response := map[string]string{
		"status":  "ok",
		"message": "Service is running",
	}
	sendJSONResponse(w, response, http.StatusOK)
}

// sendJSONResponse отправляет JSON ответ (вспомогательная функция)
func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// sendErrorResponse отправляет JSON ответ с ошибкой (вспомогательная функция)
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	json.NewEncoder(w).Encode(response)
}

// parseJSONRequest парсит JSON из тела запроса (вспомогательная функция)
func parseJSONRequest(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Строгая проверка полей

	return decoder.Decode(v)
}

// validateRegisterRequest валидирует данные регистрации
func validateRegisterRequest(req *RegisterRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	// Проверка email
	if err := ValidateEmail(req.Email); err != nil {
		return err
	}

	// Проверка пароля
	if err := ValidatePassword(req.Password); err != nil {
		return err
	}

	// Проверка длины username (минимум 3 символа)
	if len(req.Username) < 3 {
		return fmt.Errorf("username must be at least 3 characters long")
	}

	// Проверка, что username содержит только допустимые символы
	for _, ch := range req.Username {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_') {
			return fmt.Errorf("username can only contain letters, numbers and underscore")
		}
	}

	return nil
}

// validateLoginRequest валидирует данные входа
func validateLoginRequest(req *LoginRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}
