package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// Глобальная переменная для подключения к БД
var db *sql.DB

// InitDB инициализирует подключение к базе данных
func InitDB() error {
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "7432"),
		getEnv("DB_USER", "postgres"),
		getEnv("DB_PASSWORD", "postgres"),
		getEnv("DB_NAME", "secure_service"),
	)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	fmt.Println("Database connected successfully!")
	return nil
}

// CloseDB закрывает соединение с базой данных
func CloseDB() {
	if db != nil {
		db.Close()
	}
}

// CreateUser создает нового пользователя в базе данных
func CreateUser(email, username, passwordHash string) (*User, error) {
	query := `INSERT INTO public.users (email, username, password_hash) 
			VALUES ($1, $2, $3) 
			RETURNING id, created_at`
	row := db.QueryRow(query, email, username, passwordHash)

	user := &User{}
	err := row.Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	user.Email = email
	user.Username = username
	user.PasswordHash = passwordHash

	return user, nil
}

// GetUserByEmail находит пользователя по email
func GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, email, username, password_hash, created_at FROM public.users WHERE email = $1`
	row := db.QueryRow(query, email)

	user := &User{}
	err := row.Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.CreatedAt)
	if err != nil {
		// Если пользователь не найден — возвращаем nil и ошибку
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user with email %s not found", email)
		}
		// Любая другая ошибка
		return nil, fmt.Errorf("failed to get user: %v", err)
	}

	return user, nil
}

// GetUserByID находит пользователя по ID
func GetUserByID(userID int) (*User, error) {
	query := `SELECT id, email, username, created_at FROM public.users WHERE id = $1`
	row := db.QueryRow(query, userID)

	user := &User{}
	err := row.Scan(&user.ID, &user.Email, &user.Username, &user.CreatedAt)
	if err != nil {
		// Если пользователь не найден — возвращаем nil и ошибку
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user with id %d not found", userID)
		}
		// Любая другая ошибка
		return nil, fmt.Errorf("failed to get user: %v", err)
	}

	return user, nil
}

// UserExistsByEmail проверяет, существует ли пользователь с данным email
func UserExistsByEmail(email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM public.users WHERE email = $1)`
	row := db.QueryRow(query, email)

	var isExist bool
	err := row.Scan(&isExist)
	if err != nil {
		return false, fmt.Errorf("failed to check user by email: %v", err)
	}

	return isExist, nil
}

// GetDB возвращает подключение к базе данных (для тестирования)
func GetDB() *sql.DB {
	return db
}
