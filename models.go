package main

import (
	"time"
)

type Model struct {
	ID        string `gorm:"primary_key"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time
}

type User struct {
	ID       string `gorm:"primary_key"`
	Username string
	Name     string
	Password string
	Email    string
	Articles []Article
}

type Article struct {
	ID        string `gorm:"primary_key"`
	Title     string
	Desc      string
	Content   string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time
}

type Error struct {
	Code    string
	Message string
}

type Token struct {
	Token string
}
