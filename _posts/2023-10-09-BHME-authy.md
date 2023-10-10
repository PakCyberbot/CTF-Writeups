---
title: Authy (Web)
author: pcb
date: 2023-10-09 20:00:00 +0500
categories: [CTF Events, Blackhat MEA 2023]
tags: [web]
math: true
mermaid: true
image:
  path: https://i.imgur.com/fDDlPRz.png
  alt: 

---
This challenge came with the source code of web application that's written in GO. I am putting the code of the API's below

```go
package controllers

import (
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/blackhat/db"
	"github.com/blackhat/helper"
	models "github.com/blackhat/model"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"golang.org/x/crypto/bcrypt"
)

func Registration(c echo.Context) error {
	var user models.Users
	body, _ := io.ReadAll(c.Request().Body)
	err := json.Unmarshal(body, &user)
	if err != nil {
		return err
	}
	if len(user.Password) < 6 {
		log.Error("Password too short")
		resp := c.JSON(http.StatusConflict, helper.ErrorLog(http.StatusConflict, "Password too short", "EXT_REF"))
		return resp
	}
	DB := db.DB()
	var count int
	sqlStatement := `Select count(username) from users where username=?`
	err = DB.QueryRow(sqlStatement, user.Username).Scan(&count)
	if err != nil {
		log.Error(err.Error())
	}
	if count > 0 {
		log.Error("username already used")
		resp := c.JSON(http.StatusConflict, helper.ErrorLog(http.StatusConflict, "username already used", "EXT_REF"))
		return resp
	}
	//hashing password (even it's a CTF, stick to the good habits)
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)
	if err != nil {
		resp := c.JSON(http.StatusInternalServerError, helper.ErrorLog(http.StatusInternalServerError, " Error While Hashing Password", "EXT_REF"))
		return resp
	}
	user.Password = string(hash)
	user.DateCreated = helper.DateTime()
	user.Token = helper.JwtGenerator(user.Username, user.Firstname, user.Lastname, os.Getenv("SECRET"))
	stmt, err := DB.Prepare("Insert into users (username,firstname,lastname,password,token,datecreated) VALUES (?,?,?,?,?,?)")
	if err != nil {
		resp := c.JSON(http.StatusInternalServerError, helper.ErrorLog(http.StatusInternalServerError, "Error when prepare statement : "+err.Error(), "EXT_REF"))
		return resp
	}
	_, err = stmt.Exec(user.Username, user.Firstname, user.Lastname, user.Password, user.Token, user.DateCreated)
	if err != nil {
		log.Error(err)
		resp := c.JSON(http.StatusInternalServerError, helper.ErrorLog(http.StatusInternalServerError, "Error when execute statement : "+err.Error(), "EXT_REF"))
		return resp
	}
	resp := c.JSON(http.StatusOK, user)
	log.Info()
	return resp
}

type Flag struct {
	Flag string `json:"flag"`
}

func LoginController(c echo.Context) error {
	var user models.Users
	payload, _ := io.ReadAll(c.Request().Body)
	err := json.Unmarshal(payload, &user)

	if err != nil {
		log.Error(err)
		return err
	}
	var result models.Users
	DB := db.DB()
	sqlStatement := "select * from users where username=?"

	err = DB.QueryRow(sqlStatement, user.Username).Scan(&result.Username, &result.Firstname, &result.Lastname, &result.Password, &result.Token, &result.DateCreated)
	if err != nil {
		log.Error(err)
		resp := c.JSON(http.StatusInternalServerError, helper.ErrorLog(http.StatusInternalServerError, "Invalid Username", "EXT_REF"))
		return resp
	}

	err = bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))
	if err != nil {
		log.Error("Invalid Password :", err)
		resp := c.JSON(http.StatusInternalServerError, helper.ErrorLog(http.StatusInternalServerError, "Invalid Password", "EXT_REF"))
		return resp
	}
	password := []rune(user.Password)
	result.Token = helper.JwtGenerator(result.Username, result.Firstname, result.Lastname, os.Getenv("SECRET"))
	if len(password) < 6 {
		flag := os.Getenv("FLAG")
		res := &Flag{
			Flag: flag,
		}
		resp := c.JSON(http.StatusOK, res)
		log.Info()
		return resp
	}
	resp := c.JSON(http.StatusOK, result)
	log.Info()
	return resp
}

```
To obtain the flag, my password needs to be less than 6 characters. However, during registration, the system doesn't allow passwords with fewer than 6 characters. An important observation here is that during registration, the password string is directly compared, whereas during login, the code utilizes the rune function.

```go
// registration
if len(user.Password) < 6 {
  log.Error("Password too short")
  resp := c.JSON(http.StatusConflict, helper.ErrorLog(http.StatusConflict, "Password too short", "EXT_REF"))
  return resp
}

// login
password := []rune(user.Password)
result.Token = helper.JwtGenerator(result.Username, result.Firstname, result.Lastname, os.Getenv("SECRET"))
if len(password) < 6 {
  flag := os.Getenv("FLAG")
  res := &Flag{
    Flag: flag,
  }
  resp := c.JSON(http.StatusOK, res)
  log.Info()
  return resp
}
```
You can find information about rune online. In simple terms, rune is used to handle Unicode characters properly. For instance, the character 'A' consists of 1 byte, whereas a single Chinese character consists of 2 bytes. If Go directly compares a password containing a Chinese character, it might consider it as 2 characters. However, using rune(), it treats it as a single character. This implies that if we use a 3 Chinese character password, it will meet both the registration and login flag criteria.
![registration](https://i.imgur.com/UO75C6g.png)
![login](https://i.imgur.com/Y8aQrtj.png)



> Show some support by following me on [Github](https://github.com/PakCyberbot)
{: .prompt-tip }
