/*
   ZAU Single Sign-On
   Copyright (C) 2021  Daniel A. Hawton <daniel@hawton.org>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package models

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	dbTypes "github.com/adh-partnership/api/pkg/database/models"
	gomysql "github.com/go-sql-driver/mysql"
	"github.com/imdario/mergo"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB
var MaxAttempts = 10
var DelayBetweenAttempts = time.Minute * 1

type DBOptions struct {
	Driver   string
	Host     string
	Port     string
	User     string
	Password string
	Database string
	Options  string

	MaxOpenConns int
	MaxIdleConns int

	CACert string
}

var defaultOptions = DBOptions{
	MaxOpenConns: 50,
	MaxIdleConns: 10,
}

func GenerateDSN(options DBOptions) (string, error) {
	var dsn string

	if options.Driver == "mysql" {
		tls := ""
		if options.CACert != "" {
			tls = "&tls=custom"
		}
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True%s", options.User, options.Password,
			options.Host, options.Port, options.Database, tls)
		if options.Options != "" {
			dsn += "?" + options.Options
		}
	} else {
		return "", fmt.Errorf("unsupported driver: %s", options.Driver)
	}

	return dsn, nil
}

func HandleCACert(driver string, cacert string) error {
	rootCertPool := x509.NewCertPool()
	pem, err := base64.StdEncoding.DecodeString(cacert)
	if err != nil {
		return err
	}
	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		return fmt.Errorf("failed to append PEM")
	}

	// @TODO: support other drivers
	if driver == "mysql" {
		err := gomysql.RegisterTLSConfig("custom", &tls.Config{
			RootCAs: rootCertPool,
		})
		if err != nil {
			return errors.New("error registering tls config: " + err.Error())
		}
	}

	return nil
}

func isValidDriver(driver string) bool {
	return driver == "mysql"
}

func Connect(options DBOptions) error {
	if !isValidDriver(options.Driver) {
		return errors.New("invalid driver: " + options.Driver)
	}

	err := mergo.Merge(&options, defaultOptions)
	if err != nil {
		return errors.New("failed to apply defaults: " + err.Error())
	}

	if options.CACert != "" {
		err := HandleCACert(options.Driver, options.CACert)
		if err != nil {
			return err
		}
	}

	dsn, err := GenerateDSN(options)
	if err != nil {
		return err
	}

	var conn *sql.DB
	if options.Driver == "mysql" {
		conn, err = sql.Open("mysql", dsn)
		if err != nil {
			return err
		}
		DB, err = gorm.Open(mysql.New(mysql.Config{Conn: conn}), &gorm.Config{})
		if err != nil {
			return err
		}
	}

	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	sqlDB.SetMaxOpenConns(options.MaxOpenConns)
	sqlDB.SetMaxIdleConns(options.MaxIdleConns)
	sqlDB.SetConnMaxIdleTime(time.Minute * 5)

	DB.AutoMigrate(&dbTypes.OAuthClient{}, &dbTypes.OAuthLogin{}, &dbTypes.Rating{}, &dbTypes.Role{}, &dbTypes.User{})

	return nil
}
