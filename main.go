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

package main

import (
	"fmt"
	"os"

	dbTypes "github.com/adh-partnership/api/pkg/database/models"
	"github.com/adh-partnership/sso/database/models"
	"github.com/adh-partnership/sso/database/seed"
	"github.com/adh-partnership/sso/pkg/tokens"
	"github.com/adh-partnership/sso/utils"
	"github.com/common-nighthawk/go-figure"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/robfig/cron/v3"
	"hawton.dev/log4g"
)

var log = log4g.Category("main")

func main() {
	log4g.SetLogLevel(log4g.DEBUG)

	intro := figure.NewFigure("ZDV SSO", "", false).Slicify()
	for i := 0; i < len(intro); i++ {
		log.Info(intro[i])
	}

	log.Info("Starting ZDV SSO")
	log.Info("Checking for .env, loading if exists")
	if _, err := os.Stat(".env"); err == nil {
		log.Info("Found, loading")
		err := godotenv.Load()
		if err != nil {
			log.Error("Error loading .env file: " + err.Error())
		}
	}

	appenv := utils.Getenv("APP_ENV", "dev")
	log.Debug(fmt.Sprintf("APPENV=%s", appenv))

	if appenv == "production" {
		log4g.SetLogLevel(log4g.INFO)
		log.Info("Setting gin to Release Mode")
		gin.SetMode(gin.ReleaseMode)
	} else {
		log4g.SetLogLevel(log4g.DEBUG)
	}

	log.Info("Connecting to database and handling migrations")
	models.Connect(models.DBOptions{
		Driver:   utils.Getenv("DB_DRIVER", "mysql"),
		Host:     utils.Getenv("DB_HOST", "localhost"),
		Port:     utils.Getenv("DB_PORT", "3306"),
		User:     utils.Getenv("DB_USERNAME", "root"),
		Password: utils.Getenv("DB_PASSWORD", ""),
		Database: utils.Getenv("DB_DATABASE", "sso"),

		MaxOpenConns: 10,
		MaxIdleConns: 1,

		CACert: utils.Getenv("DB_CA_CERT", ""),
	})

	seed.CheckSeeds()

	log.Info("Configuring Gin Server")
	server := NewServer(appenv)

	err := tokens.BuildKeyset(utils.Getenv("SSO_JWKS", ""))
	if err != nil {
		log.Error("Error building keyset: " + err.Error())
	}
	log.Info("Built JWKS with %d keys", tokens.KeySet.Len())

	log.Info("Configuring scheduled jobs")
	jobs := cron.New()
	jobs.AddFunc("@every 1m", func() {
		if err := models.DB.Where("code <> '' and now() >= date_add(created_at, interval 30 minute)").Delete(&dbTypes.OAuthLogin{}).Error; err != nil {
			log4g.Category("job/cleanup").Error(fmt.Sprintf("Error cleaning up old codes: %s", err.Error()))
		}
		if err := models.DB.Where("now() >= expires_at").Delete(&dbTypes.OAuthLogin{}).Error; err != nil {
			log4g.Category("job/cleanup").Error(fmt.Sprintf("Error cleaning up expired codes: %s", err.Error()))
		}
	})
	jobs.Start()

	log.Info("Done with setup, starting web server...")
	server.engine.Run(fmt.Sprintf(":%s", utils.Getenv("PORT", "3000")))
}
