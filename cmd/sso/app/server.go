/*
 * Copyright ADH Partnership
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package app

import (
	"github.com/adh-partnership/api/pkg/database"
	"github.com/adh-partnership/api/pkg/database/models"
	"github.com/adh-partnership/api/pkg/logger"
	"github.com/adh-partnership/sso/v2/internal/router"
	"github.com/adh-partnership/sso/v2/pkg/config"
	"github.com/adh-partnership/sso/v2/pkg/server"
	"github.com/urfave/cli/v2"
)

var log = logger.Logger.WithField("component", "server")

func newServerCommand() *cli.Command {
	return &cli.Command{
		Name:  "server",
		Usage: "Start the SSO server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Usage:   "Path to the configuration file",
				Value:   "config.yaml",
				EnvVars: []string{"CONFIG"},
			},
			&cli.StringFlag{
				Name:    "jwks-config",
				Usage:   "Path to the JWKS configuration file",
				Value:   "jwks.yaml",
				EnvVars: []string{"JWKS_CONFIG"},
			},
		},
		Action: func(c *cli.Context) error {
			log.Infof("Starting SSO server")
			log.Infof("config=%s", c.String("config"))

			log.Infof("Loading configuration...")
			err := config.LoadConfig(c.String("config"), c.String("jwks-config"))
			if err != nil {
				return err
			}

			log.Infof("Connecting to database")
			err = database.Connect(database.DBOptions{
				Host:     config.Cfg.Database.Host,
				Port:     config.Cfg.Database.Port,
				User:     config.Cfg.Database.User,
				Password: config.Cfg.Database.Password,
				Database: config.Cfg.Database.Database,
				CACert:   config.Cfg.Database.CACert,
				Driver:   "mysql",
				Logger:   logger.Logger,
			})
			if err != nil {
				return err
			}

			log.Infof("Running Database Migrations")
			err = database.DB.AutoMigrate(
				&models.OAuthClient{},
				&models.OAuthLogin{},
				&models.OAuthRefresh{},
			)
			if err != nil {
				return err
			}

			log.Infof("Building web server...")
			srvr := server.NewServer(
				router.SetupRoutes,
			)

			log.Infof("Building routes...")
			srvr.BuildRoutes()

			return nil
		},
	}
}
