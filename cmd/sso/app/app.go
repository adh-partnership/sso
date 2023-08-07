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
	"fmt"

	"github.com/adh-partnership/api/pkg/logger"
	"github.com/urfave/cli/v2"
)

func NewRootCommand() *cli.App {
	return &cli.App{
		Name:  "sso",
		Usage: "ADH Partnership Single Sign-On OAuth2 Provider",
		Commands: []*cli.Command{
			newServerCommand(),
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Usage:   "Set the log level",
				Value:   "info",
				EnvVars: []string{"LOG_LEVEL"},
			},
			&cli.StringFlag{
				Name:    "log-format",
				Aliases: []string{"f"},
				Usage:   "Set the log format (text or json)",
				Value:   "text",
				EnvVars: []string{"LOG_FORMAT"},
			},
		},
		Before: func(c *cli.Context) error {
			format := c.String("log-format")
			if !logger.IsValidFormat(format) {
				return fmt.Errorf("invalid log format: %s", format)
			}
			logger.NewLogger(format)

			l, err := logger.ParseLogLevel(c.String("log-level"))
			if err != nil {
				return err
			}
			logger.Logger.SetLevel(l)

			return nil
		},
	}
}
