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

package middleware

import (
	"fmt"
	"strconv"
	"time"

	"github.com/adh-partnership/api/pkg/logger"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

func Logger() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			request := c.Request()
			response := c.Response()
			start := time.Now()

			var err error
			if err = next(c); err != nil {
				c.Error(err)
			}

			stop := time.Now()

			requestSize := request.Header.Get(echo.HeaderContentLength)
			if requestSize == "" {
				requestSize = "0"
			}

			if logger.Format == "json" {
				l := logger.Logger.WithFields(logrus.Fields{
					"component": "gin",

					"status":     response.Status,
					"method":     request.Method,
					"path":       request.RequestURI,
					"ip":         c.RealIP(),
					"latency":    stop.Sub(start).String(),
					"size":       strconv.FormatInt(response.Size, 10),
					"user_agent": request.UserAgent(),
					"referer":    request.Referer(),
				})
				if response.Status >= 400 {
					l.Error()
				} else {
					l.Info()
				}
			} else {
				l := logger.Logger.WithField("component", "gin")
				msg := fmt.Sprintf("%s %d %s %s %s %s %s %s",
					c.RealIP(),
					response.Status,
					request.Method,
					request.RequestURI,
					stop.Sub(start).String(),
					requestSize,
					request.UserAgent(),
					request.Referer(),
				)

				if response.Status >= 400 {
					l.Errorf("%s", msg)
				} else {
					l.Info(msg)
				}
			}
			return err
		}
	}
}
