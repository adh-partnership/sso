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

package response

import (
	"net/http"

	"github.com/adh-partnership/sso/v2/pkg/utils"

	"github.com/labstack/echo/v4"
	"gopkg.in/yaml.v2"
)

var YamlHeaders = []string{"application/x-yaml", "application/vnd.yaml", "text/yaml", "text/vnd.yaml"}

func RespondMessage(c echo.Context, status int, message string) error {
	return Respond(c, status, map[string]string{"message": message})
}

func RespondBlank(c echo.Context, status int) error {
	return Respond(c, status, map[string]string{})
}

func RespondError(c echo.Context, status int, err error) error {
	return Respond(c, status, map[string]string{"error": err.Error()})
}

func Respond(c echo.Context, status int, data interface{}) error {
	hdr := c.Request().Header.Get("Accept")
	if utils.Contains(YamlHeaders, hdr) {
		b, err := yaml.Marshal(data)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		c.Response().Header().Set("Content-Type", c.Request().Header.Get("Accept"))
		return c.String(status, string(b))
	} else if hdr == "application/xml" {
		return c.XML(status, data)
	} else {
		return c.JSON(status, data)
	}
}

func HandleError(c echo.Context, err error) error {
	if err != nil {
		return RespondError(c, http.StatusInternalServerError, err)
	}
	return nil
}
