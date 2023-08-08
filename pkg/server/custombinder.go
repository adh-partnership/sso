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

package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"gopkg.in/yaml.v2"
	"gorm.io/gorm/utils"

	"github.com/adh-partnership/sso/v2/pkg/response"
)

type CustomBinder struct{}

func (b *CustomBinder) Bind(i interface{}, c echo.Context) error {
	ct := c.Request().Header.Get(echo.HeaderContentType)
	if utils.Contains(response.YamlHeaders, ct) {
		if err := yaml.NewDecoder(c.Request().Body).Decode(i); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	} else {
		db := new(echo.DefaultBinder)
		err := db.Bind(i, c)
		if err != nil {
			return err
		}
	}

	return nil
}
