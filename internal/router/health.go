/*
 * Copyright Daniel Hawton
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

package router

import (
	"database/sql"
	"net/http"

	"github.com/adh-partnership/api/pkg/database"
	"github.com/labstack/echo/v4"
)

func healthCheckHandler(c echo.Context) error {
	return c.String(http.StatusOK, "OK")
}

func readyCheckHandler(c echo.Context) error {
	var d *sql.DB
	d, err := database.DB.DB()
	if err != nil {
		return c.String(http.StatusInternalServerError, "Database not ready")
	}
	err = d.Ping()
	if err != nil {
		return c.String(http.StatusInternalServerError, "Database not ready")
	}

	return c.String(http.StatusOK, "OK")
}
