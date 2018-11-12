package pgsql

import (
	"database/sql"
	"time"
)

func (pgSQL *pgSQL) GetSetting(name string) (string, error) {
	defer observeQueryTime("getSetting", "all", time.Now())

	var value string
	err := pgSQL.QueryRow(getSetting, name).Scan(&value)
	if err != nil {
		return "", err
	}

	return value, nil
}

func (pgSQL *pgSQL) UpsertSetting(name, value string) (bool, error) {
	var old string
	err := pgSQL.QueryRow(getSetting, name).Scan(&old)
	if err != nil {
		if err != sql.ErrNoRows {
			return false, err
		}
		_, err = pgSQL.Exec(insertSetting, name, value)
		if err != nil {
			return false, err
		} else {
			return true, nil
		}
	}

	_, err = pgSQL.Exec(updateSetting, value, name)
	if err != nil {
		return false, err
	}

	return true, nil
}
