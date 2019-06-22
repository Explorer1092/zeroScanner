package main

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

type PocDb struct {
	dbFile string
	db     *sql.DB
	sqlMap map[string]string
}

func (self *PocDb) Init(dbFile string) error {
	self.dbFile = dbFile
	self.sqlMap = map[string]string{
		"insert":         "INSERT INTO poc (name, code, type, info, service, level, username_dict, password_dict, other_dict, suggestion, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
		"update":         "UPDATE poc SET name=?, code=?, type=?, info=?, service=?, level=?, username_dict=?, password_dict=?, other_dict=?, suggestion=?, hash=? WHERE id=?",
		"delete":         "DELETE FROM poc WHERE id in (%s)",
		"query":          "SELECT * FROM poc WHERE id in (%s)",
		"queryall":       "SELECT * FROM poc",
		"queryallenable": "SELECT * FROM poc WHERE enable=1",
		"switch":         "UPDATE poc SET enable=? WHERE id in (%s)",
	}
	self.db, _ = sql.Open("sqlite3", self.dbFile)
	return self.tryCreateTable()
}

func (self *PocDb) tryCreateTable() error {
	var createTable = `
	CREATE TABLE IF NOT EXISTS poc (
		id INTEGER PRIMARY KEY,
		name varchar(50) NOT NULL UNIQUE,
		code text NOT NULL,
		type varchar(5) NOT NULL,
		info varchar(1000) NOT NULL,
		service varchar(100) NOT NULL,
		level INTEGER NOT NULL,
		username_dict varchar(100) DEFAULT NULL,
		password_dict varchar(100) DEFAULT NULL,
		other_dict varchar(100) DEFAULT NULL,
		suggestion varchar(1000) DEFAULT "",
		hash varchar(32) DEFAULT NULL,
		enable INTEGER NOT NULL DEFAULT 0,
		updatetime DATETIME DEFAULT (DATETIME(CURRENT_TIMESTAMP, 'LOCALTIME'))
	);
	CREATE INDEX IF NOT EXISTS poc_name_index on poc (name);
	CREATE INDEX IF NOT EXISTS poc_updatetime_index on poc (updatetime);
	CREATE INDEX IF NOT EXISTS poc_enable_index on poc (enable);

	CREATE TRIGGER IF NOT EXISTS poc_update_trigger AFTER UPDATE ON poc FOR EACH ROW
		WHEN OLD.updatetime = NEW.updatetime
	BEGIN
		UPDATE poc SET updatetime = (DATETIME(CURRENT_TIMESTAMP, 'LOCALTIME'))  WHERE id = NEW.id;
	END;`
	_, err := self.db.Exec(createTable)
	return err
}

func (self *PocDb) Add(args ...interface{}) (int64, error) {
	r, err := self.db.Exec(self.sqlMap["insert"], args...)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func (self *PocDb) Delete(ids ...interface{}) error {
	var err error
	sqi := fmt.Sprintf(self.sqlMap["delete"], strings.TrimSuffix(strings.Repeat("?,", len(ids)), ","))
	_, err = self.db.Exec(sqi, ids...)
	return err
}

func (self *PocDb) Update(args ...interface{}) error {
	_, err := self.db.Exec(self.sqlMap["update"], args...)
	return err
}

func (self *PocDb) Query(ids ...interface{}) ([]map[string]interface{}, error) {
	sqi := fmt.Sprintf(self.sqlMap["query"], strings.TrimSuffix(strings.Repeat("?,", len(ids)), ","))
	return self._query(sqi, ids...)
}

func (self *PocDb) QueryAll() ([]map[string]interface{}, error) {
	return self._query(self.sqlMap["queryall"])
}

func (self *PocDb) QueryAllEnable() ([]map[string]interface{}, error) {
	return self._query(self.sqlMap["queryallenable"])
}

func (self *PocDb) Switch(status int, ids ...interface{}) error {
	var err error
	sqi := fmt.Sprintf(self.sqlMap["switch"], strings.TrimSuffix(strings.Repeat("?,", len(ids)), ","))
	_, err = self.db.Exec(sqi, append([]interface{}{status}, ids...)...)
	return err
}

func (self *PocDb) _query(sqlStr string, vals ...interface{}) ([]map[string]interface{}, error) {
	rowMaps := []map[string]interface{}{}
	rows, err := self.db.Query(sqlStr, vals...)
	if err != nil {
		return nil, err
	} else {
		defer rows.Close()
		colNames, err := rows.Columns()
		if err != nil {
			return nil, err
		}

		colValues := make([]interface{}, len(colNames))
		colValuesPointers := make([]interface{}, len(colNames))
		for i, _ := range colNames {
			colValuesPointers[i] = &colValues[i]
		}

		for rows.Next() {
			if err := rows.Scan(colValuesPointers...); err != nil {
				return nil, err
			}
			each := make(map[string]interface{})
			for i, colName := range colNames {
				if v, ok := colValues[i].([]byte); ok {
					each[colName] = string(v)
					continue
				}
				each[colName] = colValues[i]
			}
			rowMaps = append(rowMaps, each)
		}
	}
	return rowMaps, nil
}
