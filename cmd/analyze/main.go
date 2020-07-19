package main

import (
	"fmt"
)

func main() {
	db := GetDbConnection()
	authDataList := FetchAuthData(db, 10)

	for _, authData := range authDataList {
		fmt.Printf("%#v\n", authData)
	}
}
