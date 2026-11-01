package main

import (
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"vyomite/pkg/models" // Assuming vyomite is the module name
)

func main() {
	dsn := "host=localhost user=postgres password=postgres dbname=vyomite port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	var findings []models.VulnerabilityFinding
	db.Find(&findings)
	for _, f := range findings {
		fmt.Printf("Category: '%s', Title: '%s'\n", f.Category, f.Title)
	}
}
