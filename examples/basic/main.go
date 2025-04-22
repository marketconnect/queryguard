package main

import (
	"fmt"

	"github.com/marketconnect/queryguard"
)

func main() {
	// Example queries
	queries := map[string]string{
		"valid_basic":       "SELECT product_id, quantity FROM stocks WHERE warehouse_id = 123",
		"valid_join":        "SELECT s.product_id, o.price FROM stocks s JOIN orders o ON s.product_id = o.product_id",
		"invalid_star":      "SELECT * FROM stocks",
		"invalid_function":  "SELECT CONCAT(product_id, '-', warehouse_id) FROM stocks",
		"invalid_subquery":  "SELECT product_id FROM stocks WHERE warehouse_id IN (SELECT warehouse_id FROM orders)",
		"invalid_multiple":  "SELECT product_id FROM stocks; SELECT price FROM orders",
		"invalid_injection": "SELECT product_id FROM stocks WHERE warehouse_id = '1' OR 1=1; --'",
	}

	fmt.Println("======= STANDARD MODE =======")
	for name, query := range queries {
		err := queryguard.IsSafeSelectQuery(query, 0, false)
		status := "VALID"
		if err != nil {
			status = fmt.Sprintf("INVALID: %v", err)
		}
		fmt.Printf("%-20s: %s\n", name, status)
	}

	// Reporting mode examples
	reportingQueries := map[string]string{
		"valid_group_by":        "SELECT product_id, COUNT(*) FROM stocks GROUP BY product_id",
		"valid_order_by":        "SELECT product_id, quantity FROM stocks ORDER BY quantity DESC",
		"valid_limit":           "SELECT product_id FROM stocks LIMIT 10",
		"valid_full_reporting":  "SELECT product_id, COUNT(*) FROM stocks GROUP BY product_id ORDER BY COUNT(*) DESC LIMIT 10",
		"invalid_having_no_agg": "SELECT product_id FROM stocks GROUP BY product_id HAVING product_id > 100",
	}

	fmt.Println("\n======= REPORTING MODE =======")
	for name, query := range reportingQueries {
		err := queryguard.IsSafeSelectQuery(query, 0, true)
		status := "VALID"
		if err != nil {
			status = fmt.Sprintf("INVALID: %v", err)
		}
		fmt.Printf("%-20s: %s\n", name, status)
	}

	// Extending allowed functions example
	fmt.Println("\n======= EXTENDED CONFIGURATION =======")
	originalCount := len(queryguard.AllowedFunctions)

	// Add CONCAT as an allowed function
	queryguard.AllowedFunctions["CONCAT"] = true

	// Add a new table
	queryguard.AllowedTables["products"] = []string{"id", "name", "category", "description"}

	// Now the previously invalid query should work
	err := queryguard.IsSafeSelectQuery("SELECT CONCAT(product_id, '-', warehouse_id) FROM stocks", 0, false)
	status := "VALID"
	if err != nil {
		status = fmt.Sprintf("INVALID: %v", err)
	}
	fmt.Printf("Added function       : %s\n", status)

	// Try with the new table
	err = queryguard.IsSafeSelectQuery("SELECT id, name FROM products WHERE category = 'electronics'", 0, false)
	status = "VALID"
	if err != nil {
		status = fmt.Sprintf("INVALID: %v", err)
	}
	fmt.Printf("New table access     : %s\n", status)

	fmt.Printf("Functions before: %d, after: %d\n", originalCount, len(queryguard.AllowedFunctions))
}
