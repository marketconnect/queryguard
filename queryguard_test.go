package queryguard

import (
	"testing"
)

func TestIsSafeSelectQuery(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		reportingMode bool
		wantErr       bool
	}{
		// Standard mode tests
		{"Valid basic query", "SELECT product_id, quantity FROM stocks WHERE warehouse_id = 123", false, false},
		{"Valid JOIN query", "SELECT s.product_id, o.price FROM stocks s JOIN orders o ON s.product_id = o.product_id", false, false},
		{"Invalid - Subquery", "SELECT product_id FROM stocks WHERE warehouse_id IN (SELECT warehouse_id FROM orders)", false, true},
		{"Invalid - Multi queries", "SELECT product_id FROM stocks; SELECT price FROM orders", false, true},
		{"Invalid - Star", "SELECT * FROM stocks", false, true},
		{"Invalid - GROUP BY in standard", "SELECT product_id, COUNT(*) FROM stocks GROUP BY product_id", false, true},
		{"Invalid - ORDER BY in standard", "SELECT product_id FROM stocks ORDER BY product_id", false, true},
		{"Invalid - DISTINCT", "SELECT DISTINCT product_id FROM stocks", false, true},
		{"Invalid - Function not allowed", "SELECT CONCAT(product_id, '-', warehouse_id) FROM stocks", false, true},
		{"Invalid - Column not exists", "SELECT nonexistent_field FROM stocks", false, true},
		{"Invalid - Table not exists", "SELECT id FROM nonexistent_table", false, true},
		{"Invalid - UNION", "SELECT product_id FROM stocks UNION SELECT product_id FROM orders", false, true},
		{"Invalid - WITH clause", "WITH temp AS (SELECT product_id FROM stocks) SELECT * FROM temp", false, true},
		{"Invalid - LEFT JOIN", "SELECT s.product_id FROM stocks s LEFT JOIN orders o ON s.product_id = o.product_id", false, true},

		// Reporting mode tests
		{"Valid - GROUP BY", "SELECT product_id, COUNT(*) FROM stocks GROUP BY product_id", true, false},
		{"Valid - ORDER BY", "SELECT product_id FROM stocks ORDER BY product_id", true, false},
		{"Valid - LIMIT", "SELECT product_id FROM stocks LIMIT 10", true, false},
		{"Valid - Full reporting", "SELECT product_id, COUNT(*) FROM stocks GROUP BY product_id ORDER BY COUNT(*) DESC LIMIT 10", true, false},
		{"Invalid - HAVING no aggr", "SELECT product_id FROM stocks GROUP BY product_id HAVING product_id > 100", true, true},
		{"Invalid - Subquery", "SELECT product_id FROM stocks WHERE warehouse_id IN (SELECT warehouse_id FROM orders)", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := IsSafeSelectQuery(tt.query, 0, tt.reportingMode)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsSafeSelectQuery() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigModification(t *testing.T) {
	// Save original values
	originalFunctions := make(map[string]bool)
	for k, v := range AllowedFunctions {
		originalFunctions[k] = v
	}
	originalTables := make(map[string][]string)
	for k, v := range AllowedTables {
		originalTables[k] = append([]string{}, v...)
	}

	// Test extension of allowed functions
	t.Run("Add function", func(t *testing.T) {
		// Add CONCAT as allowed function
		AllowedFunctions["CONCAT"] = true

		// Test with previously invalid query
		err := IsSafeSelectQuery("SELECT CONCAT(product_id, '-', warehouse_id) FROM stocks", 0, false)
		if err != nil {
			t.Errorf("After adding CONCAT function, query should be valid but got: %v", err)
		}
	})

	// Test adding new table
	t.Run("Add table", func(t *testing.T) {
		// Add new allowed table
		AllowedTables["products"] = []string{"id", "name", "category", "description"}

		// Test new table access
		err := IsSafeSelectQuery("SELECT id, name FROM products WHERE category = 'electronics'", 0, false)
		if err != nil {
			t.Errorf("After adding products table, query should be valid but got: %v", err)
		}
	})

	// Restore original values
	AllowedFunctions = originalFunctions
	AllowedTables = originalTables
}
