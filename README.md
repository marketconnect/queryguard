# QueryGuard

QueryGuard is a Go package for validating SQL queries against security and architectural constraints. It helps protect your application by ensuring SQL queries follow safe patterns and access only allowed tables and columns.

## Features

- Validates SQL SELECT queries against defined security rules
- Prevents SQL injection attacks
- Restricts table and column access to approved lists
- Enforces good SQL practices (no `SELECT *`, restricted JOIN types, etc.)
- Supports two validation modes:
  - Standard mode: Basic data access with minimal constructs
  - Reporting mode: More advanced queries with GROUP BY, ORDER BY, etc.

## Installation

```
go get github.com/marketconnect/queryguard
```

## Usage

```go
package main

import (
    "fmt"
    "github.com/marketconnect/queryguard"
)

func main() {
    // Basic usage - validate a simple SELECT query
    query := "SELECT product_id, quantity FROM stocks WHERE warehouse_id = 123"
    
    // Standard mode validation
    err := queryguard.IsSafeSelectQuery(query, 0, false)
    if err != nil {
        fmt.Printf("Query validation failed: %v\n", err)
        return
    }
    
    fmt.Println("Query is valid!")
    
    // For reporting queries with aggregations, sorting, limits
    reportingQuery := "SELECT product_id, COUNT(*) FROM stocks GROUP BY product_id ORDER BY COUNT(*) DESC LIMIT 10"
    
    // Use reporting mode (third parameter true)
    err = queryguard.IsSafeSelectQuery(reportingQuery, 0, true)
    if err != nil {
        fmt.Printf("Reporting query validation failed: %v\n", err)
        return
    }
    
    fmt.Println("Reporting query is valid!")
}
```

## Configuration

The package exposes several variables that can be modified to customize validation:

```go
// Configure allowed tables and columns
queryguard.AllowedTables["newtable"] = []string{"column1", "column2"}

// Add additional allowed functions
queryguard.AllowedFunctions["LOWER"] = true

// Adjust validation limits
queryguard.MaxQueryDepth = 5
queryguard.MaxConditions = 30
```

## Limitations

QueryGuard is designed for validating SELECT queries only and does not support:
- Data manipulation queries (INSERT, UPDATE, DELETE)
- Schema modification queries (CREATE, ALTER, DROP)
- Subqueries, CTEs, window functions
- Certain advanced SQL features

## License

[MIT License](LICENSE) 