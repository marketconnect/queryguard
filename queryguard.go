package queryguard

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/xwb1989/sqlparser"
)

// Common SQL reserved keywords that should not be used as aliases
var sqlKeywords = map[string]bool{
	"select": true, "from": true, "where": true, "group": true, "order": true,
	"having": true, "limit": true, "offset": true, "union": true, "case": true,
	"when": true, "then": true, "else": true, "end": true, "create": true,
	"alter": true, "drop": true, "insert": true, "update": true, "delete": true,
	"merge": true, "join": true, "inner": true, "outer": true, "left": true,
	"right": true, "full": true, "on": true, "as": true, "using": true, "with": true,
	"distinct": true, "all": true, "into": true, "values": true, "index": true,
	"primary": true, "key": true, "foreign": true, "references": true, "constraint": true,
	"default": true, "null": true, "auto_increment": true, "table": true, "view": true,
	"procedure": true, "function": true, "trigger": true, "database": true, "schema": true,
	"if": true, "while": true, "do": true, "for": true, "return": true, "declare": true,
	"exec": true, "execute": true, "begin": true, "commit": true, "rollback": true,
	"transaction": true, "set": true, "between": true, "like": true, "in": true, "exists": true,
	"and": true, "or": true, "not": true, "is": true, "true": true, "false": true,
}

// AllowedTables defines tables and their fields that are permitted in queries
var AllowedTables = map[string][]string{
	"stocks":    {"product_id", "warehouse_id", "size_option_id", "quantity", "basic_price", "timestamp"},
	"orders":    {"product_id", "size_option_id", "warehouse_id", "price", "orders", "timestamp"},
	"orders30d": {"product_id", "subject_id", "price", "orders", "is_fbs", "total_revenue"},
}

// AllowedFunctions defines SQL functions that are permitted in queries
var AllowedFunctions = map[string]bool{
	"COUNT": true,
	"SUM":   true,
	"AVG":   true,
	"MIN":   true,
	"MAX":   true,
}

// AllowedOperators defines SQL operators that are permitted in queries
var AllowedOperators = map[string]bool{
	"=":      true,
	"<":      true,
	">":      true,
	"<=":     true,
	">=":     true,
	"!=":     true,
	"<>":     true,
	"IN":     true,
	"LIKE":   true,
	"IS":     true,
	"IS NOT": true,
}

// ProhibitedPatterns defines regex patterns for prohibited SQL constructs
var ProhibitedPatterns = []string{
	`(?i)\bWITH\b`,           // CTE/WITH clause
	`/\*.*\*/`,               // Multi-line comments
	`--.*$`,                  // Single-line comments
	`;\s*\S`,                 // Multiple statements
	`\bunion\b`,              // UNION
	`\bexcept\b`,             // EXCEPT
	`\bintersect\b`,          // INTERSECT
	`\bcreate\b`,             // CREATE
	`\bdrop\b`,               // DROP
	`\balter\b`,              // ALTER
	`\bexec\b`,               // EXEC
	`\bcall\b`,               // CALL
	`\bpragma\b`,             // PRAGMA
	`\binsert\b`,             // INSERT
	`\bupdate\b`,             // UPDATE
	`\bdelete\b`,             // DELETE
	`\bwindow\b`,             // WINDOW
	`\bpartition\b`,          // PARTITION
	`\brecursive\b`,          // RECURSIVE
	`\busing\b`,              // USING (not in JOIN context)
	`\bexplain\b`,            // EXPLAIN
	`\banalyze\b`,            // ANALYZE
	`\bexplain\s+analyze\b`,  // EXPLAIN ANALYZE
	`\bcase\b`,               // CASE
	`\bover\b`,               // OVER for window functions
	`\bnatural\b\s+\bjoin\b`, // NATURAL JOIN
}

// Configuration options for query validation
var (
	MaxQueryDepth = 10
	MaxConditions = 50
	MaxJoinDepth  = 3
)

var prohibitedPatternsRegex []*regexp.Regexp

func init() {
	for _, pattern := range ProhibitedPatterns {
		prohibitedPatternsRegex = append(prohibitedPatternsRegex,
			regexp.MustCompile(`(?i)`+pattern))
	}

	// Normalize all table fields to lowercase
	for table, fields := range AllowedTables {
		lowerFields := make([]string, len(fields))
		for i, f := range fields {
			lowerFields[i] = strings.ToLower(f)
		}
		AllowedTables[table] = lowerFields
	}

	// Normalize function names to uppercase
	upperFuncs := make(map[string]bool)
	for name, allowed := range AllowedFunctions {
		upperFuncs[strings.ToUpper(name)] = allowed
	}
	AllowedFunctions = upperFuncs
}

// IsSafeSelectQuery validates a SQL query against security rules
// The reportingMode parameter changes validation behavior for reporting queries
func IsSafeSelectQuery(sqlQuery string, currentDepth int, reportingMode bool) error {
	if currentDepth > MaxQueryDepth {
		return fmt.Errorf("maximum query nesting depth exceeded (%d)", MaxQueryDepth)
	}

	// Check for multiple queries using string methods
	trimmedQuery := strings.TrimSpace(sqlQuery)
	// Check for semicolon not at the end of the query
	semicolonPos := strings.Index(trimmedQuery, ";")
	if semicolonPos >= 0 && semicolonPos < len(trimmedQuery)-1 {
		// There's a semicolon, and it's not at the end
		remainder := strings.TrimSpace(trimmedQuery[semicolonPos+1:])
		if remainder != "" {
			return fmt.Errorf("extra tokens after main statement: %q", remainder)
		}
	}

	// Remove trailing semicolon if present
	if strings.HasSuffix(trimmedQuery, ";") {
		trimmedQuery = trimmedQuery[:len(trimmedQuery)-1]
	}

	// Pre-check for dangerous patterns in text
	// This check is now necessary as we won't use pre-filtering
	if err := checkDangerousPatterns(trimmedQuery); err != nil {
		return err
	}

	// Parse the query
	stmt, err := sqlparser.Parse(trimmedQuery)
	if err != nil {
		return fmt.Errorf("SQL parsing error: %w", err)
	}

	// Check query type - must be SELECT only
	selectStmt, ok := stmt.(*sqlparser.Select)
	if !ok {
		return fmt.Errorf("forbidden SQL query type: only SELECT is allowed")
	}

	// Check for prohibited constructs in AST
	if err := checkProhibitedConstructs(selectStmt); err != nil {
		return err
	}

	// Check for DISTINCT
	if selectStmt.Distinct != "" {
		return fmt.Errorf("SELECT DISTINCT usage is forbidden for performance reasons")
	}

	// Check for FROM
	if selectStmt.From == nil {
		return fmt.Errorf("missing FROM clause")
	}

	// Check for CROSS JOIN using commas
	if len(selectStmt.From) > 1 {
		return fmt.Errorf("old-style implicit CROSS JOIN using commas is forbidden, use explicit JOIN syntax")
	}

	// Collect and validate tables
	tableAliases, err := collectTablesInfo(selectStmt)
	if err != nil {
		return fmt.Errorf("table validation error: %w", err)
	}

	// Check all fields and expressions in SELECT
	if err := validateSelectExpressions(selectStmt.SelectExprs, tableAliases); err != nil {
		return fmt.Errorf("SELECT clause error: %w", err)
	}

	// Check WHERE
	if selectStmt.Where != nil {
		if err := validateWhereExpression(selectStmt.Where.Expr, tableAliases); err != nil {
			return fmt.Errorf("WHERE clause error: %w", err)
		}
	}

	// Check GROUP BY, ORDER BY and LIMIT depending on mode
	if !reportingMode {
		// In standard mode, these constructs are forbidden
		if len(selectStmt.GroupBy) > 0 {
			return fmt.Errorf("GROUP BY clause is forbidden in standard mode, use reporting mode for data aggregation")
		}

		if len(selectStmt.OrderBy) > 0 {
			return fmt.Errorf("ORDER BY clause is forbidden in standard mode, use reporting mode for data sorting")
		}

		if selectStmt.Having != nil {
			return fmt.Errorf("HAVING clause is forbidden")
		}

		if selectStmt.Limit != nil {
			return fmt.Errorf("LIMIT clause is forbidden in standard mode, use reporting mode for result limiting")
		}
	} else {
		// In reporting mode, check constraints on these constructs
		if err := validateReportingClauses(selectStmt, tableAliases); err != nil {
			return err
		}
	}

	return nil
}

// Check for dangerous text patterns
func checkDangerousPatterns(query string) error {
	lowerQuery := strings.ToLower(query)

	// Check for multiple SELECT statements (subqueries)
	if strings.Count(lowerQuery, "select") > 1 {
		selectIndexes := findAllIndexes(lowerQuery, "select")
		// Check if they are in parentheses (potential subqueries)
		for _, idx := range selectIndexes[1:] { // Skip the first SELECT
			// If there's an opening parenthesis before "select", it's a subquery
			for i := idx - 1; i >= 0; i-- {
				if lowerQuery[i] == '(' {
					return fmt.Errorf("subqueries are forbidden")
				}
				if !unicode.IsSpace(rune(lowerQuery[i])) {
					break
				}
			}
		}
	}

	// Check for UNION
	if strings.Contains(lowerQuery, " union ") {
		return fmt.Errorf("UNION operations are forbidden")
	}

	// Check for WITH (CTE)
	if regexp.MustCompile(`(?i)^\s*with\s+`).MatchString(lowerQuery) {
		return fmt.Errorf("WITH clauses (Common Table Expressions) are forbidden")
	}

	// Other dangerous constructs
	dangerousPatterns := []string{
		"--;", "/*", "*/", "@@", "xp_", "sp_",
		"exec ", "execute ", "declare ", "cast(",
		"convert(", "information_schema", "sysobjects",
		"benchmark(", "sleep(", "load_file(", "load data",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerQuery, pattern) {
			return fmt.Errorf("prohibited SQL pattern detected: %s", pattern)
		}
	}

	return nil
}

// Helper function to find all occurrences of substring
func findAllIndexes(s, substr string) []int {
	var indexes []int
	index := 0
	for {
		idx := strings.Index(s[index:], substr)
		if idx == -1 {
			break
		}
		indexes = append(indexes, index+idx)
		index += idx + len(substr)
	}
	return indexes
}

// Check for prohibited constructs in AST tree
func checkProhibitedConstructs(stmt *sqlparser.Select) error {
	// Check for subqueries in FROM
	for _, tableExpr := range stmt.From {
		if err := checkForSubqueries(tableExpr); err != nil {
			return err
		}
	}

	// Check for subqueries in WHERE
	if stmt.Where != nil && containsSubquery(stmt.Where.Expr) {
		return fmt.Errorf("subqueries in WHERE clause are forbidden")
	}

	// Check for HAVING
	if stmt.Having != nil {
		if !containsAggregateFunction(stmt.Having.Expr) {
			return fmt.Errorf("HAVING clause must contain at least one aggregate function")
		}
		if containsSubquery(stmt.Having.Expr) {
			return fmt.Errorf("subqueries in HAVING clause are forbidden")
		}
	}

	// Check for UNION
	// UNION constructs are usually parsed as a separate type, but add an extra check
	selectStr := sqlparser.String(stmt)
	if strings.Contains(strings.ToUpper(selectStr), " UNION ") {
		return fmt.Errorf("UNION operations are forbidden")
	}

	return nil
}

// Check for subqueries in FROM clause
func checkForSubqueries(tableExpr sqlparser.TableExpr) error {
	switch expr := tableExpr.(type) {
	case *sqlparser.AliasedTableExpr:
		if _, ok := expr.Expr.(*sqlparser.Subquery); ok {
			return fmt.Errorf("subqueries in FROM clause are forbidden")
		}
	case *sqlparser.JoinTableExpr:
		if err := checkForSubqueries(expr.LeftExpr); err != nil {
			return err
		}
		if err := checkForSubqueries(expr.RightExpr); err != nil {
			return err
		}

		// Check JOIN type
		joinType := strings.ToUpper(strings.TrimSpace(expr.Join))
		if joinType != "JOIN" && joinType != "INNER JOIN" {
			return fmt.Errorf("only INNER JOIN or JOIN are allowed, found: %s", expr.Join)
		}

		// Check ON condition
		if expr.Condition.On == nil {
			return fmt.Errorf("JOIN must have ON condition")
		}

		// Check for USING
		if expr.Condition.Using != nil {
			return fmt.Errorf("USING construct in JOIN is forbidden, use ON instead")
		}

		// Check for subqueries in ON condition
		if containsSubquery(expr.Condition.On) {
			return fmt.Errorf("subqueries in JOIN ON condition are forbidden")
		}
	}

	return nil
}

// Check if expression contains a subquery
func containsSubquery(expr sqlparser.Expr) bool {
	if expr == nil {
		return false
	}

	switch e := expr.(type) {
	case *sqlparser.Subquery:
		return true
	case *sqlparser.AndExpr:
		return containsSubquery(e.Left) || containsSubquery(e.Right)
	case *sqlparser.OrExpr:
		return containsSubquery(e.Left) || containsSubquery(e.Right)
	case *sqlparser.NotExpr:
		return containsSubquery(e.Expr)
	case *sqlparser.ParenExpr:
		return containsSubquery(e.Expr)
	case *sqlparser.ComparisonExpr:
		return containsSubquery(e.Left) || containsSubquery(e.Right)
	case *sqlparser.RangeCond:
		return containsSubquery(e.Left) || containsSubquery(e.From) || containsSubquery(e.To)
	case *sqlparser.ExistsExpr:
		return true // EXISTS always contains a subquery
	}

	return false
}

// Check if expression contains an aggregate function
func containsAggregateFunction(expr sqlparser.Expr) bool {
	found := false

	sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
		switch n := node.(type) {
		case *sqlparser.FuncExpr:
			funcName := strings.ToUpper(n.Name.String())
			if funcName == "SUM" || funcName == "COUNT" || funcName == "AVG" || funcName == "MIN" || funcName == "MAX" {
				found = true
				return false, nil
			}
		}
		return true, nil
	}, expr)

	return found
}

// Collect information about tables in the query
func collectTablesInfo(stmt *sqlparser.Select) (map[string]string, error) {
	aliases := make(map[string]string) // alias -> table
	aliasCount := make(map[string]int) // for duplicate alias checking

	for _, tableExpr := range stmt.From {
		if err := extractTableAliases(tableExpr, aliases, aliasCount); err != nil {
			return nil, err
		}
	}

	return aliases, nil
}

// Recursively extract table aliases
func extractTableAliases(tableExpr sqlparser.TableExpr, aliases map[string]string, aliasCount map[string]int) error {
	switch t := tableExpr.(type) {
	case *sqlparser.AliasedTableExpr:
		if tableName, ok := t.Expr.(sqlparser.TableName); ok {
			// Check for DB qualifier
			if !tableName.Qualifier.IsEmpty() {
				return fmt.Errorf("database qualifier usage is forbidden: %s",
					tableName.Qualifier.String())
			}

			// Check for allowed table
			tblName := tableName.Name.String()
			tblNameLower := strings.ToLower(tblName)
			if _, ok := AllowedTables[tblNameLower]; !ok {
				return fmt.Errorf("forbidden table: %s", tblName)
			}

			// Handle alias
			var aliasStr string
			if !t.As.IsEmpty() {
				aliasStr = t.As.String()
				aliasLower := strings.ToLower(aliasStr)

				// Check for reserved keyword
				if isReservedKeyword(aliasLower) {
					return fmt.Errorf("alias '%s' is a reserved SQL keyword, choose a different alias",
						aliasStr)
				}

				// Check for conflict with table name
				for existingTable := range AllowedTables {
					if aliasLower == existingTable {
						return fmt.Errorf("alias '%s' conflicts with an existing table name, choose a different alias",
							aliasStr)
					}
				}

				// Add alias
				aliases[aliasLower] = tblNameLower

				// Check for duplication
				aliasCount[aliasLower]++
				if aliasCount[aliasLower] > 1 {
					return fmt.Errorf("duplicate alias detected: %s", aliasStr)
				}
			} else {
				// If no explicit alias, use table name
				aliases[tblNameLower] = tblNameLower

				// Check for duplication
				aliasCount[tblNameLower]++
				if aliasCount[tblNameLower] > 1 {
					return fmt.Errorf("duplicate table name detected: %s", tblName)
				}
			}
		} else if tableName, ok := t.Expr.(*sqlparser.TableName); ok {
			// Also handle *sqlparser.TableName
			// Check for DB qualifier
			if !tableName.Qualifier.IsEmpty() {
				return fmt.Errorf("database qualifier usage is forbidden: %s",
					tableName.Qualifier.String())
			}

			// Check for allowed table
			tblName := tableName.Name.String()
			tblNameLower := strings.ToLower(tblName)
			if _, ok := AllowedTables[tblNameLower]; !ok {
				return fmt.Errorf("forbidden table: %s", tblName)
			}

			// Handle alias
			var aliasStr string
			if !t.As.IsEmpty() {
				aliasStr = t.As.String()
				aliasLower := strings.ToLower(aliasStr)

				// Check for reserved keyword
				if isReservedKeyword(aliasLower) {
					return fmt.Errorf("alias '%s' is a reserved SQL keyword, choose a different alias",
						aliasStr)
				}

				// Check for conflict with table name
				for existingTable := range AllowedTables {
					if aliasLower == existingTable {
						return fmt.Errorf("alias '%s' conflicts with an existing table name, choose a different alias",
							aliasStr)
					}
				}

				// Add alias
				aliases[aliasLower] = tblNameLower

				// Check for duplication
				aliasCount[aliasLower]++
				if aliasCount[aliasLower] > 1 {
					return fmt.Errorf("duplicate alias detected: %s", aliasStr)
				}
			} else {
				// If no explicit alias, use table name
				aliases[tblNameLower] = tblNameLower

				// Check for duplication
				aliasCount[tblNameLower]++
				if aliasCount[tblNameLower] > 1 {
					return fmt.Errorf("duplicate table name detected: %s", tblName)
				}
			}
		} else {
			// If we get here, the expression is something other than a table name
			return fmt.Errorf("only direct table references are allowed in FROM, found: %T", t.Expr)
		}
	case *sqlparser.JoinTableExpr:
		// Check JOIN type
		joinType := strings.ToUpper(strings.TrimSpace(t.Join))
		if joinType != "JOIN" && joinType != "INNER JOIN" {
			return fmt.Errorf("only INNER JOIN or JOIN are allowed, found: %s", t.Join)
		}

		// Extract aliases from left and right parts
		if err := extractTableAliases(t.LeftExpr, aliases, aliasCount); err != nil {
			return err
		}
		if err := extractTableAliases(t.RightExpr, aliases, aliasCount); err != nil {
			return err
		}

		// Check JOIN condition
		if t.Condition.On == nil {
			return fmt.Errorf("JOIN must have ON condition")
		}

		// Forbid USING
		if t.Condition.Using != nil {
			return fmt.Errorf("USING construct in JOIN is forbidden, use ON instead")
		}
	case *sqlparser.ParenTableExpr:
		// Handle tables in parentheses
		for _, expr := range t.Exprs {
			if err := extractTableAliases(expr, aliases, aliasCount); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported table expression type: %T", tableExpr)
	}

	return nil
}

// Validate expressions in SELECT
func validateSelectExpressions(selectExprs sqlparser.SelectExprs, tableAliases map[string]string) error {
	for _, expr := range selectExprs {
		switch e := expr.(type) {
		case *sqlparser.StarExpr:
			return fmt.Errorf("usage of 'SELECT *' is forbidden, columns must be explicitly listed")
		case *sqlparser.AliasedExpr:
			if err := validateExpr(e.Expr, "SELECT", tableAliases); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported SELECT expression type: %T", expr)
		}
	}

	return nil
}

// Validate expressions in WHERE
func validateWhereExpression(expr sqlparser.Expr, tableAliases map[string]string) error {
	return validateExpr(expr, "WHERE", tableAliases)
}

// Unified validation of SQL expressions
func validateExpr(expr sqlparser.Expr, context string, tableAliases map[string]string) error {
	if expr == nil {
		return nil
	}

	switch e := expr.(type) {
	case *sqlparser.SQLVal:
		return validateSQLLiteral(e)
	case *sqlparser.NullVal, *sqlparser.BoolVal:
		return nil
	case *sqlparser.ColName:
		return validateColumnName(e, context, tableAliases)
	case *sqlparser.FuncExpr:
		return validateFunction(e, context, tableAliases)
	case *sqlparser.ComparisonExpr:
		if !isAllowedOperator(e.Operator) {
			return fmt.Errorf("forbidden comparison operator '%s' in %s clause", e.Operator, context)
		}
		if err := validateExpr(e.Left, context, tableAliases); err != nil {
			return err
		}
		return validateExpr(e.Right, context, tableAliases)
	case *sqlparser.AndExpr:
		if err := validateExpr(e.Left, context, tableAliases); err != nil {
			return err
		}
		return validateExpr(e.Right, context, tableAliases)
	case *sqlparser.OrExpr:
		if err := validateExpr(e.Left, context, tableAliases); err != nil {
			return err
		}
		return validateExpr(e.Right, context, tableAliases)
	case *sqlparser.NotExpr:
		return validateExpr(e.Expr, context, tableAliases)
	case *sqlparser.ParenExpr:
		return validateExpr(e.Expr, context, tableAliases)
	case *sqlparser.IsExpr:
		return validateExpr(e.Expr, context, tableAliases)
	case *sqlparser.RangeCond:
		if err := validateExpr(e.Left, context, tableAliases); err != nil {
			return err
		}
		if err := validateExpr(e.From, context, tableAliases); err != nil {
			return err
		}
		return validateExpr(e.To, context, tableAliases)
	case sqlparser.ValTuple:
		if len(e) > 100 {
			return fmt.Errorf("too many values in list (maximum 100)")
		}
		for _, val := range e {
			if err := validateExpr(val, context, tableAliases); err != nil {
				return err
			}
		}
		return nil
	case *sqlparser.Subquery:
		return fmt.Errorf("subqueries are forbidden in %s clause", context)
	case *sqlparser.CaseExpr, *sqlparser.IntervalExpr, *sqlparser.CollateExpr,
		*sqlparser.ValuesFuncExpr, *sqlparser.ConvertExpr, *sqlparser.ConvertUsingExpr,
		*sqlparser.MatchExpr, *sqlparser.GroupConcatExpr, *sqlparser.Default, *sqlparser.ExistsExpr:
		return fmt.Errorf("unsupported expression type %T in %s clause", e, context)
	default:
		return fmt.Errorf("unknown expression type %T in %s clause", e, context)
	}
}

// Validate column name
func validateColumnName(col *sqlparser.ColName, context string, tableAliases map[string]string) error {
	if col == nil {
		return fmt.Errorf("nil column name")
	}

	tableName := ""
	if !col.Qualifier.IsEmpty() {
		qualName := strings.ToLower(col.Qualifier.Name.String())

		// Check if alias exists
		if tableAliases != nil {
			if originalTable, ok := tableAliases[qualName]; ok {
				tableName = originalTable
			} else {
				return fmt.Errorf("unknown table alias '%s' in %s clause. Known aliases: %s",
					col.Qualifier.Name.String(), context, formatAliases(tableAliases))
			}
		} else {
			tableName = qualName
		}
	}

	// Check if field is allowed for the table
	colName := col.Name.String()
	if !isAllowedField(tableName, colName, tableAliases) {
		if tableName == "" {
			// If multiple tables, require qualifier
			if len(tableAliases) > 1 {
				return fmt.Errorf("ambiguous field '%s' in %s clause "+
					"(multiple tables in query, specify table alias)", colName, context)
			}
			return fmt.Errorf("forbidden field '%s' in %s clause", colName, context)
		} else {
			return fmt.Errorf("forbidden field '%s.%s' in %s clause", tableName, colName, context)
		}
	}

	return nil
}

// Validate function
func validateFunction(fn *sqlparser.FuncExpr, context string, tableAliases map[string]string) error {
	if fn == nil {
		return fmt.Errorf("nil function")
	}

	// Check if function is allowed
	funcName := strings.ToUpper(fn.Name.String())
	if _, allowed := AllowedFunctions[funcName]; !allowed {
		return fmt.Errorf("forbidden function '%s' in %s clause; only %s are allowed",
			funcName, context, allowedFunctionsList())
	}

	// Forbid DISTINCT in functions
	if fn.Distinct {
		return fmt.Errorf("DISTINCT usage in function '%s' is forbidden", funcName)
	}

	// Check function arguments
	for _, arg := range fn.Exprs {
		switch a := arg.(type) {
		case *sqlparser.StarExpr:
			// Allow only COUNT(*)
			if funcName != "COUNT" || !a.TableName.IsEmpty() {
				return fmt.Errorf("* usage is only allowed for COUNT(*)")
			}
		case *sqlparser.AliasedExpr:
			if err := validateExpr(a.Expr, context, tableAliases); err != nil {
				return fmt.Errorf("error in %s function argument: %w", funcName, err)
			}
		default:
			return fmt.Errorf("unsupported argument type %T in %s function", arg, funcName)
		}
	}

	return nil
}

// Validate SQL literal
func validateSQLLiteral(val *sqlparser.SQLVal) error {
	if val == nil {
		return nil
	}

	if val.Type == sqlparser.StrVal {
		str := string(val.Val)

		// Check suspicious sequences in strings
		suspiciousPatterns := []string{
			"--", "/*", "*/", ";", "@@", "@@version", "@@global",
			"information_schema", "sys.", "system_user(", "database(", "schema(",
			"load_file(", "sleep(", "benchmark(", "xp_", "exec(", "waitfor",
			"with ", "union", "select", "insert", "update", "delete", "drop", "alter",
		}

		lowerStr := strings.ToLower(str)
		for _, pattern := range suspiciousPatterns {
			if strings.Contains(lowerStr, pattern) {
				return fmt.Errorf("forbidden sequence '%s' in string literal", pattern)
			}
		}

		// Check forbidden characters
		for _, c := range str {
			if !unicode.IsPrint(c) || c == '\\' {
				return fmt.Errorf("forbidden characters in string literal")
			}
		}
	}

	return nil
}

// Validate reporting mode clauses
func validateReportingClauses(stmt *sqlparser.Select, tableAliases map[string]string) error {
	// Check GROUP BY
	if len(stmt.GroupBy) > 0 {
		if err := validateGroupBy(stmt.GroupBy, tableAliases); err != nil {
			return err
		}
	}

	// Check ORDER BY
	if len(stmt.OrderBy) > 0 {
		if err := validateOrderBy(stmt.OrderBy, tableAliases); err != nil {
			return err
		}
	}

	// Check HAVING
	if stmt.Having != nil {
		if err := validateHaving(stmt.Having.Expr, tableAliases); err != nil {
			return err
		}
	}

	// Check LIMIT
	if stmt.Limit != nil {
		if err := validateLimit(stmt.Limit); err != nil {
			return err
		}
	}

	return nil
}

// Check if string is a reserved SQL keyword
func isReservedKeyword(word string) bool {
	return sqlKeywords[strings.ToLower(word)]
}

// Check if operator is allowed
func isAllowedOperator(op string) bool {
	return AllowedOperators[strings.ToUpper(op)]
}

// Check if field is allowed for the table
func isAllowedField(tableName, fieldName string, tableAliases map[string]string) bool {
	// If no table specified and there's a single table, use that one
	if tableName == "" {
		if len(tableAliases) == 1 {
			// There's only one table, use it
			for _, originalTable := range tableAliases {
				tableName = originalTable
				break
			}
		} else {
			// If multiple tables and no qualifier, check all tables for the field
			for _, originalTable := range tableAliases {
				fields, ok := AllowedTables[originalTable]
				if !ok {
					continue
				}

				// Normalize field name to lowercase
				fieldNameLower := strings.ToLower(fieldName)

				// Check if field is in allowed list
				for _, f := range fields {
					if strings.ToLower(f) == fieldNameLower {
						return true
					}
				}
			}
			return false
		}
	} else {
		// Replace alias with table name if it's an alias
		if tableAliases != nil {
			if originalName, ok := tableAliases[strings.ToLower(tableName)]; ok {
				tableName = originalName
			}
		}
	}

	// Normalize table name to lowercase
	tableName = strings.ToLower(tableName)

	// Get list of allowed fields
	fields, ok := AllowedTables[tableName]
	if !ok {
		return false
	}

	// Normalize field name to lowercase
	fieldName = strings.ToLower(fieldName)

	// Check if field is in allowed list
	for _, f := range fields {
		if strings.ToLower(f) == fieldName {
			return true
		}
	}

	return false
}

// Format list of allowed functions
func allowedFunctionsList() string {
	functions := make([]string, 0, len(AllowedFunctions))
	for f := range AllowedFunctions {
		functions = append(functions, f)
	}
	return strings.Join(functions, ", ")
}

// Validate GROUP BY clause
func validateGroupBy(groupBy sqlparser.GroupBy, tableAliases map[string]string) error {
	for _, expr := range groupBy {
		switch e := expr.(type) {
		case *sqlparser.ColName:
			tableName := e.Qualifier.Name.String()
			fieldName := e.Name.String()

			if tableName != "" && !isAllowedField(tableName, fieldName, tableAliases) {
				return fmt.Errorf("invalid field %s.%s in GROUP BY", tableName, fieldName)
			}
		default:
			return fmt.Errorf("invalid expression in GROUP BY: %T", expr)
		}
	}
	return nil
}

// Validate ORDER BY clause
func validateOrderBy(orderBy sqlparser.OrderBy, tableAliases map[string]string) error {
	for _, order := range orderBy {
		switch expr := order.Expr.(type) {
		case *sqlparser.ColName:
			tableName := expr.Qualifier.Name.String()
			fieldName := expr.Name.String()

			if tableName != "" && !isAllowedField(tableName, fieldName, tableAliases) {
				return fmt.Errorf("invalid field %s.%s in ORDER BY", tableName, fieldName)
			}
		case *sqlparser.SQLVal:
			// Check position numbers (e.g., ORDER BY 1, 2)
			if expr.Type != sqlparser.IntVal {
				return fmt.Errorf("invalid literal in ORDER BY: %s", string(expr.Val))
			}
		case *sqlparser.FuncExpr:
			// Allow functions in ORDER BY
			if err := validateFunction(expr, "ORDER BY", tableAliases); err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid expression in ORDER BY: %T", order.Expr)
		}
	}
	return nil
}

// Validate HAVING clause
func validateHaving(expr sqlparser.Expr, tableAliases map[string]string) error {
	// HAVING should contain an aggregate function
	if !containsAggregateFunction(expr) {
		return fmt.Errorf("HAVING must contain an aggregate function")
	}

	// Check all fields and functions in HAVING
	err := sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
		switch n := node.(type) {
		case *sqlparser.FuncExpr:
			funcName := strings.ToUpper(n.Name.String())
			if !AllowedFunctions[funcName] {
				return false, fmt.Errorf("invalid function in HAVING: %s", funcName)
			}
		case *sqlparser.ColName:
			tableName := n.Qualifier.Name.String()
			fieldName := n.Name.String()
			if tableName != "" && !isAllowedField(tableName, fieldName, tableAliases) {
				return false, fmt.Errorf("invalid field %s.%s in HAVING", tableName, fieldName)
			}
		case *sqlparser.ComparisonExpr:
			if !isAllowedOperator(n.Operator) {
				return false, fmt.Errorf("invalid operator in HAVING: %s", n.Operator)
			}
		}
		return true, nil
	}, expr)

	return err
}

// Validate LIMIT clause
func validateLimit(limit *sqlparser.Limit) error {
	if limit == nil {
		return nil
	}

	// Check that LIMIT and OFFSET are valid
	switch limit.Rowcount.(type) {
	case *sqlparser.SQLVal:
		// This is valid
	default:
		return fmt.Errorf("LIMIT must be a numeric value, got: %T", limit.Rowcount)
	}

	if limit.Offset != nil {
		switch limit.Offset.(type) {
		case *sqlparser.SQLVal:
			// This is valid
		default:
			return fmt.Errorf("OFFSET must be a numeric value, got: %T", limit.Offset)
		}
	}

	return nil
}

// Format list of aliases
func formatAliases(aliases map[string]string) string {
	if len(aliases) == 0 {
		return "none"
	}

	aliasList := make([]string, 0, len(aliases))
	for alias, table := range aliases {
		aliasList = append(aliasList, fmt.Sprintf("%s->%s", alias, table))
	}
	return strings.Join(aliasList, ", ")
}
