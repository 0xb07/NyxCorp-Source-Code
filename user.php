<?php
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  api/user.php — NyxCorp User Data API                               ║
// ║  Vulnerability Class: SQL Injection (UNION-Based)                   ║
// ╚══════════════════════════════════════════════════════════════════════╝
//
// ── WHAT THIS ENDPOINT DOES ─────────────────────────────────────────────
//   This is an API endpoint — it returns data in JSON format, not HTML.
//   It takes a user ID from the URL and returns that user's data:
//
//     /api/user.php?id=1   → returns user 1's id, email, and role as JSON
//
//   Try it in your browser. You will see a JSON response like:
//     {"status":"ok","count":1,"data":[{"id":"1","email":"...","role":"admin"}]}
//
// ── HOW SQL INJECTION WORKS ─────────────────────────────────────────────
//   SQL is the language used to query a database. The server builds a
//   SQL query using your ?id= input:
//
//     SELECT id, email, role FROM users WHERE id = [YOUR INPUT]
//
//   Intended: ?id=1
//     SELECT id, email, role FROM users WHERE id = 1
//     → returns 1 row for user ID 1
//
//   The flaw: your input goes directly into the query string with NO
//   escaping, sanitisation, or prepared statements.
//
// ── STEP 1: CONFIRM THE VULNERABILITY ──────────────────────────────────
//   SQL uses a single quote (') to delimit text values.
//   If you add a quote that the developer did not expect, you will
//   BREAK the SQL syntax — and MySQL will return an error.
//
//   When an error occurs, this code sends the error AND the raw query
//   back to you in JSON. This tells you:
//     a) The endpoint is injectable
//     b) What the query structure looks like
//
//   How to trigger it: add a single quote to the ?id= value.
//   Watch the JSON response — look for "error":true and "detail".
//
// ── STEP 2: COUNT THE COLUMNS ───────────────────────────────────────────
//   To use UNION injection, you must know how many columns the original
//   SELECT returns. The original query selects: id, email, role = 3 columns.
//
//   SQL's ORDER BY clause lets you sort by column number.
//   If you ORDER BY a column number that does not exist, MySQL errors.
//
//   Use this to probe:
//     Try ORDER BY 1--   → works (column 1 exists)
//     Try ORDER BY 2--   → works (column 2 exists)
//     Try ORDER BY 3--   → works (column 3 exists)
//     Try ORDER BY 4--   → error! (only 3 columns)
//
//   This tells you: the query has exactly 3 columns.
//
//   Note: In SQL, -- starts a comment. Everything after -- is ignored.
//   This is how you terminate the rest of the original query cleanly.
//
// ── STEP 3: FIND WHICH COLUMN REFLECTS YOUR INPUT ──────────────────────
//   UNION SELECT appends a second SELECT to the first.
//   The result rows of both are combined and returned together.
//
//   To find which column is visible in the JSON output, inject values
//   that are easy to spot. Use a non-existent ID to suppress the real row:
//
//     ?id=-1 UNION SELECT [value1],[value2],[value3]--
//
//   Look at the JSON response — which field shows your injected values?
//   That column is where you will inject your real payloads in later steps.
//
// ── STEP 4: ENUMERATE THE DATABASE ─────────────────────────────────────
//   MySQL has a built-in database called information_schema.
//   It contains metadata about ALL databases, tables, and columns.
//
//   Useful tables in information_schema:
//     schemata   → lists all database names
//     tables     → lists all tables (and which database they belong to)
//     columns    → lists all columns in every table
//
//   Functions to know:
//     group_concat()  → joins multiple values into a single comma-separated string
//     schema_name     → the column name for database names in schemata
//     table_name      → the column name for table names in the tables table
//     table_schema    → filters by which database a table belongs to
//
//   Your goal: find what tables exist in the 'nyxcorp' database.
//   The 'users' table you already know about. Look for others.
//
// ── STEP 5: DUMP THE HIDDEN TABLE ──────────────────────────────────────
//   Once you know the table name and its columns, you can SELECT from it
//   using the same UNION technique.
//
//   Useful function: if you need to know what columns a table has, query
//   information_schema.columns filtering by table_name.
//
//   The flag is in a column called flag_value in a hidden table.
//   Retrieve it with:   UNION SELECT 1, [the flag column], 3 FROM [table]--
//
// ── BONUS: LOAD_FILE ────────────────────────────────────────────────────
//   MySQL has a function called LOAD_FILE() that reads a file from the
//   server's filesystem and returns its contents as a string.
//
//   The database user 'nyxapp' has been granted the FILE privilege,
//   which allows it to use LOAD_FILE().
//
//   This means SQL injection here can also read server files directly
//   without needing to exploit the LFI in view.php.
//
//   Which file would be most interesting to read?
//
// ════════════════════════════════════════════════════════════════════════

require_once '../db.php';

header('Content-Type: application/json');

// $id is taken directly from the URL — no casting, no escaping.
// It is placed directly into the SQL string below.
$id  = $_GET['id'] ?? '1';

// This is the vulnerable query. The value of $id is concatenated in.
// Whatever characters are in $id become part of the SQL statement.
$sql = "SELECT id, email, role FROM users WHERE id = $id";

$result = mysqli_query($conn, $sql);

if (!$result) {
    // When the query fails (e.g. due to injected syntax),
    // the raw MySQL error AND the full query are returned to the client.
    // This is what makes error-based injection possible here.
    echo json_encode([
        'error'  => true,
        'detail' => mysqli_error($conn),  // tells you WHY the query failed
        'query'  => $sql,                 // shows you the full query string
    ]);
    exit();
}

$rows = [];
while ($row = mysqli_fetch_assoc($result)) {
    $rows[] = $row;
}

// Normal response: status ok + the returned row(s)
// When you inject UNION SELECT, your injected row appears here in "data"
echo json_encode([
    'status' => 'ok',
    'count'  => count($rows),
    'data'   => $rows,
]);
