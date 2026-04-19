<?php
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  view.php — NyxCorp Document Viewer                                 ║
// ║  Vulnerability Class: Local File Inclusion (LFI) / Path Traversal   ║
// ╚══════════════════════════════════════════════════════════════════════╝
//
// ── WHAT THIS PAGE DOES ─────────────────────────────────────────────────
//   This page displays text files from the server's /docs/ directory.
//   A user provides a filename via the ?file= URL parameter, and the
//   server reads that file and displays its contents.
//
//   Intended usage:
//     /view.php?file=welcome.txt       → reads /var/www/html/docs/welcome.txt
//     /view.php?file=policy.txt        → reads /var/www/html/docs/policy.txt
//     /view.php?file=network_report.txt
//
// ── HOW THE CODE CONSTRUCTS THE FILE PATH ───────────────────────────────
//   The code takes the user's input and joins it onto a base directory:
//
//     $basedir  = "/var/www/html/docs/"
//     $file     = [whatever the user typed in ?file=]
//     $fullPath = $basedir . $file
//
//   So if you type: ?file=welcome.txt
//   It reads:       /var/www/html/docs/welcome.txt  ✓ intended
//
// ── THE FLAW ────────────────────────────────────────────────────────────
//   There is NO check to ensure the resulting path stays inside /docs/.
//   The developer forgot to call realpath() or basename() to validate.
//
//   The Linux filesystem uses "../" to mean "go up one directory level":
//
//     /var/www/html/docs/../         = /var/www/html/
//     /var/www/html/docs/../../      = /var/www/
//     /var/www/html/docs/../../../   = /var/
//     /var/www/html/docs/../../../../ = /
//
//   So if you type: ?file=../welcome.txt
//   It reads:       /var/www/html/docs/../welcome.txt
//                 = /var/www/html/welcome.txt   (escaped docs/)
//
// ── YOUR TASK ───────────────────────────────────────────────────────────
//   Goal: Read /etc/passwd from the server.
//
//   /etc/passwd is at the absolute path: /etc/passwd
//   The base directory is:               /var/www/html/docs/
//
//   You need to figure out:
//     - How many "../" sequences are needed to go from /docs/ up to /
//     - What to append after the traversal to reach /etc/passwd
//
//   Count the directory levels:
//     docs/   → one "../"  → html/
//     html/   → two "../"  → www/
//     www/    → three "../" → var/
//     var/    → four "../"  → / (root)
//   Then: / + etc/passwd = /etc/passwd
//
//   Hint: how many "../" did you need?
//
// ── DISCOVERY CHAIN ─────────────────────────────────────────────────────
//   Another way to confirm the server path is to look at what the
//   error message reveals when a file is NOT found.
//   The error message shows the FULL path it tried to open.
//   This tells you exactly what the base directory is.
//
//   Try: ?file=doesnotexist.txt
//   Read the error. What path does it show?
//
// ── BONUS ───────────────────────────────────────────────────────────────
//   Once you can read arbitrary files, try:
//     ?file=../db.php        → what credentials are in here?
//     ?file=../index.php     → can you read the login page source?
//
// ════════════════════════════════════════════════════════════════════════

session_start();

$file    = $_GET['file'] ?? 'welcome.txt';
$basedir = __DIR__ . '/docs/';
$content = "";
$error   = "";

// The base directory is the /docs/ folder inside the web root.
// __DIR__ gives the directory where this PHP file lives (the web root).
// So $basedir = "/var/www/html/docs/"

// ── THE VULNERABLE LINE ─────────────────────────────────────────────────
// This line simply joins the base path and the user input with no checks.
// If $file contains "../", PHP will follow the path up the directory tree.
// There is no call to realpath() which would resolve and validate the path.
// There is no call to basename() which would strip directory components.
$fullPath = $basedir . $file;

// file_exists() and is_file() just check if the path resolves to a file.
// They do NOT check if the path is still inside /docs/.
if (file_exists($fullPath) && is_file($fullPath)) {
    // file_get_contents() reads the entire file and returns it as a string.
    // If $fullPath points to /etc/passwd, it reads /etc/passwd.
    $content = file_get_contents($fullPath);
} else {
    // When the file is not found, the full server path is shown.
    // This information disclosure helps confirm the directory depth.
    $error = "File not found: " . htmlspecialchars($fullPath);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NyxCorp — Document Viewer</title>
<style>
  *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0d1117; font-family:'Segoe UI',Arial,sans-serif; color:#f0f4f8; }
  .topbar { background:#161b22; border-bottom:1px solid #21262d; padding:0 32px; height:56px;
    display:flex; align-items:center; justify-content:space-between; }
  .brand { font-size:18px; font-weight:800; letter-spacing:2px; }
  .brand span { color:#ff4757; }
  .back { color:#8b949e; text-decoration:none; font-size:13px; }
  .back:hover { color:#ffd166; }
  .container { max-width:900px; margin:40px auto; padding:0 24px; }
  h1 { font-size:22px; margin-bottom:6px; }
  .sub { color:#8b949e; font-size:13px; margin-bottom:24px; }
  .nav-form { display:flex; gap:10px; margin-bottom:20px; }
  input[type="text"] { flex:1; padding:9px 14px; background:#161b22; border:1px solid #30363d;
    border-radius:3px; color:#f0f4f8; font-family:Consolas,monospace; font-size:13px; outline:none; }
  input[type="text"]:focus { border-color:#ffd166; }
  .btn-view { padding:9px 22px; background:#ffd166; border:none; border-radius:3px;
    color:#0d1117; font-weight:700; font-size:13px; cursor:pointer; }
  .viewer-head { background:#161b22; border:1px solid #21262d; border-bottom:none;
    border-radius:4px 4px 0 0; padding:12px 20px; display:flex; align-items:center; justify-content:space-between; }
  .filepath { font-family:Consolas,monospace; font-size:12px; color:#8b949e; }
  .filepath span { color:#ffd166; }
  .viewer-body { background:#020409; border:1px solid #21262d; border-radius:0 0 4px 4px;
    padding:22px; min-height:260px; }
  pre { white-space:pre-wrap; word-break:break-all; font-family:Consolas,monospace;
    font-size:13px; color:#39d353; line-height:1.75; }
  .err { color:#ff4757; font-family:Consolas,monospace; font-size:13px; }
  .docs-list { margin-top:22px; background:#161b22; border:1px solid #21262d; border-radius:4px; padding:20px; }
  .docs-list h3 { font-size:12px; color:#8b949e; text-transform:uppercase; letter-spacing:1px;
    margin-bottom:12px; font-family:Consolas,monospace; }
  .doc-link { display:block; color:#ffd166; text-decoration:none; font-family:Consolas,monospace;
    font-size:13px; padding:5px 0; border-bottom:1px solid #21262d; }
  .doc-link:hover { color:#ffe599; }
  .doc-link:last-child { border-bottom:none; }
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">NYX<span>CORP</span></div>
  <a class="back" href="dashboard.php">← Dashboard</a>
</div>
<div class="container">
  <h1>📄 Document Viewer</h1>
  <div class="sub">View internal documents from the NyxCorp document repository.</div>
  <form class="nav-form" method="GET">
    <input type="text" name="file" value="<?= htmlspecialchars($file) ?>" placeholder="filename.txt">
    <button type="submit" class="btn-view">VIEW</button>
  </form>
  <div class="viewer-head">
    <div class="filepath">docs/ → <span><?= htmlspecialchars($file) ?></span></div>
  </div>
  <div class="viewer-body">
    <?php if ($error): ?>
      <div class="err"><?= $error ?></div>
    <?php else: ?>
      <pre><?= htmlspecialchars($content) ?></pre>
    <?php endif; ?>
  </div>
  <div class="docs-list">
    <h3>Available Documents</h3>
    <a class="doc-link" href="view.php?file=welcome.txt">welcome.txt</a>
    <a class="doc-link" href="view.php?file=policy.txt">policy.txt</a>
    <a class="doc-link" href="view.php?file=network_report.txt">network_report.txt</a>
  </div>
</div>
</body>
</html>
