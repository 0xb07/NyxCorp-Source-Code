<?php
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  ping.php — NyxCorp Network Diagnostics                             ║
// ║  Vulnerability Class: OS Command Injection (Remote Code Execution)  ║
// ╚══════════════════════════════════════════════════════════════════════╝
//
// ── WHAT THIS PAGE DOES ─────────────────────────────────────────────────
//   This page provides a network diagnostic tool. You type a hostname or
//   IP address, and the server runs the Linux "ping" command against it
//   and shows you the output.
//
//   Intended usage:
//     ?host=8.8.8.8       → server runs: ping -c 2 8.8.8.8
//     ?host=127.0.0.1     → server runs: ping -c 2 127.0.0.1
//
// ── HOW THE COMMAND IS BUILT ────────────────────────────────────────────
//   Look at this line in the code:
//
//     shell_exec('ping -c 2 ' . $host . ' 2>&1')
//
//   This builds a shell command by joining strings together:
//     - 'ping -c 2 '   (fixed, written by the developer)
//     - $host          (your input from the URL)
//     - ' 2>&1'        (fixed, redirects errors to output)
//
//   If $host = "8.8.8.8":
//     Command = ping -c 2 8.8.8.8 2>&1    ← intended
//
// ── THE FLAW ────────────────────────────────────────────────────────────
//   The Linux shell allows multiple commands to be chained together
//   on one line using special separator characters.
//
//   Common separators and what they do:
//
//     ;   run the next command regardless of whether the first succeeded
//     &&  run the next command ONLY if the first succeeded
//     ||  run the next command ONLY if the first failed
//     |   pipe: send output of first command as input to second
//
//   If the user types a separator followed by another command,
//   the shell runs BOTH — the intended ping AND the injected command.
//
//   The developer did NOT sanitise $host before passing it to shell_exec().
//   There is no check for special characters. Whatever you type goes
//   directly into the shell command.
//
// ── YOUR TASK ───────────────────────────────────────────────────────────
//   Goal: Read /etc/passwd from the server.
//
//   Think about:
//     1. Which separator character would you use to add a second command?
//     2. What Linux command reads the contents of a file?
//     3. What file path contains the user accounts on a Linux system?
//
//   The structure of your ?host= value should be:
//
//     [valid IP][separator][linux command] [target file]
//
//   If the injection works, you will see the ping output first,
//   then the output of your injected command below it.
//
// ── WHAT shell_exec() DOES ──────────────────────────────────────────────
//   shell_exec() runs a command in the system shell (bash/sh) and
//   returns all output as a string. It is like opening a terminal
//   and typing the command.
//
//   The shell is running as the web server user (www-data).
//   www-data can read /etc/passwd (it is world-readable on Linux).
//
// ── WHY IT MATTERS ──────────────────────────────────────────────────────
//   This vulnerability gives the attacker the same level of access
//   as the web server process. From here, a real attacker could:
//     - Read sensitive configuration files
//     - List files and directories
//     - Establish a persistent connection back to their machine
//
// ════════════════════════════════════════════════════════════════════════

session_start();

$host   = $_GET['host'] ?? '';
$output = "";

if ($host !== '') {

    // ── THE VULNERABLE LINE ─────────────────────────────────────────────
    // $host is appended directly to the command string with no checks.
    // Any shell separator characters in $host are passed to the shell.
    // shell_exec() runs the resulting string in a bash shell.
    $output = shell_exec('ping -c 2 ' . $host . ' 2>&1');

    if ($output === null) {
        $output = "[Error: shell_exec returned null — check php.ini disable_functions]";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NyxCorp — Network Diagnostics</title>
<style>
  *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0d1117; font-family:'Segoe UI',Arial,sans-serif; color:#f0f4f8; }
  .topbar { background:#161b22; border-bottom:1px solid #21262d; padding:0 32px; height:56px;
    display:flex; align-items:center; justify-content:space-between; }
  .brand { font-size:18px; font-weight:800; letter-spacing:2px; }
  .brand span { color:#1db9a4; }
  .back { color:#8b949e; text-decoration:none; font-size:13px; }
  .back:hover { color:#1db9a4; }
  .container { max-width:840px; margin:40px auto; padding:0 24px; }
  h1 { font-size:22px; margin-bottom:6px; }
  .sub { color:#8b949e; font-size:13px; margin-bottom:24px; }
  .info { background:#0a2e2b; border:1px solid #1db9a4; border-radius:3px;
    padding:12px 16px; font-size:12px; color:#8b949e; margin-bottom:20px; }
  .info strong { color:#1db9a4; }
  .diag-card { background:#161b22; border:1px solid #21262d; border-radius:4px; padding:28px; margin-bottom:22px; }
  .diag-card h3 { font-size:12px; color:#1db9a4; text-transform:uppercase; letter-spacing:1px;
    margin-bottom:16px; font-family:Consolas,monospace; }
  .input-row { display:flex; gap:10px; margin-bottom:12px; }
  input[type="text"] { flex:1; padding:10px 14px; background:#0d1117; border:1px solid #30363d;
    border-radius:3px; color:#f0f4f8; font-family:Consolas,monospace; font-size:13px; outline:none; }
  input[type="text"]:focus { border-color:#1db9a4; }
  .btn-run { padding:10px 24px; background:#1db9a4; border:none; border-radius:3px;
    color:#0d1117; font-weight:700; font-size:13px; cursor:pointer; }
  .btn-run:hover { background:#19a090; }
  .hint { font-size:11px; color:#30363d; font-family:Consolas,monospace; margin-top:6px; }
  .presets { display:flex; gap:8px; flex-wrap:wrap; margin-top:12px; }
  .preset { padding:5px 12px; background:#1c2433; border:1px solid #30363d; border-radius:2px;
    color:#8b949e; font-family:Consolas,monospace; font-size:11px; text-decoration:none; }
  .preset:hover { border-color:#1db9a4; color:#1db9a4; }
  .terminal { background:#020409; border:1px solid #30363d; border-radius:3px; overflow:hidden; }
  .term-bar { background:#161b22; padding:8px 14px; display:flex; align-items:center; gap:6px; }
  .dot { width:10px; height:10px; border-radius:50%; }
  .term-cmd { font-size:11px; color:#8b949e; font-family:Consolas,monospace; margin-left:8px; }
  .term-out { padding:18px 20px; }
  pre { white-space:pre-wrap; word-break:break-all; font-family:Consolas,monospace;
    font-size:12.5px; color:#39d353; line-height:1.75; }
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">NYX<span>CORP</span></div>
  <a class="back" href="dashboard.php">← Dashboard</a>
</div>
<div class="container">
  <h1>🌐 Network Diagnostics</h1>
  <div class="sub">Run connectivity checks against internal and external hosts.</div>
  <div class="info">
    <strong>Usage:</strong> Enter a hostname or IP address to run a connectivity check.
  </div>
  <div class="diag-card">
    <h3>Ping Test</h3>
    <form method="GET">
      <div class="input-row">
        <input type="text" name="host" value="<?= htmlspecialchars($host) ?>"
               placeholder="hostname or IP  (e.g. 8.8.8.8)">
        <button type="submit" class="btn-run">RUN</button>
      </div>
    </form>
    <div class="hint"># Executes: ping -c 2 &lt;host&gt;</div>
    <div class="presets">
      <a class="preset" href="ping.php?host=127.0.0.1">127.0.0.1</a>
      <a class="preset" href="ping.php?host=8.8.8.8">8.8.8.8</a>
      <a class="preset" href="ping.php?host=nyxcorp.internal">nyxcorp.internal</a>
    </div>
  </div>
  <?php if ($output !== ''): ?>
  <div class="terminal">
    <div class="term-bar">
      <div class="dot" style="background:#ff5f56;"></div>
      <div class="dot" style="background:#ffbd2e;"></div>
      <div class="dot" style="background:#27c93f;"></div>
      <div class="term-cmd">$ ping -c 2 <?= htmlspecialchars($host) ?></div>
    </div>
    <div class="term-out">
      <pre><?= htmlspecialchars($output) ?></pre>
    </div>
  </div>
  <?php endif; ?>
</div>
</body>
</html>
