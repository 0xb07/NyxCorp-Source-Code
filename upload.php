<?php
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  upload.php — NyxCorp File Manager                                  ║
// ║  Vulnerability Class: Unrestricted File Upload                       ║
// ╚══════════════════════════════════════════════════════════════════════╝
//
// ── WHAT THIS PAGE DOES ─────────────────────────────────────────────────
//   This page allows users to upload a file from their computer to the
//   server. The uploaded file is saved into the /uploads/ directory and
//   becomes accessible by its direct URL.
//
//   Key fact: the /uploads/ directory is configured to EXECUTE PHP files.
//   This means if a PHP file lands there, the server will run it as code.
//
// ── HOW THE VALIDATION WORKS ────────────────────────────────────────────
//   The developer attempted to restrict uploads to .jpg files only.
//   Look carefully at how the check is implemented below.
//
//   The filename is split using the dot (.) character as a separator.
//   Example:
//     Filename: photo.jpg
//     explode('.', 'photo.jpg') → ['photo', 'jpg']
//     Index 0 = 'photo'
//     Index 1 = 'jpg'  ← only this index is checked
//
//   The check passes if index [1] equals 'jpg'.
//
// ── THE FLAW ────────────────────────────────────────────────────────────
//   What happens if the filename has MORE than one dot?
//   The developer only checks [1] — the second segment — not the LAST one.
//
//   Think about this filename:
//     shell.jpg.php
//     explode('.', 'shell.jpg.php') → ['shell', 'jpg', 'php']
//     Index 1 = 'jpg'  ← check passes
//     Index 2 = 'php'  ← never checked
//
//   The file passes the check, gets saved to /uploads/shell.jpg.php
//   Apache sees the .php extension and EXECUTES it.
//
// ── YOUR TASK ───────────────────────────────────────────────────────────
//   1. Create a file that will be EXECUTED by the server when visited.
//   2. Name it so that the validation check passes.
//   3. Upload it using this form.
//   4. Visit /uploads/[your filename] and trigger it.
//   5. Goal: read /etc/passwd from the server.
//
//   Ask yourself:
//     - What file type does a web server execute server-side?
//     - What PHP function runs a system/shell command and returns output?
//     - How can you pass a command through a URL parameter?
//     - What command reads a file on Linux?
//
// ── HINT ON PHP EXECUTION ───────────────────────────────────────────────
//   A PHP file that runs a system command looks like this pattern:
//
//     <?php [function]($_GET["[parameter_name]"]); ?>
//
//   You need to fill in:
//     [function]        → a PHP function that executes OS commands
//     [parameter_name]  → whatever name you want for the URL parameter
//
//   PHP functions that execute system commands: system(), shell_exec(),
//   exec(), passthru(). Look up what each one returns.
//
// ════════════════════════════════════════════════════════════════════════

session_start();

$msg     = "";
$msgType = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file     = $_FILES['file'];
    $origName = basename($file['name']);   // gets just the filename, strips any path
    $tmpPath  = $file['tmp_name'];         // temp location on server before moving

    // ── VALIDATION BLOCK — read this carefully ───────────────────────────
    //
    // explode(separator, string) splits a string by the separator character
    // and returns an array.
    //
    // Example: explode('.', 'report.pdf') → ['report', 'pdf']
    // Example: explode('.', 'a.b.c')      → ['a', 'b', 'c']
    //
    $nameParts = explode('.', $origName);

    // The check: does the element at index [1] equal 'jpg'?
    // This is checking the SECOND segment, not the LAST segment.
    // What happens when there are three segments?
    if (isset($nameParts[1]) && $nameParts[1] === 'jpg') {

        // If check passes: move the file to /uploads/ keeping the ORIGINAL name
        // The original name is used — whatever extension is at the end stays.
        $dest = __DIR__ . '/uploads/' . $origName;

        if (move_uploaded_file($tmpPath, $dest)) {
            $url     = 'uploads/' . rawurlencode($origName);
            $msg     = "Uploaded: <strong>" . htmlspecialchars($origName) . "</strong> &rarr;"
                     . " <a href='" . $url . "' target='_blank' style='color:#1db9a4'>/uploads/"
                     . htmlspecialchars($origName) . " →</a>";
            $msgType = "success";
        } else {
            $msg     = "Upload failed. Check directory permissions (/uploads must be 777).";
            $msgType = "error";
        }
    } else {
        $msg     = "Invalid file type. Only .jpg files are allowed.";
        $msgType = "error";
    }
}

// List existing files in /uploads/
$uploaded = array_filter(
    glob(__DIR__ . '/uploads/*') ?: [],
    fn($f) => is_file($f) && basename($f) !== '.gitkeep'
);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NyxCorp — File Manager</title>
<style>
  *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0d1117; font-family:'Segoe UI',Arial,sans-serif; color:#f0f4f8; }
  .topbar { background:#161b22; border-bottom:1px solid #21262d; padding:0 32px; height:56px;
    display:flex; align-items:center; justify-content:space-between; }
  .brand { font-size:18px; font-weight:800; letter-spacing:2px; }
  .brand span { color:#ff4757; }
  .back { color:#8b949e; text-decoration:none; font-size:13px; }
  .back:hover { color:#ff4757; }
  .container { max-width:840px; margin:40px auto; padding:0 24px; }
  h1 { font-size:22px; margin-bottom:6px; }
  .sub { color:#8b949e; font-size:13px; margin-bottom:24px; }
  .notice { background:#0a1a2e; border:1px solid #1a2b4a; border-radius:3px;
    padding:12px 16px; font-size:12px; color:#8b949e; margin-bottom:20px; }
  .notice strong { color:#58a6ff; }
  .upload-card { background:#161b22; border:1px solid #21262d; border-radius:4px; padding:32px; margin-bottom:24px; }
  .drop-zone { border:2px dashed #30363d; border-radius:4px; padding:42px 24px;
    text-align:center; margin-bottom:20px; cursor:pointer; transition:border-color .2s; }
  .drop-zone:hover { border-color:#ff4757; }
  .drop-icon { font-size:36px; margin-bottom:12px; }
  .drop-label { font-size:14px; color:#8b949e; }
  .drop-label strong { color:#f0f4f8; }
  #sel-name { font-family:Consolas,monospace; font-size:13px; color:#ffd166; margin-top:8px; min-height:18px; }
  input[type="file"] { display:none; }
  .browse { display:inline-block; margin-top:14px; padding:8px 20px;
    background:#21262d; border:1px solid #30363d; border-radius:3px;
    color:#f0f4f8; font-size:13px; cursor:pointer; }
  .btn-upload { width:100%; padding:13px; background:#ff4757; border:none; border-radius:3px;
    color:#fff; font-size:14px; font-weight:700; cursor:pointer; transition:background .2s; }
  .btn-upload:hover { background:#e03546; }
  .msg { border-radius:3px; padding:12px 16px; font-size:13px; margin-bottom:20px; }
  .success { background:#0a2e1a; border:1px solid #1db9a4; color:#1db9a4; }
  .error   { background:#7a1f2b; border:1px solid #ff4757; color:#ffb3b9; }
  .files-card { background:#161b22; border:1px solid #21262d; border-radius:4px; }
  .files-head { padding:14px 24px; border-bottom:1px solid #21262d;
    display:flex; align-items:center; justify-content:space-between; }
  .files-head h3 { font-size:12px; color:#8b949e; text-transform:uppercase; letter-spacing:1px; font-family:Consolas,monospace; }
  .count { font-size:11px; color:#30363d; font-family:Consolas,monospace; }
  .file-row { display:flex; align-items:center; justify-content:space-between;
    padding:12px 24px; border-bottom:1px solid #21262d; transition:background .15s; }
  .file-row:last-child { border-bottom:none; }
  .file-row:hover { background:#1c2433; }
  .fname { font-family:Consolas,monospace; font-size:13px; color:#f0f4f8; }
  .fname.php { color:#ff4757; font-weight:700; }
  .fsize { font-size:12px; color:#8b949e; font-family:Consolas,monospace; }
  .f-link { color:#1db9a4; text-decoration:none; font-size:12px; font-family:Consolas,monospace; }
  .f-link:hover { color:#25d3bc; }
  .empty { padding:28px 24px; text-align:center; color:#8b949e; font-size:13px; }
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">NYX<span>CORP</span></div>
  <a class="back" href="dashboard.php">← Dashboard</a>
</div>
<div class="container">
  <h1>📁 File Manager</h1>
  <div class="sub">Upload documents to the NyxCorp document repository.</div>
  <div class="notice">
    <strong>Note:</strong> All uploaded files are stored at
    <code style="color:#ffd166">/uploads/</code> and are accessible by direct URL.
  </div>
  <?php if ($msg): ?>
  <div class="msg <?= $msgType ?>"><?= $msg ?></div>
  <?php endif; ?>
  <div class="upload-card">
    <form method="POST" enctype="multipart/form-data" id="upForm">
      <div class="drop-zone" onclick="document.getElementById('fileInput').click()">
        <div class="drop-icon">📤</div>
        <div class="drop-label"><strong>Click to choose a file</strong> or drag and drop</div>
        <label class="browse">Browse Files</label>
        <input type="file" name="file" id="fileInput"
               onchange="document.getElementById('sel-name').textContent = this.files[0]?.name ?? ''">
        <div id="sel-name"></div>
      </div>
      <button type="submit" class="btn-upload">UPLOAD →</button>
    </form>
  </div>
  <div class="files-card">
    <div class="files-head">
      <h3>Uploaded Files</h3>
      <span class="count"><?= count($uploaded) ?> file(s)</span>
    </div>
    <?php if (empty($uploaded)): ?>
      <div class="empty">No files uploaded yet.</div>
    <?php else: ?>
      <?php foreach ($uploaded as $fp):
        $fn  = basename($fp);
        $ext = strtolower(pathinfo($fn, PATHINFO_EXTENSION));
        $sz  = filesize($fp);
        $szs = $sz < 1024 ? $sz . ' B' : round($sz/1024, 1) . ' KB';
      ?>
      <div class="file-row">
        <span class="fname <?= $ext === 'php' ? 'php' : '' ?>"><?= htmlspecialchars($fn) ?></span>
        <span class="fsize"><?= $szs ?></span>
        <a class="f-link" href="uploads/<?= rawurlencode($fn) ?>" target="_blank">Open →</a>
      </div>
      <?php endforeach; ?>
    <?php endif; ?>
  </div>
</div>
</body>
</html>
