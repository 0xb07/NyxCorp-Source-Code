<?php
// ╔══════════════════════════════════════════════════════════════════════╗
// ║  profile.php — NyxCorp Staff Directory                              ║
// ║  Vulnerability Class: Insecure Direct Object Reference (IDOR)       ║
// ╚══════════════════════════════════════════════════════════════════════╝
//
// ── WHAT THIS PAGE DOES ─────────────────────────────────────────────────
//   This page shows a staff member's profile from the database.
//   The user requests a profile by passing an ID number in the URL:
//
//     /profile.php?id=1    → shows profile for user with database ID 1
//     /profile.php?id=2    → shows profile for user with database ID 2
//
// ── WHAT IDOR MEANS ─────────────────────────────────────────────────────
//   IDOR stands for Insecure Direct Object Reference.
//
//   "Direct Object Reference" means the application directly exposes
//   a database identifier (like id=1) to the user in the URL.
//
//   "Insecure" means there is NO check to verify that the person
//   requesting id=5 is actually authorised to see id=5.
//
//   A proper application would check:
//     "Is the currently logged-in user allowed to view profile ID 5?"
//   This code does NOT perform that check.
//
// ── THE FLAW ────────────────────────────────────────────────────────────
//   The code takes the ?id= value, converts it to an integer (safe from
//   SQL injection), and fetches the matching row from the database.
//   It then displays ALL data from that row — including private fields.
//
//   There is no session check like:
//     if ($_SESSION['user_id'] !== $id) { die("Forbidden"); }
//
//   Anyone who can load this page can view any profile.
//
// ── YOUR TASK ───────────────────────────────────────────────────────────
//   The database has 10 user accounts (IDs 1 through 10).
//   The dashboard shows no links to this page — you found it via fuzzing.
//   This page also has no navigation buttons between profiles.
//
//   Your job:
//     1. Change the ?id= number in the URL manually.
//     2. Look at each profile from ID 1 to ID 10.
//     3. Some profiles have a "Private Notes" field.
//     4. Find the profile where Private Notes contains something valuable.
//
//   Think: which user ID contains the flag?
//
// ── WHY intval() IS USED ────────────────────────────────────────────────
//   intval() converts the input to a plain integer before it touches SQL.
//   This PREVENTS SQL injection on this endpoint.
//
//   Example:
//     Input: ?id=1 UNION SELECT ...
//     intval() converts this to: 1
//     Query becomes: WHERE id = 1   (injection stripped)
//
//   The vulnerability here is NOT SQL injection.
//   The vulnerability is the missing authorisation check.
//
// ── NOTE ON THE NOTES FIELD ─────────────────────────────────────────────
//   The "Private Notes" section is only displayed when notes is not empty:
//     if (!empty($user['notes']))
//
//   Most users have no notes. Some do.
//   Enumerate every ID and look at each profile carefully.
//
// ════════════════════════════════════════════════════════════════════════

session_start();
require_once 'db.php';

// intval() safely converts user input to an integer.
// Prevents SQL injection — but does NOT prevent IDOR.
$id     = intval($_GET['id'] ?? 1);

// The query fetches the full user row for whatever ID was requested.
// No check is made to verify the logged-in user is allowed to see this ID.
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
$user   = mysqli_fetch_assoc($result);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NyxCorp — Staff Directory</title>
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
  .profile-card { background:#161b22; border:1px solid #21262d; border-radius:4px; padding:32px; }
  .profile-head { display:flex; align-items:center; gap:20px; margin-bottom:28px;
    padding-bottom:20px; border-bottom:1px solid #21262d; }
  .avatar { width:62px; height:62px; border-radius:50%; background:#30363d;
    display:flex; align-items:center; justify-content:center; font-size:26px; flex-shrink:0; }
  .profile-name { font-size:20px; font-weight:600; }
  .role-badge { font-size:11px; font-family:Consolas,monospace; margin-top:5px;
    padding:2px 10px; border-radius:2px; display:inline-block; font-weight:700; }
  .role-admin { background:#7a1f2b; color:#ff4757; }
  .role-staff { background:#1c2433; color:#8b949e; }
  .field-grid { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:22px; }
  .field-label { font-size:11px; color:#8b949e; text-transform:uppercase; letter-spacing:.5px;
    margin-bottom:6px; font-family:Consolas,monospace; }
  .field-val { font-size:14px; color:#f0f4f8; background:#0d1117; border:1px solid #21262d;
    border-radius:3px; padding:9px 14px; font-family:Consolas,monospace; }
  .notes-label { font-size:11px; color:#8b949e; text-transform:uppercase; letter-spacing:.5px;
    margin-bottom:8px; font-family:Consolas,monospace; }
  .notes-box { background:#0d1117; border:1px solid #21262d; border-left:3px solid #ffd166;
    border-radius:3px; padding:14px 18px; font-family:Consolas,monospace;
    font-size:13px; color:#ffd166; line-height:1.75; }
  .not-found { color:#ff4757; font-family:Consolas,monospace; font-size:14px;
    padding:20px; background:#7a1f2b; border-radius:4px; }
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">NYX<span>CORP</span></div>
  <a class="back" href="dashboard.php">← Dashboard</a>
</div>
<div class="container">
  <h1>👤 Staff Directory</h1>
  <div class="sub">Viewing profile
    <code style="color:#ffd166;font-family:Consolas">?id=<?= $id ?></code>
  </div>
  <?php if ($user): ?>
  <div class="profile-card">
    <div class="profile-head">
      <div class="avatar">👤</div>
      <div>
        <div class="profile-name"><?= htmlspecialchars($user['fullname']) ?></div>
        <span class="role-badge role-<?= htmlspecialchars($user['role']) ?>">
          <?= strtoupper(htmlspecialchars($user['role'])) ?>
        </span>
      </div>
    </div>
    <div class="field-grid">
      <div>
        <div class="field-label">Username</div>
        <div class="field-val"><?= htmlspecialchars($user['username']) ?></div>
      </div>
      <div>
        <div class="field-label">Email</div>
        <div class="field-val"><?= htmlspecialchars($user['email']) ?></div>
      </div>
      <div>
        <div class="field-label">Department</div>
        <div class="field-val"><?= htmlspecialchars($user['department'] ?? '—') ?></div>
      </div>
      <div>
        <div class="field-label">User ID</div>
        <div class="field-val">#<?= htmlspecialchars($user['id']) ?></div>
      </div>
    </div>
    <?php if (!empty($user['notes'])): ?>
    <div class="notes-label">Private Notes</div>
    <div class="notes-box"><?= htmlspecialchars($user['notes']) ?></div>
    <?php endif; ?>
  </div>
  <?php else: ?>
  <div class="not-found">⚠ User ID <?= $id ?> not found.</div>
  <?php endif; ?>
</div>
</body>
</html>
