NyxCorp Source Code
===================

IMPORTANT NOTICE FOR DEVELOPERS
---------------------------------

This repository contains the NyxCorp source code that has NOT been patched yet.
Several vulnerabilities exist within this codebase, some of which are critical in severity.

Before deploying or hosting any part of this code on the web or any public-facing
environment, you MUST:

  1. Download the zip file of this repository.
  2. Review ALL source files thoroughly.
  3. Identify and patch every known vulnerability (see list below).
  4. Test the patched code in a secure, isolated environment.
  5. Only after confirming all patches are applied and verified should the code
     be hosted or deployed.

DO NOT host the unpatched source code on any public server.

Known Vulnerability Categories (to be patched before deployment):
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Insecure Direct Object References (IDOR)
  - Authentication and Session Management flaws
  - Sensitive Data Exposure
  - Security Misconfiguration
  - Use of components with known vulnerabilities

Access: Developer use only. Do not distribute externally.
