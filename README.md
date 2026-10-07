# loginapp

A small registration and login system built with Node.js, with no extra packages.

## Features
- Registration with input checks on the browser and on the server
- Passwords stored as salted scrypt hashes, never as plain text
- Login with the same error message for every failure
- Session cookies (HttpOnly, SameSite=Strict)
- A protected dashboard page and logout
- Lockout for one minute after 5 failed attempts

## Run it
1. Install Node.js
2. Run: node server.js
3. Open http://localhost:3000

## Limits
This is a learning project. It has no HTTPS, uses a JSON file instead of a database, and keeps sessions in memory. Do not use it to store real passwords.
