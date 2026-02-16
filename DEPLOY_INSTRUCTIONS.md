# How to Deploy NullRoute (Cloud Backend)

You asked if you can run the backend **without** the batch file.
**Answer:** Yes, but only if you host it on a Cloud Server.

If you run it on your own PC, you **must** use `run_server.bat` because HTML cannot start programs.

## Option 1: Run Locally (Your PC)
1. Double-click `run_server.bat`.
2. That's it.

## Option 2: Run in the Cloud (Automatic Backend)
If you upload this project to a Node.js host, the server will run automatically 24/7.

### Recommended Hosts (Free Tiers):
1. **Render.com** (Best option)
   - Create account -> "New Web Service"
   - Connect your GitHub repo
   - Build Command: `npm install`
   - Start Command: `npm start`
   - **Result:** You get a URL (e.g., `https://nullroute.onrender.com`). You can visit it from any device (Phone, PC) and the backend works automatically.

2. **Replit.com**
   - Create new Repl -> Import from GitHub
   - Click "Run"
   - **Result:** Works instantly.

3. **Glitch.com**
   - New Project -> Import from GitHub
   - **Result:** Works instantly.

### How I made it "Cloud Ready":
I updated `index.html` to automatically detect if it's running on a server.
- **Local:** It tries `localhost:3000` (requires batch file).
- **Cloud:** It connects to itself (requires NO configuration).
