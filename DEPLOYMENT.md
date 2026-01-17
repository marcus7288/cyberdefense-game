# Quick Deployment Guide

## Step-by-Step: GitHub + Netlify

### 1. Initialize Git Repository
```bash
cd cyberdefense-game
git init
git add .
git commit -m "Initial commit: CyberDefense OWASP game"
```

### 2. Create GitHub Repository
- Go to https://github.com/new
- Repository name: `cyberdefense-game` (or your choice)
- Choose Public or Private
- **DO NOT** initialize with README, .gitignore, or license (we already have these)
- Click "Create repository"

### 3. Push to GitHub
Copy the commands from GitHub and run them:
```bash
git remote add origin https://github.com/YOUR_USERNAME/cyberdefense-game.git
git branch -M main
git push -u origin main
```

### 4. Deploy to Netlify

**Option A: Netlify UI (Easiest)**
1. Go to https://app.netlify.com
2. Click "Add new site" → "Import an existing project"
3. Click "Deploy with GitHub"
4. Authorize Netlify to access your GitHub
5. Select `cyberdefense-game` repository
6. Netlify auto-detects settings from `netlify.toml`:
   - Build command: `npm run build`
   - Publish directory: `dist`
7. Click "Deploy site"
8. Wait 2-3 minutes for deployment
9. Your site is live! 🎉

**Option B: Netlify CLI**
```bash
# Install Netlify CLI globally (one time)
npm install -g netlify-cli

# Login to Netlify
netlify login

# Deploy
netlify deploy --prod
```

### 5. Custom Domain (Optional)
In Netlify dashboard:
- Go to Site settings → Domain management
- Click "Add custom domain"
- Follow DNS configuration instructions

### 6. Configure Site Name
In Netlify dashboard:
- Go to Site settings → General → Site details
- Click "Change site name"
- Choose: `cyberdefense-game` or your preferred name
- Your URL: `https://cyberdefense-game.netlify.app`

## Continuous Deployment

Once connected to GitHub, every time you push changes:
```bash
git add .
git commit -m "Update: description of changes"
git push
```

Netlify will automatically rebuild and deploy! 🚀

## Testing Before Deployment

```bash
# Install dependencies
npm install

# Test locally
npm run dev
# Opens at http://localhost:5173

# Build and preview production version
npm run build
npm run preview
```

## Troubleshooting

### Build Fails on Netlify
- Check that Node version is 18+ in `netlify.toml`
- Verify all dependencies are in `package.json`
- Check build logs in Netlify dashboard

### Game Doesn't Load
- Clear browser cache
- Check browser console for errors (F12)
- Verify `index.html` is being served

### GitHub Push Fails
```bash
# If you need to use a personal access token instead of password:
git remote set-url origin https://YOUR_TOKEN@github.com/YOUR_USERNAME/cyberdefense-game.git
```

## Environment Variables (if needed later)
In Netlify dashboard:
- Go to Site settings → Build & deploy → Environment
- Add variables as key-value pairs

## Sharing Your Game

After deployment, share the Netlify URL with your students/colleagues:
- `https://your-site-name.netlify.app`
- Works on any device with a web browser
- No installation required
- Perfect for classroom or training exercises

---

**Need Help?**
- Netlify Docs: https://docs.netlify.com
- GitHub Docs: https://docs.github.com
- This project's README.md has more detailed information
