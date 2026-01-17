# CyberDefense Game - Project Structure

```
cyberdefense-game/
├── src/
│   ├── App.jsx              # Main game component with all logic
│   ├── main.jsx             # React entry point
│   └── index.css            # Global styles with Tailwind
├── index.html               # HTML entry point
├── package.json             # Dependencies and scripts
├── vite.config.js           # Vite build configuration
├── tailwind.config.js       # Tailwind CSS configuration
├── postcss.config.js        # PostCSS configuration
├── netlify.toml             # Netlify deployment settings
├── .gitignore               # Git ignore rules
├── README.md                # Full project documentation
├── DEPLOYMENT.md            # Step-by-step deployment guide
└── PROJECT_STRUCTURE.md     # This file
```

## Key Files Explained

### `src/App.jsx` (Main Game)
- Complete game logic and UI
- All 12 security incidents
- 8 player roles
- Game state management
- Timer functionality
- Scoring system

### `package.json`
- React 18.2.0
- Vite 5.0.7
- Tailwind CSS 3.3.6
- Lucide React icons

### `netlify.toml`
- Build command: `npm run build`
- Publish directory: `dist`
- SPA redirect rules
- Node 18 environment

### Configuration Files
- **vite.config.js**: Bundles React app for production
- **tailwind.config.js**: Scans src/ for Tailwind classes
- **postcss.config.js**: Processes Tailwind CSS

## Build Output

After running `npm run build`, creates:
```
dist/
├── index.html
├── assets/
│   ├── index-[hash].js
│   └── index-[hash].css
```

This `dist/` folder is what Netlify serves to users.

## Development Workflow

1. **Local development**: `npm run dev` → http://localhost:5173
2. **Build**: `npm run build` → creates dist/
3. **Preview**: `npm run preview` → tests production build
4. **Deploy**: `git push` → Netlify auto-deploys

## Mobile Optimization Features

- Viewport meta tags for mobile
- Touch-friendly buttons (min 44x44px)
- Portrait-optimized layout
- Prevents zoom on inputs
- PWA-ready manifest
- Responsive breakpoints via Tailwind

## No Server Required

This is a completely static React app:
- No backend/database needed
- All game state in browser memory
- Works offline after first load
- Perfect for Netlify/GitHub Pages/Vercel

## Future Additions

Potential files to add:
- `public/manifest.json` - PWA manifest
- `public/icons/` - App icons
- `src/components/` - Split App.jsx into components
- `src/data/incidents.js` - Externalize incident data
- `src/hooks/` - Custom React hooks
- `src/utils/` - Helper functions
- `.env` - Environment variables
- `tests/` - Unit tests
