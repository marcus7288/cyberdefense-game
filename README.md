# CyberDefense - OWASP Tabletop Security Game

An interactive, mobile-optimized cybersecurity incident response game based on OWASP principles. Designed for 6-8 players working collaboratively to defend an organization against security threats.

## 🎮 Game Features

- **Collaborative Gameplay**: 6-8 players work together as a security team
- **8 Specialized Roles**: CISO, Security Analyst, Security Engineer, Incident Responder, System Admin, Dev Team Lead, Network Engineer, and User Education
- **12 Realistic Incidents**: Based on real-world OWASP threats including phishing, ransomware, SQL injection, data breaches, and more
- **Timed Decision Making**: Each incident has a countdown timer forcing quick strategic decisions
- **Role-Based Actions**: Different responses require specific team roles
- **Mobile Optimized**: Designed for smartphone and tablet play
- **Dynamic Difficulty**: Incidents have varying severity levels and time constraints

## 🚀 Deployment Instructions

### Option 1: Deploy to Netlify via GitHub (Recommended)

1. **Push to GitHub**:
   ```bash
   cd cyberdefense-game
   git init
   git add .
   git commit -m "Initial commit: CyberDefense game"
   git branch -M main
   git remote add origin YOUR_GITHUB_REPO_URL
   git push -u origin main
   ```

2. **Connect to Netlify**:
   - Go to [Netlify](https://app.netlify.com)
   - Click "Add new site" → "Import an existing project"
   - Choose "Deploy with GitHub"
   - Select your repository
   - Netlify will auto-detect the settings from `netlify.toml`
   - Click "Deploy site"

3. **Your site will be live** at a URL like: `https://your-site-name.netlify.app`

### Option 2: Deploy via Netlify CLI

```bash
cd cyberdefense-game
npm install
npm run build
npx netlify-cli deploy --prod
```

### Option 3: Deploy via Netlify Drop

1. Build the project locally:
   ```bash
   npm install
   npm run build
   ```
2. Go to [Netlify Drop](https://app.netlify.com/drop)
3. Drag and drop the `dist` folder

## 🛠️ Local Development

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## 🎯 How to Play

### Setup Phase
1. **Assemble Your Team**: Each player selects a role (6 minimum, 8 maximum)
2. **Start Mission**: Begin the incident response simulation

### Gameplay
1. **Read the Incident**: Each round presents a new security threat
2. **Discuss Strategy**: Team discusses the best response (you have limited time!)
3. **Choose Action**: Select a response option - actions require specific roles
4. **Resolve Outcome**: Actions have success rates - hope for good rolls!
5. **Survive 8 Rounds**: Keep organization health above 0 to win

### Roles & Responsibilities

- **CISO**: Strategic decisions, policy, and leadership
- **Security Analyst**: Threat detection and analysis
- **Security Engineer**: Technical controls and system hardening
- **Incident Responder**: Emergency response and recovery
- **System Admin**: Infrastructure and operations
- **Dev Team Lead**: Secure development and patching
- **Network Engineer**: Network security and monitoring
- **User Education**: Training and awareness programs

### Incident Categories

- Social Engineering
- Malware & Ransomware
- Application Security
- Network Attacks
- Vulnerability Management
- Data Security
- Access Control
- Third Party Risk
- Cloud Security
- Authentication
- IoT Security

## 📱 Mobile Optimization

- Responsive design works on all screen sizes
- Touch-optimized buttons and controls
- Optimized for portrait orientation
- Works offline after initial load (PWA ready)

## 🎓 Educational Value

This game teaches:
- Incident response procedures
- Role-based security responsibilities
- Time-critical decision making
- Team collaboration under pressure
- OWASP Top 10 vulnerabilities
- Real-world attack scenarios
- Security trade-offs and risk management

## 🔧 Technical Stack

- **React 18**: UI framework
- **Vite**: Build tool and dev server
- **Tailwind CSS**: Styling
- **Lucide React**: Icons
- **Netlify**: Hosting and deployment

## 📝 Customization

### Adding New Incidents

Edit `src/App.jsx` and add to the `incidents` array:

```javascript
{
  id: 13,
  title: 'Your Incident Title',
  category: 'Category Name',
  severity: 'critical|high|medium|low',
  description: 'What happened?',
  impact: 25, // damage if no action taken
  timeLimit: 60, // seconds to respond
  responses: [
    {
      text: 'Response action description',
      roles: ['role1', 'role2'], // required roles
      success: 85, // % chance of success
      damage: 10 // damage on failure
    }
  ]
}
```

### Adjusting Game Balance

In `src/App.jsx`, modify:
- `maxRounds`: Number of rounds (default: 8)
- `organizationHealth`: Starting health (default: 100)
- `timerSeconds`: Time per incident
- Response `success` rates
- `impact` and `damage` values

## 🤝 Contributing

This game is designed for educational purposes. Feel free to:
- Add new incidents based on current threats
- Create new roles for specialized security functions
- Adjust difficulty and timing
- Translate to other languages
- Add sound effects or animations

## 📄 License

MIT License - Free to use for educational purposes

## 🎉 Credits

Created for cybersecurity education and team training. Based on OWASP principles and real-world incident response scenarios.

## 🐛 Known Issues / Future Enhancements

- [ ] Add sound effects for incidents and outcomes
- [ ] Implement difficulty levels (easy/medium/hard)
- [ ] Add achievement system
- [ ] Create campaign mode with connected scenarios
- [ ] Add player statistics tracking
- [ ] Implement persistent storage for game history
- [ ] Add multiplayer sync across devices
- [ ] Create printable reference cards

## 📞 Support

For issues or questions, please open an issue on GitHub.

---

**Good luck, Security Team! The organization is counting on you! 🛡️**
