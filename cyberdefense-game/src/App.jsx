import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Users, Clock, Target, Award, ChevronRight, Zap, Database, Lock, Wifi, Mail, Server } from 'lucide-react';

const CybersecurityGame = () => {
  const [gameState, setGameState] = useState('setup'); // setup, playing, gameOver
  const [players, setPlayers] = useState([]);
  const [currentRound, setCurrentRound] = useState(1);
  const [maxRounds] = useState(8);
  const [organizationHealth, setOrganizationHealth] = useState(100);
  const [securityScore, setSecurityScore] = useState(0);
  const [currentIncident, setCurrentIncident] = useState(null);
  const [timerSeconds, setTimerSeconds] = useState(90);
  const [isTimerActive, setIsTimerActive] = useState(false);
  const [usedIncidents, setUsedIncidents] = useState([]);
  const [eventLog, setEventLog] = useState([]);

  const roles = [
    { id: 'ciso', name: 'CISO', icon: Shield, color: 'bg-purple-500', description: 'Security strategy & policy' },
    { id: 'analyst', name: 'Security Analyst', icon: Target, color: 'bg-blue-500', description: 'Threat detection & analysis' },
    { id: 'engineer', name: 'Security Engineer', icon: Lock, color: 'bg-green-500', description: 'Technical controls & hardening' },
    { id: 'responder', name: 'Incident Responder', icon: Zap, color: 'bg-red-500', description: 'Emergency response & recovery' },
    { id: 'admin', name: 'System Admin', icon: Server, color: 'bg-yellow-500', description: 'Infrastructure & operations' },
    { id: 'developer', name: 'Dev Team Lead', icon: Database, color: 'bg-indigo-500', description: 'Secure development & patching' },
    { id: 'neteng', name: 'Network Engineer', icon: Wifi, color: 'bg-cyan-500', description: 'Network security & monitoring' },
    { id: 'user', name: 'User Education', icon: Mail, color: 'bg-pink-500', description: 'Training & awareness' }
  ];

  const incidents = [
    {
      id: 1,
      title: 'Phishing Campaign Detected',
      category: 'Social Engineering',
      severity: 'medium',
      description: 'Multiple employees received convincing phishing emails claiming to be from IT.',
      impact: 15,
      timeLimit: 90,
      responses: [
        { text: 'Block sender domains immediately', roles: ['analyst', 'neteng'], success: 70, damage: 5 },
        { text: 'Send organization-wide warning', roles: ['user', 'ciso'], success: 85, damage: 8 },
        { text: 'Isolate affected accounts', roles: ['admin', 'responder'], success: 90, damage: 10 },
        { text: 'Implement email authentication', roles: ['engineer', 'neteng'], success: 95, damage: 3 }
      ]
    },
    {
      id: 2,
      title: 'Ransomware on File Server',
      category: 'Malware',
      severity: 'critical',
      description: 'Encryption detected on a critical file server. Ransom note demands payment.',
      impact: 30,
      timeLimit: 60,
      responses: [
        { text: 'Isolate infected systems immediately', roles: ['responder', 'admin'], success: 95, damage: 15 },
        { text: 'Restore from last backup', roles: ['admin', 'engineer'], success: 80, damage: 20 },
        { text: 'Negotiate with attackers', roles: ['ciso'], success: 30, damage: 30 },
        { text: 'Wipe and rebuild systems', roles: ['admin', 'engineer'], success: 85, damage: 25 }
      ]
    },
    {
      id: 3,
      title: 'SQL Injection Vulnerability',
      category: 'Application Security',
      severity: 'high',
      description: 'Penetration test reveals SQL injection in customer portal allowing data extraction.',
      impact: 20,
      timeLimit: 90,
      responses: [
        { text: 'Deploy emergency patch', roles: ['developer', 'engineer'], success: 90, damage: 5 },
        { text: 'Take application offline', roles: ['ciso', 'admin'], success: 95, damage: 15 },
        { text: 'Implement WAF rules', roles: ['engineer', 'neteng'], success: 75, damage: 10 },
        { text: 'Review all input validation', roles: ['developer', 'analyst'], success: 85, damage: 8 }
      ]
    },
    {
      id: 4,
      title: 'Insider Threat Suspected',
      category: 'Insider Risk',
      severity: 'high',
      description: 'Unusual data access patterns from privileged account during non-business hours.',
      impact: 25,
      timeLimit: 75,
      responses: [
        { text: 'Suspend account immediately', roles: ['ciso', 'admin'], success: 85, damage: 20 },
        { text: 'Review access logs thoroughly', roles: ['analyst', 'responder'], success: 80, damage: 15 },
        { text: 'Engage HR and legal', roles: ['ciso'], success: 70, damage: 12 },
        { text: 'Implement privileged access monitoring', roles: ['engineer', 'analyst'], success: 90, damage: 10 }
      ]
    },
    {
      id: 5,
      title: 'DDoS Attack in Progress',
      category: 'Network Attack',
      severity: 'high',
      description: 'Website experiencing massive traffic spike. Services degrading rapidly.',
      impact: 20,
      timeLimit: 45,
      responses: [
        { text: 'Enable DDoS mitigation service', roles: ['neteng', 'admin'], success: 90, damage: 8 },
        { text: 'Block attacking IP ranges', roles: ['neteng', 'engineer'], success: 60, damage: 15 },
        { text: 'Scale infrastructure', roles: ['admin', 'engineer'], success: 70, damage: 12 },
        { text: 'Engage ISP for upstream filtering', roles: ['neteng', 'ciso'], success: 85, damage: 10 }
      ]
    },
    {
      id: 6,
      title: 'Unpatched Critical Vulnerability',
      category: 'Vulnerability Management',
      severity: 'critical',
      description: 'Zero-day exploit announced for software used across organization. Active exploitation in the wild.',
      impact: 35,
      timeLimit: 60,
      responses: [
        { text: 'Emergency patching campaign', roles: ['admin', 'engineer'], success: 85, damage: 10 },
        { text: 'Disable affected service', roles: ['ciso', 'admin'], success: 95, damage: 20 },
        { text: 'Implement compensating controls', roles: ['engineer', 'neteng'], success: 75, damage: 15 },
        { text: 'Hunt for indicators of compromise', roles: ['analyst', 'responder'], success: 80, damage: 25 }
      ]
    },
    {
      id: 7,
      title: 'Data Breach Discovered',
      category: 'Data Security',
      severity: 'critical',
      description: 'Customer data found for sale on dark web. Breach timeline unclear.',
      impact: 40,
      timeLimit: 90,
      responses: [
        { text: 'Activate incident response plan', roles: ['ciso', 'responder'], success: 95, damage: 20 },
        { text: 'Notify customers immediately', roles: ['ciso', 'user'], success: 85, damage: 25 },
        { text: 'Engage forensics team', roles: ['analyst', 'responder'], success: 90, damage: 15 },
        { text: 'Begin regulatory notifications', roles: ['ciso'], success: 80, damage: 30 }
      ]
    },
    {
      id: 8,
      title: 'Compromised Admin Credentials',
      category: 'Access Control',
      severity: 'critical',
      description: 'Domain admin credentials leaked in credential dump. Potential for full network compromise.',
      impact: 35,
      timeLimit: 45,
      responses: [
        { text: 'Force password reset all admins', roles: ['admin', 'ciso'], success: 95, damage: 15 },
        { text: 'Revoke all active sessions', roles: ['admin', 'engineer'], success: 90, damage: 12 },
        { text: 'Enable MFA immediately', roles: ['engineer', 'admin'], success: 85, damage: 10 },
        { text: 'Hunt for unauthorized access', roles: ['analyst', 'responder'], success: 88, damage: 20 }
      ]
    },
    {
      id: 9,
      title: 'Supply Chain Attack',
      category: 'Third Party Risk',
      severity: 'high',
      description: 'Trusted vendor compromised. Their software update contains backdoor.',
      impact: 25,
      timeLimit: 75,
      responses: [
        { text: 'Block vendor updates immediately', roles: ['admin', 'engineer'], success: 90, damage: 10 },
        { text: 'Audit vendor access', roles: ['analyst', 'ciso'], success: 85, damage: 15 },
        { text: 'Rollback to previous version', roles: ['admin', 'developer'], success: 80, damage: 18 },
        { text: 'Scan for IOCs across environment', roles: ['analyst', 'responder'], success: 88, damage: 12 }
      ]
    },
    {
      id: 10,
      title: 'Misconfigured Cloud Storage',
      category: 'Cloud Security',
      severity: 'high',
      description: 'Public S3 bucket discovered containing sensitive internal documents.',
      impact: 22,
      timeLimit: 60,
      responses: [
        { text: 'Make bucket private immediately', roles: ['admin', 'engineer'], success: 95, damage: 8 },
        { text: 'Audit all cloud resources', roles: ['engineer', 'analyst'], success: 85, damage: 15 },
        { text: 'Implement cloud security policies', roles: ['engineer', 'ciso'], success: 90, damage: 10 },
        { text: 'Investigate data exposure', roles: ['analyst', 'responder'], success: 80, damage: 18 }
      ]
    },
    {
      id: 11,
      title: 'Credential Stuffing Attack',
      category: 'Authentication',
      severity: 'medium',
      description: 'Automated login attempts using leaked credentials from other breaches.',
      impact: 18,
      timeLimit: 90,
      responses: [
        { text: 'Implement rate limiting', roles: ['engineer', 'neteng'], success: 85, damage: 5 },
        { text: 'Force password resets', roles: ['admin', 'user'], success: 80, damage: 12 },
        { text: 'Deploy CAPTCHA', roles: ['developer', 'engineer'], success: 90, damage: 7 },
        { text: 'Enable account monitoring', roles: ['analyst', 'engineer'], success: 88, damage: 8 }
      ]
    },
    {
      id: 12,
      title: 'IoT Device Botnet',
      category: 'IoT Security',
      severity: 'medium',
      description: 'Office smart devices compromised and participating in botnet activities.',
      impact: 15,
      timeLimit: 75,
      responses: [
        { text: 'Isolate IoT network segment', roles: ['neteng', 'admin'], success: 90, damage: 5 },
        { text: 'Reset all IoT devices', roles: ['admin', 'engineer'], success: 85, damage: 10 },
        { text: 'Update firmware', roles: ['engineer', 'admin'], success: 80, damage: 8 },
        { text: 'Implement IoT security policy', roles: ['ciso', 'neteng'], success: 88, damage: 6 }
      ]
    }
  ];

  useEffect(() => {
    if (isTimerActive && timerSeconds > 0) {
      const timer = setTimeout(() => {
        setTimerSeconds(timerSeconds - 1);
      }, 1000);
      return () => clearTimeout(timer);
    } else if (isTimerActive && timerSeconds === 0) {
      handleTimeout();
    }
  }, [timerSeconds, isTimerActive]);

  const startGame = () => {
    if (players.length < 6) {
      alert('Need at least 6 players to start!');
      return;
    }
    setGameState('playing');
    drawNewIncident();
    addToLog('Game started! Organization under threat...');
  };

  const addPlayer = (roleId) => {
    const role = roles.find(r => r.id === roleId);
    const playerName = prompt(`Enter name for ${role.name}:`);
    if (playerName) {
      setPlayers([...players, { ...role, playerName, actionsThisRound: 0 }]);
    }
  };

  const removePlayer = (index) => {
    setPlayers(players.filter((_, i) => i !== index));
  };

  const drawNewIncident = () => {
    const availableIncidents = incidents.filter(i => !usedIncidents.includes(i.id));
    if (availableIncidents.length === 0) {
      endGame('victory');
      return;
    }
    const randomIncident = availableIncidents[Math.floor(Math.random() * availableIncidents.length)];
    setCurrentIncident(randomIncident);
    setTimerSeconds(randomIncident.timeLimit);
    setIsTimerActive(true);
    setUsedIncidents([...usedIncidents, randomIncident.id]);
    addToLog(`Round ${currentRound}: ${randomIncident.title} - ${randomIncident.category}`);
  };

  const handleResponse = (response) => {
    const playerRoles = players.map(p => p.id);
    const hasRequiredRoles = response.roles.every(role => playerRoles.includes(role));
    
    if (!hasRequiredRoles) {
      alert(`This action requires: ${response.roles.map(r => roles.find(role => role.id === r)?.name).join(', ')}`);
      return;
    }

    const roll = Math.random() * 100;
    const success = roll < response.success;
    
    if (success) {
      setSecurityScore(securityScore + 10);
      setOrganizationHealth(Math.min(100, organizationHealth + 5));
      addToLog(`✓ Success! ${response.text} - Organization health improved`);
    } else {
      const damage = response.damage;
      setOrganizationHealth(organizationHealth - damage);
      addToLog(`✗ Failed! ${response.text} - Took ${damage} damage`);
    }

    setIsTimerActive(false);
    
    if (organizationHealth - (success ? 0 : response.damage) <= 0) {
      endGame('defeat');
    } else if (currentRound >= maxRounds) {
      endGame('victory');
    } else {
      setTimeout(() => {
        setCurrentRound(currentRound + 1);
        drawNewIncident();
      }, 2000);
    }
  };

  const handleTimeout = () => {
    const damage = currentIncident.impact;
    setOrganizationHealth(organizationHealth - damage);
    addToLog(`⏰ Time's up! No action taken - ${damage} damage from ${currentIncident.title}`);
    setIsTimerActive(false);
    
    if (organizationHealth - damage <= 0) {
      endGame('defeat');
    } else if (currentRound >= maxRounds) {
      endGame('victory');
    } else {
      setTimeout(() => {
        setCurrentRound(currentRound + 1);
        drawNewIncident();
      }, 2000);
    }
  };

  const endGame = (result) => {
    setGameState('gameOver');
    setIsTimerActive(false);
    if (result === 'victory') {
      addToLog('🎉 Victory! Organization secured!');
    } else {
      addToLog('💥 Game Over! Organization compromised!');
    }
  };

  const addToLog = (message) => {
    setEventLog(prev => [...prev, { message, timestamp: new Date().toLocaleTimeString() }].slice(-10));
  };

  const resetGame = () => {
    setGameState('setup');
    setPlayers([]);
    setCurrentRound(1);
    setOrganizationHealth(100);
    setSecurityScore(0);
    setCurrentIncident(null);
    setUsedIncidents([]);
    setEventLog([]);
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'critical': return 'bg-red-600';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      default: return 'bg-blue-500';
    }
  };

  if (gameState === 'setup') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 text-white p-4">
        <div className="max-w-2xl mx-auto">
          <div className="text-center mb-8">
            <Shield className="w-20 h-20 mx-auto mb-4 text-blue-400" />
            <h1 className="text-4xl font-bold mb-2">CyberDefense</h1>
            <p className="text-blue-300">OWASP Tabletop Security Game</p>
          </div>

          <div className="bg-slate-800/50 backdrop-blur rounded-lg p-6 mb-6 border border-blue-500/30">
            <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
              <Users className="w-5 h-5" />
              Team Assembly ({players.length}/8)
            </h2>
            
            {players.length < 6 && (
              <div className="bg-yellow-500/20 border border-yellow-500/50 rounded p-3 mb-4">
                <p className="text-sm text-yellow-200">Need at least 6 players to start</p>
              </div>
            )}

            <div className="space-y-2 mb-4">
              {players.map((player, index) => {
                const RoleIcon = player.icon;
                return (
                  <div key={index} className={`${player.color} rounded p-3 flex items-center justify-between`}>
                    <div className="flex items-center gap-3">
                      <RoleIcon className="w-5 h-5" />
                      <div>
                        <p className="font-semibold">{player.playerName}</p>
                        <p className="text-xs opacity-90">{player.name}</p>
                      </div>
                    </div>
                    <button onClick={() => removePlayer(index)} className="text-white/70 hover:text-white">×</button>
                  </div>
                );
              })}
            </div>

            <div className="grid grid-cols-2 gap-2">
              {roles.filter(role => !players.find(p => p.id === role.id)).map(role => {
                const RoleIcon = role.icon;
                return (
                  <button
                    key={role.id}
                    onClick={() => addPlayer(role.id)}
                    className={`${role.color} hover:opacity-90 rounded p-3 text-left transition-all`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <RoleIcon className="w-4 h-4" />
                      <p className="font-semibold text-sm">{role.name}</p>
                    </div>
                    <p className="text-xs opacity-90">{role.description}</p>
                  </button>
                );
              })}
            </div>
          </div>

          <button
            onClick={startGame}
            disabled={players.length < 6}
            className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-bold py-4 rounded-lg transition-all flex items-center justify-center gap-2"
          >
            <Shield className="w-5 h-5" />
            Start Mission
          </button>

          <div className="mt-6 bg-slate-800/30 rounded-lg p-4 text-sm text-blue-200">
            <h3 className="font-bold mb-2">How to Play:</h3>
            <ul className="space-y-1 list-disc list-inside">
              <li>Work together to respond to security incidents</li>
              <li>Each response requires specific roles</li>
              <li>Choose wisely - success rates and damage vary</li>
              <li>Keep organization health above 0</li>
              <li>Survive {maxRounds} rounds to win!</li>
            </ul>
          </div>
        </div>
      </div>
    );
  }

  if (gameState === 'gameOver') {
    const finalGrade = organizationHealth > 75 ? 'A' : organizationHealth > 50 ? 'B' : organizationHealth > 25 ? 'C' : 'F';
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 text-white p-4 flex items-center justify-center">
        <div className="max-w-md w-full bg-slate-800/50 backdrop-blur rounded-lg p-6 border border-blue-500/30">
          <div className="text-center mb-6">
            {organizationHealth > 0 ? (
              <Award className="w-20 h-20 mx-auto mb-4 text-green-400" />
            ) : (
              <AlertTriangle className="w-20 h-20 mx-auto mb-4 text-red-400" />
            )}
            <h1 className="text-3xl font-bold mb-2">
              {organizationHealth > 0 ? 'Mission Complete!' : 'System Compromised'}
            </h1>
          </div>

          <div className="space-y-4 mb-6">
            <div className="bg-slate-700/50 rounded p-4">
              <p className="text-sm text-gray-300 mb-1">Final Health</p>
              <div className="flex items-center gap-3">
                <div className="flex-1 bg-slate-600 rounded-full h-3">
                  <div 
                    className={`h-full rounded-full transition-all ${organizationHealth > 50 ? 'bg-green-500' : organizationHealth > 25 ? 'bg-yellow-500' : 'bg-red-500'}`}
                    style={{width: `${Math.max(0, organizationHealth)}%`}}
                  />
                </div>
                <span className="font-bold text-xl">{Math.max(0, organizationHealth)}%</span>
              </div>
            </div>

            <div className="bg-slate-700/50 rounded p-4">
              <p className="text-sm text-gray-300 mb-1">Security Score</p>
              <p className="text-2xl font-bold text-blue-400">{securityScore}</p>
            </div>

            <div className="bg-slate-700/50 rounded p-4">
              <p className="text-sm text-gray-300 mb-1">Performance Grade</p>
              <p className="text-4xl font-bold text-center">{finalGrade}</p>
            </div>

            <div className="bg-slate-700/50 rounded p-4">
              <p className="text-sm text-gray-300 mb-2">Incidents Handled</p>
              <p className="text-lg font-bold">{currentRound - 1} / {maxRounds}</p>
            </div>
          </div>

          <button
            onClick={resetGame}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-lg transition-all"
          >
            New Game
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 text-white p-4 pb-20">
      <div className="max-w-2xl mx-auto">
        {/* Header Stats */}
        <div className="grid grid-cols-3 gap-2 mb-4">
          <div className="bg-slate-800/50 backdrop-blur rounded-lg p-3 border border-blue-500/30">
            <div className="flex items-center gap-2 mb-1">
              <Clock className="w-4 h-4 text-blue-400" />
              <p className="text-xs text-gray-300">Round</p>
            </div>
            <p className="text-xl font-bold">{currentRound}/{maxRounds}</p>
          </div>
          
          <div className="bg-slate-800/50 backdrop-blur rounded-lg p-3 border border-blue-500/30">
            <div className="flex items-center gap-2 mb-1">
              <Shield className="w-4 h-4 text-green-400" />
              <p className="text-xs text-gray-300">Health</p>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex-1 bg-slate-600 rounded-full h-2">
                <div 
                  className={`h-full rounded-full transition-all ${organizationHealth > 50 ? 'bg-green-500' : organizationHealth > 25 ? 'bg-yellow-500' : 'bg-red-500'}`}
                  style={{width: `${organizationHealth}%`}}
                />
              </div>
              <span className="text-sm font-bold">{organizationHealth}%</span>
            </div>
          </div>

          <div className="bg-slate-800/50 backdrop-blur rounded-lg p-3 border border-blue-500/30">
            <div className="flex items-center gap-2 mb-1">
              <Award className="w-4 h-4 text-yellow-400" />
              <p className="text-xs text-gray-300">Score</p>
            </div>
            <p className="text-xl font-bold">{securityScore}</p>
          </div>
        </div>

        {/* Timer */}
        <div className="bg-slate-800/50 backdrop-blur rounded-lg p-4 mb-4 border border-red-500/50">
          <div className="flex items-center justify-between mb-2">
            <p className="font-bold text-red-400">TIME REMAINING</p>
            <Clock className="w-5 h-5 text-red-400" />
          </div>
          <div className="text-4xl font-bold text-center text-red-400">
            {Math.floor(timerSeconds / 60)}:{(timerSeconds % 60).toString().padStart(2, '0')}
          </div>
          <div className="mt-2 bg-slate-600 rounded-full h-2">
            <div 
              className="bg-red-500 h-full rounded-full transition-all"
              style={{width: `${(timerSeconds / currentIncident?.timeLimit) * 100}%`}}
            />
          </div>
        </div>

        {/* Current Incident */}
        {currentIncident && (
          <div className="bg-slate-800/50 backdrop-blur rounded-lg p-4 mb-4 border border-red-500/30">
            <div className="flex items-start justify-between mb-3">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <span className={`${getSeverityColor(currentIncident.severity)} px-2 py-1 rounded text-xs font-bold uppercase`}>
                    {currentIncident.severity}
                  </span>
                  <span className="bg-blue-500/30 px-2 py-1 rounded text-xs">
                    {currentIncident.category}
                  </span>
                </div>
                <h2 className="text-xl font-bold mb-2">{currentIncident.title}</h2>
                <p className="text-sm text-gray-300">{currentIncident.description}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-400 flex-shrink-0 ml-2" />
            </div>
          </div>
        )}

        {/* Response Options */}
        <div className="space-y-2 mb-4">
          <p className="text-sm font-bold text-gray-300 mb-2">RESPONSE OPTIONS:</p>
          {currentIncident?.responses.map((response, index) => {
            const requiredRoleNames = response.roles.map(r => roles.find(role => role.id === r)?.name);
            const playerRoles = players.map(p => p.id);
            const hasRoles = response.roles.every(role => playerRoles.includes(role));
            
            return (
              <button
                key={index}
                onClick={() => handleResponse(response)}
                disabled={!hasRoles}
                className={`w-full text-left p-4 rounded-lg border transition-all ${
                  hasRoles 
                    ? 'bg-slate-700/50 border-blue-500/50 hover:bg-slate-700 hover:border-blue-500' 
                    : 'bg-slate-800/30 border-gray-600/30 opacity-50'
                }`}
              >
                <div className="flex items-start justify-between mb-2">
                  <p className="font-semibold flex-1">{response.text}</p>
                  <ChevronRight className="w-5 h-5 flex-shrink-0 ml-2" />
                </div>
                <div className="flex items-center justify-between text-xs">
                  <div className="flex flex-wrap gap-1">
                    {requiredRoleNames.map((name, i) => (
                      <span key={i} className="bg-blue-600/30 px-2 py-0.5 rounded">
                        {name}
                      </span>
                    ))}
                  </div>
                  <span className="text-gray-400">Success: {response.success}%</span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Event Log */}
        <div className="bg-slate-800/50 backdrop-blur rounded-lg p-4 border border-blue-500/30">
          <p className="text-sm font-bold text-gray-300 mb-2">EVENT LOG:</p>
          <div className="space-y-1 text-xs max-h-32 overflow-y-auto">
            {eventLog.slice().reverse().map((log, index) => (
              <div key={index} className="text-gray-300">
                <span className="text-blue-400">[{log.timestamp}]</span> {log.message}
              </div>
            ))}
          </div>
        </div>

        {/* Active Team */}
        <div className="mt-4 bg-slate-800/50 backdrop-blur rounded-lg p-4 border border-blue-500/30">
          <p className="text-sm font-bold text-gray-300 mb-2">ACTIVE TEAM:</p>
          <div className="grid grid-cols-2 gap-2">
            {players.map((player, index) => {
              const RoleIcon = player.icon;
              return (
                <div key={index} className={`${player.color} rounded p-2 text-xs`}>
                  <div className="flex items-center gap-2">
                    <RoleIcon className="w-4 h-4" />
                    <div className="flex-1 min-w-0">
                      <p className="font-semibold truncate">{player.playerName}</p>
                      <p className="text-xs opacity-75 truncate">{player.name}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default CybersecurityGame;
