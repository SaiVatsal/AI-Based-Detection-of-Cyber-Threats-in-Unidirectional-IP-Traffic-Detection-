import { useState, useRef, useEffect } from 'react';
import { Bot, X, Send, Sparkles, Shield, Terminal, Volume2, VolumeX, RefreshCw } from 'lucide-react';

const SUGGESTED_PROMPTS = [
  'Why does Snort fail on Data Diodes?',
  'How to mitigate a 2,000+ req/s DDoS attack?',
  'Explain Shannon Entropy for DNS Tunnelling',
  'What are the 20 Unidirectional Features?',
  'How does Isolation Forest detect Zero-Day threats?',
  'Generate an Nginx WAF rate-limit config',
];

const KNOWLEDGE_BASE = {
  snort: `Traditional IDS tools like Snort, Suricata, and Zeek fail behind Data Diodes because they require bi-directional TCP 3-way handshakes (SYN -> SYN-ACK -> ACK) and request-response correlation. On an optical data diode, return traffic is physically 0 packets. CampusShield AI solves this by computing 20 unidirectional-safe features purely from passive one-way arrival metadata.`,
  mitigate: `To mitigate a high-velocity volumetric attack (2,000+ req/s):
1. **Linux IPTables Drop**:
   \`iptables -A INPUT -p tcp --dport 80 -m limit --limit 150/s --limit-burst 300 -j ACCEPT\`
   \`iptables -A INPUT -s 198.51.100.0/24 -j DROP\`
2. **Nginx WAF Zone**:
   \`limit_req_zone $binary_remote_addr zone=flood_zone:20m rate=150r/s;\`
3. **Optical Diode Buffer Tuning**: Increase Rx ring buffers to prevent packet drop on burst frames.`,
  entropy: `Shannon Entropy H(X) measures byte randomness:
$$H(X) = -\\sum P(b_i) \\log_2 P(b_i)$$
- **Plain HTTP / Normal DNS**: H(X) ≈ 3.5 - 4.5 bits/byte (structured English).
- **DNS Tunnel / Encrypted Exfiltration**: H(X) spikes to 7.2 - 7.99 bits/byte.
We detect high-entropy payloads and query names without needing private decryption keys!`,
  features: `The 20 Unidirectional Features include:
1. **Volume/Rate**: packets_per_second, bytes_per_second, total_bytes, packet_count
2. **Frame Sizes**: min, max, mean, std, skewness
3. **Timing/Jitter**: min_iat, max_iat, mean_iat, std_iat, burst_count (Δt < 1ms)
4. **Entropy & Spread**: payload_entropy, protocol_entropy, dst_port_entropy, unique_dst_ports
5. **Protocols**: tcp_ratio, udp_ratio`,
  isolation: `Isolation Forest uses an ensemble of 100 decision trees. Because anomalous packet vectors (DDoS floods, port sweeps) differ drastically in feature space, they isolate near tree roots with short path lengths h(x). The anomaly score s(x, n) = 2^(-E(h(x))/c(n)) flags threats with zero labeled training data.`,
  waf: `Here is the production Nginx WAF rate-limiting policy:
\`\`\`nginx
# In nginx.conf
limit_req_zone $binary_remote_addr zone=campus_shield_waf:20m rate=100r/s;
limit_req_status 429;

server {
    location / {
        limit_req zone=campus_shield_waf burst=200 nodelay;
        proxy_pass http://backend_upstream;
    }
}
\`\`\``,
  default: `I am your **CampusShield AI SOC Copilot**! I can provide real-time recommendations, explain our 20 unidirectional mathematical features, generate Linux firewall drop scripts, or detail why hardware data diodes require passive ML intelligence. What threat or architectural detail would you like to analyze?`
};

export default function AICopilotChat() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      id: 1,
      sender: 'ai',
      text: `Hello Lead Architect! 🛡️ I am your **CampusShield AI SOC Copilot**. I analyze unidirectional telemetry, explain AI formulas, and generate automated mitigation playbooks. Ask me anything or select a topic below!`,
      time: 'Just now'
    }
  ]);
  const [inputText, setInputText] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [voiceEnabled, setVoiceEnabled] = useState(true);
  const chatEndRef = useRef(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const getFemaleVoice = () => {
    if (typeof window === 'undefined' || !window.speechSynthesis) return null;
    const voices = window.speechSynthesis.getVoices();
    return (
      voices.find((v) => v.name.includes('Natural') || v.name.includes('Neural')) ||
      voices.find(
        (v) =>
          v.lang.startsWith('en') &&
          (/jenny|aria|samantha|karen|serena|victoria|ava|google us english/i.test(v.name))
      ) ||
      voices.find((v) => v.lang.startsWith('en') && !/david|mark|george|male/i.test(v.name)) ||
      voices[0]
    );
  };

  const speak = (text) => {
    if (!voiceEnabled || !window.speechSynthesis) return;
    try {
      window.speechSynthesis.cancel();
      // Clean text of markdown, code blocks, and formulas for smooth human speech
      const cleanText = text
        .replace(/```[\s\S]*?```/g, 'I have generated the configuration code in the chat.')
        .replace(/[*#`$\\]/g, '')
        .slice(0, 240);

      const utterance = new SpeechSynthesisUtterance(cleanText);
      const voice = getFemaleVoice();
      if (voice) utterance.voice = voice;
      utterance.pitch = 1.04;
      utterance.rate = 1.02;
      window.speechSynthesis.speak(utterance);
    } catch (e) {
      console.warn('Speech error:', e);
    }
  };

  const handleSend = (textToSend) => {
    const query = (textToSend || inputText).trim();
    if (!query) return;

    const userMsg = {
      id: Date.now(),
      sender: 'user',
      text: query,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!textToSend) setInputText('');
    setIsTyping(true);

    setTimeout(() => {
      let replyText = KNOWLEDGE_BASE.default;
      const lower = query.toLowerCase();

      if (lower.includes('snort') || lower.includes('suricata') || lower.includes('fail') || lower.includes('traditional')) {
        replyText = KNOWLEDGE_BASE.snort;
      } else if (lower.includes('mitigate') || lower.includes('ddos') || lower.includes('iptables') || lower.includes('block')) {
        replyText = KNOWLEDGE_BASE.mitigate;
      } else if (lower.includes('entropy') || lower.includes('shannon') || lower.includes('dns') || lower.includes('tunnel')) {
        replyText = KNOWLEDGE_BASE.entropy;
      } else if (lower.includes('feature') || lower.includes('20') || lower.includes('extractor')) {
        replyText = KNOWLEDGE_BASE.features;
      } else if (lower.includes('isolation') || lower.includes('forest') || lower.includes('zero-day') || lower.includes('unsupervised')) {
        replyText = KNOWLEDGE_BASE.isolation;
      } else if (lower.includes('waf') || lower.includes('nginx') || lower.includes('rate-limit')) {
        replyText = KNOWLEDGE_BASE.waf;
      } else {
        replyText = `Under the SIH26145 unidirectional constraint, "${query}" is analyzed purely through passive flow features (arrival intervals, packet size moments, and Shannon byte entropy). Would you like me to generate specific firewall rules or detail our Isolation Forest scoring pipeline for this?`;
      }

      const aiMsg = {
        id: Date.now() + 1,
        sender: 'ai',
        text: replyText,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      setMessages((prev) => [...prev, aiMsg]);
      setIsTyping(false);
      speak(replyText);
    }, 600);
  };

  return (
    <>
      {/* Floating Copilot Launcher Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        style={{
          position: 'fixed',
          bottom: 24,
          right: 24,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '12px 18px',
          background: 'linear-gradient(135deg, #060b18, #0a1024)',
          border: '1px solid var(--accent-cyan)',
          borderRadius: 30,
          color: 'var(--accent-cyan)',
          fontWeight: 700,
          fontSize: 13,
          cursor: 'pointer',
          boxShadow: '0 0 24px rgba(0, 240, 255, 0.3), 0 8px 32px rgba(0,0,0,0.8)',
          zIndex: 1100,
          transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
        }}
      >
        <div style={{ position: 'relative' }}>
          <Bot size={20} color="var(--accent-cyan)" />
          <span style={{ position: 'absolute', top: -2, right: -2, width: 6, height: 6, borderRadius: '50%', background: 'var(--severity-low)', boxShadow: '0 0 6px var(--severity-low)' }} />
        </div>
        <span>AI Threat Copilot</span>
        <Sparkles size={14} color="var(--accent-cyan)" />
      </button>

      {/* Cyber Chat Drawer */}
      {isOpen && (
        <div
          style={{
            position: 'fixed',
            bottom: 84,
            right: 24,
            width: 400,
            maxWidth: 'calc(100vw - 48px)',
            height: 540,
            maxHeight: 'calc(100vh - 120px)',
            background: 'rgba(6, 11, 24, 0.96)',
            backdropFilter: 'blur(20px)',
            border: '1px solid rgba(0, 240, 255, 0.3)',
            borderRadius: 16,
            boxShadow: '0 20px 60px rgba(0, 0, 0, 0.9), 0 0 30px rgba(0, 240, 255, 0.2)',
            display: 'flex',
            flexDirection: 'column',
            zIndex: 1100,
            overflow: 'hidden',
            animation: 'fadeIn 0.25s ease-out',
          }}
        >
          {/* Header */}
          <div
            style={{
              padding: '14px 16px',
              borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
              background: 'rgba(10, 16, 36, 0.8)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ padding: 6, borderRadius: 8, background: 'rgba(0, 240, 255, 0.1)', border: '1px solid var(--accent-cyan)' }}>
                <Shield size={18} color="var(--accent-cyan)" />
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: 0.3 }}>
                  CampusShield AI SOC Copilot
                </div>
                <div style={{ fontSize: 10, color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
                  Active Unidirectional Advisory Engine
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <button
                onClick={() => {
                  setVoiceEnabled(!voiceEnabled);
                  if (voiceEnabled && window.speechSynthesis) window.speechSynthesis.cancel();
                }}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: voiceEnabled ? 'var(--accent-cyan)' : 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: 4,
                }}
                title={voiceEnabled ? 'Mute AI Voice' : 'Enable AI Voice'}
              >
                {voiceEnabled ? <Volume2 size={18} /> : <VolumeX size={18} />}
              </button>

              <button
                onClick={() => setIsOpen(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4 }}
              >
                <X size={18} />
              </button>
            </div>
          </div>

          {/* Quick Suggestion Chips */}
          <div
            style={{
              padding: '8px 12px',
              display: 'flex',
              gap: 6,
              overflowX: 'auto',
              borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
              background: '#040711',
            }}
          >
            {SUGGESTED_PROMPTS.map((p, idx) => (
              <button
                key={idx}
                onClick={() => handleSend(p)}
                style={{
                  whiteSpace: 'nowrap',
                  fontSize: 10,
                  padding: '4px 10px',
                  background: 'rgba(0, 240, 255, 0.08)',
                  border: '1px solid rgba(0, 240, 255, 0.2)',
                  borderRadius: 12,
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                }}
                onMouseEnter={(e) => { e.target.style.color = 'var(--accent-cyan)'; e.target.style.borderColor = 'var(--accent-cyan)'; }}
                onMouseLeave={(e) => { e.target.style.color = 'var(--text-secondary)'; e.target.style.borderColor = 'rgba(0, 240, 255, 0.2)'; }}
              >
                {p}
              </button>
            ))}
          </div>

          {/* Chat Messages Body */}
          <div
            style={{
              flex: 1,
              padding: 16,
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: 12,
              fontFamily: 'system-ui, sans-serif',
            }}
          >
            {messages.map((m) => (
              <div
                key={m.id}
                style={{
                  alignSelf: m.sender === 'user' ? 'flex-end' : 'flex-start',
                  maxWidth: '88%',
                }}
              >
                <div
                  style={{
                    padding: '10px 14px',
                    borderRadius: 12,
                    background: m.sender === 'user' ? 'linear-gradient(135deg, #0284c7, #0369a1)' : 'rgba(10, 16, 36, 0.9)',
                    border: `1px solid ${m.sender === 'user' ? 'transparent' : 'rgba(0, 240, 255, 0.2)'}`,
                    color: '#fff',
                    fontSize: 12.5,
                    lineHeight: 1.5,
                    boxShadow: m.sender === 'user' ? '0 4px 14px rgba(2, 132, 199, 0.3)' : 'none',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                  }}
                >
                  {m.text}
                </div>
                <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 3, textAlign: m.sender === 'user' ? 'right' : 'left' }}>
                  {m.time}
                </div>
              </div>
            ))}

            {isTyping && (
              <div style={{ alignSelf: 'flex-start', padding: '8px 14px', background: 'rgba(10, 16, 36, 0.9)', borderRadius: 12, border: '1px solid rgba(0, 240, 255, 0.2)' }}>
                <span style={{ fontSize: 11, color: 'var(--accent-cyan)' }}>AI Copilot is analyzing threat models...</span>
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          {/* Input Box */}
          <form
            onSubmit={(e) => { e.preventDefault(); handleSend(); }}
            style={{
              padding: '10px 14px',
              borderTop: '1px solid rgba(255, 255, 255, 0.08)',
              background: '#040711',
              display: 'flex',
              gap: 8,
            }}
          >
            <input
              type="text"
              placeholder="Ask Copilot about threats, WAF rules, math..."
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              style={{
                flex: 1,
                padding: '8px 12px',
                background: 'rgba(10, 16, 36, 0.8)',
                border: '1px solid rgba(0, 240, 255, 0.2)',
                borderRadius: 8,
                color: '#fff',
                fontSize: 12,
                outline: 'none',
              }}
            />
            <button
              type="submit"
              disabled={!inputText.trim()}
              style={{
                padding: '8px 14px',
                background: 'var(--accent-cyan)',
                border: 'none',
                borderRadius: 8,
                color: '#030712',
                fontWeight: 800,
                cursor: 'pointer',
                opacity: inputText.trim() ? 1 : 0.4,
              }}
            >
              <Send size={14} />
            </button>
          </form>
        </div>
      )}
    </>
  );
}
