// ─── LLM PROVIDER ABSTRACTION ─────────────────────────────────────────────────
// One interface (chat) for the coach and lab analysis, with pluggable providers.
// Run on a FREE provider now (Gemini or Groq) and switch to Anthropic later by
// changing env vars only — no code changes.
//
//   AI_PROVIDER = gemini | groq | anthropic   (optional; auto-detected from keys)
//   GEMINI_API_KEY   + optional GEMINI_MODEL   (default gemini-2.5-flash — free tier)
//   GROQ_API_KEY     + optional GROQ_MODEL     (default llama-3.3-70b-versatile — free tier)
//   ANTHROPIC_API_KEY+ optional ANTHROPIC_MODEL(default claude-haiku-4-5-20251001)

function activeProvider() {
  const p = (process.env.AI_PROVIDER || '').toLowerCase();
  if (['gemini', 'groq', 'anthropic'].includes(p)) return p;
  if (process.env.GEMINI_API_KEY)    return 'gemini';   // prefer the free options
  if (process.env.GROQ_API_KEY)      return 'groq';
  if (process.env.ANTHROPIC_API_KEY) return 'anthropic';
  return null;
}
function configured() { return activeProvider() !== null; }

// Build the HTTP request for a provider. Pure (no network) so it's unit-testable.
function buildRequest(provider, { system, messages, maxTokens = 600 }) {
  const msgs = (messages && messages.length) ? messages : [{ role: 'user', content: 'ابدأ' }];
  if (provider === 'gemini') {
    const model = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`;
    const body = {
      contents: msgs.map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] })),
      generationConfig: { maxOutputTokens: maxTokens },
    };
    if (system) body.system_instruction = { parts: [{ text: system }] };
    return { url, headers: { 'Content-Type': 'application/json' }, body };
  }
  if (provider === 'groq') {
    const model = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
    return {
      url: 'https://api.groq.com/openai/v1/chat/completions',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.GROQ_API_KEY}` },
      body: { model, max_tokens: maxTokens, messages: [...(system ? [{ role: 'system', content: system }] : []), ...msgs] },
    };
  }
  if (provider === 'anthropic') {
    const model = process.env.ANTHROPIC_MODEL || 'claude-haiku-4-5-20251001';
    const body = { model, max_tokens: maxTokens, messages: msgs };
    if (system) body.system = system;
    return {
      url: 'https://api.anthropic.com/v1/messages',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body,
    };
  }
  throw new Error('Unknown provider: ' + provider);
}

// Extract the assistant text from each provider's response shape.
function parseResponse(provider, json) {
  if (provider === 'gemini')    return json?.candidates?.[0]?.content?.parts?.[0]?.text || '';
  if (provider === 'groq')      return json?.choices?.[0]?.message?.content || '';
  if (provider === 'anthropic') return json?.content?.[0]?.text || '';
  return '';
}

async function chat({ system, messages, maxTokens = 600 }) {
  const provider = activeProvider();
  if (!provider) throw new Error('No AI provider configured — set GEMINI_API_KEY (free), GROQ_API_KEY (free), or ANTHROPIC_API_KEY');
  const req = buildRequest(provider, { system, messages, maxTokens });
  const r = await fetch(req.url, { method: 'POST', headers: req.headers, body: JSON.stringify(req.body) });
  if (!r.ok) throw new Error(`${provider} error: ${r.status}`);
  const text = parseResponse(provider, await r.json());
  return { text, provider };
}

module.exports = { chat, activeProvider, configured, buildRequest, parseResponse };
