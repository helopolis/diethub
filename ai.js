// ─── LLM PROVIDER ABSTRACTION ─────────────────────────────────────────────────
// One interface (chat) for the coach, daily brief, and lab analysis. Tries
// every configured provider in priority order and automatically falls
// through to the next on any failure (quota exhausted, key invalid, network
// error, empty response) — a real production outage taught this lesson
// directly: a single-provider setup (just Anthropic) went down when its
// credits ran out, silently breaking the chatbot and the daily brief for
// everyone until it was noticed. Free-tier providers come first on purpose.
//
// Anthropic removed entirely 2026-08-22 (was here as the one paid fallback,
// last-resort only) — explicit founder decision: no paid provider should
// ever be in this chain, at any position, regardless of how rarely it'd be
// hit. Replaced with a second OpenRouter-routed free model (openrouter2)
// rather than a brand-new provider signup — both Cerebras and Mistral were
// checked as "free" candidates first and both turned out to be time/credit-
// limited trials, not real perpetual free tiers, so they were rejected.
// OpenRouter's own free catalog was checked directly against its live API
// (openrouter.ai/api/v1/models, not the JS-rendered model browser page,
// which doesn't reflect the real list in a plain fetch) — NVIDIA's Nemotron
// line was picked from that real list for genuine infra diversity (distinct
// from Google/Gemini and Groq, unlike picking another Google Gemma variant).
//
//   AI_PROVIDER = gemini | groq | openrouter | openrouter2   (optional — forces
//                 that provider to the front of the fallback order)
//   GEMINI_API_KEY     + optional GEMINI_MODEL     (default gemini-flash-latest — free tier)
//   GROQ_API_KEY       + optional GROQ_MODEL       (default allam-2-7b — free tier; the original
//                         default, llama-3.3-70b-versatile, was retired by Groq — see the real
//                         verification story in buildRequest()'s own comment below)
//   OPENROUTER_API_KEY + optional OPENROUTER_MODEL   (default google/gemma-4-31b-it:free)
//                       + optional OPENROUTER_MODEL_2 (default nvidia/nemotron-3-super-120b-a12b:free
//                         — a second, independent free model behind the same OpenRouter key/API,
//                         so a rate-limit or retirement of one doesn't take out both. Several
//                         smaller/differently-branded candidates were live-tested and rejected
//                         first — see buildRequest()'s own comment for exactly which ones and why.)
//   OLLAMA_BASE_URL    + optional OLLAMA_MODEL     (default llama3.1 — local, self-hosted, no key;
//                         OLLAMA_BASE_URL is also what turns Ollama on at all, e.g.
//                         http://localhost:11434/v1 — Ollama's own OpenAI-compatible endpoint.
//                         Kept last in DEFAULT_ORDER below: unlike the cloud providers, "configured"
//                         only means a URL was given, not that anything is actually listening on it,
//                         so it should never be tried ahead of a provider known to really work.)

const PROVIDER_ENV_KEY = {
  gemini: 'GEMINI_API_KEY',
  groq: 'GROQ_API_KEY',
  openrouter: 'OPENROUTER_API_KEY',
  // Same key as `openrouter` on purpose — it's the same OpenRouter account,
  // just a second model string. If OPENROUTER_API_KEY is unset, both
  // correctly report as unconfigured together.
  openrouter2: 'OPENROUTER_API_KEY',
  // Ollama has no API key — this reuses the same "env var presence gates
  // inclusion" mechanism configuredProviders() already applies to every
  // other provider, just pointed at the base-URL var instead of a key, so
  // that function needs zero changes to also gate Ollama correctly.
  ollama: 'OLLAMA_BASE_URL',
};
// All free. Ollama is last, not just "another free option": it's
// local/self-hosted, so being "configured" (OLLAMA_BASE_URL set) doesn't
// mean it's actually reachable the way a cloud provider's key presence does.
const DEFAULT_ORDER = ['gemini', 'groq', 'openrouter', 'openrouter2', 'ollama'];

// The real, ordered list of providers to try this call, based on which keys
// are actually set. AI_PROVIDER (if it names a real provider) is pinned to
// the front without removing the rest of the chain behind it.
function configuredProviders() {
  const forced = (process.env.AI_PROVIDER || '').toLowerCase();
  const order = DEFAULT_ORDER.includes(forced)
    ? [forced, ...DEFAULT_ORDER.filter(p => p !== forced)]
    : DEFAULT_ORDER;
  return order.filter(p => !!process.env[PROVIDER_ENV_KEY[p]]);
}
function configured() { return configuredProviders().length > 0; }

// Build the HTTP request for a provider. Pure (no network) so it's unit-testable.
function buildRequest(provider, { system, messages, maxTokens = 600, lang = 'ar' }) {
  // This placeholder used to be hardcoded to Arabic regardless of the
  // caller's resolved language - harmless-looking (it's never shown to the
  // user), but real: it's the one actual user-turn message the model sees
  // whenever messages is empty (e.g. the chatbot's generateQuestions call).
  // A model can weight the literal language of that turn more heavily than
  // an all-English system prompt - confirmed live: Groq replied entirely in
  // Arabic to a 100%-English system prompt specifically when this fallback
  // fired, despite ai_language.js resolving 'en' correctly end-to-end.
  const msgs = (messages && messages.length) ? messages : [{ role: 'user', content: lang === 'en' ? 'Start' : 'ابدأ' }];
  if (provider === 'gemini') {
    // 'gemini-flash-latest' is Google's own auto-updating alias — verified
    // live 2026-08-06 that pinning to a specific version (gemini-2.5-flash)
    // had already gone stale ("no longer available to new users"); the alias
    // avoids repeating that failure every time Google ships a new model.
    const model = process.env.GEMINI_MODEL || 'gemini-flash-latest';
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`;
    // This model line defaults to an internal "thinking" pass that consumes
    // maxOutputTokens BEFORE any visible text is written — verified live
    // 2026-08-06: a plain one-line prompt burned 100-200 thinking tokens, a
    // realistic ~120-word brief prompt burned 1400+, and thinkingConfig:
    // {thinkingBudget:0} is rejected outright by this model ("invalid
    // argument") — there's no way found to turn thinking off, only to
    // out-budget it. GEMINI_THINKING_BUFFER pads every request so the
    // caller's real maxTokens is still honored for the visible answer.
    const GEMINI_THINKING_BUFFER = 2500;
    const body = {
      contents: msgs.map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] })),
      generationConfig: { maxOutputTokens: maxTokens + GEMINI_THINKING_BUFFER },
    };
    if (system) body.system_instruction = { parts: [{ text: system }] };
    return { url, headers: { 'Content-Type': 'application/json' }, body };
  }
  if (provider === 'groq') {
    // llama-3.3-70b-versatile was retired by Groq — confirmed 2026-08-22 by
    // querying Groq's own /v1/models directly with the real production key;
    // it's absent from the current model list, matching the exact "model
    // does not exist" error already seen live in this app's own logs.
    // qwen/qwen3.6-27b was tried first as the replacement and rejected —
    // live-tested and it leaked a visible <think>...</think> block into the
    // reply instead of answering, same failure class as the reasoning-model
    // issue already documented below for OpenRouter. allam-2-7b (SDAIA's
    // Arabic-focused instruction model) was tested directly the same way
    // and returned a clean, direct answer with no reasoning leak — and
    // being Arabic-native is a genuine bonus for this app specifically, not
    // just "a model that happens to work."
    const model = process.env.GROQ_MODEL || 'allam-2-7b';
    return {
      url: 'https://api.groq.com/openai/v1/chat/completions',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.GROQ_API_KEY}` },
      body: { model, max_tokens: maxTokens, messages: [...(system ? [{ role: 'system', content: system }] : []), ...msgs] },
    };
  }
  if (provider === 'openrouter') {
    const model = process.env.OPENROUTER_MODEL || 'google/gemma-4-31b-it:free';
    return {
      url: 'https://openrouter.ai/api/v1/chat/completions',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
        // OpenRouter asks for these on free-tier requests; harmless without them
        // but included so the account stays in good standing on their end.
        'HTTP-Referer': process.env.PUBLIC_BASE_URL || 'https://diet.talabatito.com',
        'X-Title': 'DietHub',
      },
      body: { model, max_tokens: maxTokens, messages: [...(system ? [{ role: 'system', content: system }] : []), ...msgs] },
    };
  }
  if (provider === 'openrouter2') {
    // Same API/auth as `openrouter` above — genuinely independent only in
    // which underlying model gets picked, which is the whole point (a
    // different lab/infra than Google's Gemma, so one being rate-limited
    // or retired doesn't take out both openrouter-routed rungs at once).
    // Three smaller/differently-branded NVIDIA Nemotron variants were tried
    // and live-tested directly against OpenRouter before this one: the
    // "nano-30b" reasoning variant leaked a visible chain-of-thought instead
    // of answering (same failure class as Groq's rejected qwen3.6-27b
    // above), "nano-9b-v2" and Google's own "gemma-4-26b-a4b-it:free"
    // (the smaller sibling of the already-proven `openrouter` model) both
    // returned genuinely empty responses. nemotron-3-super-120b-a12b:free
    // is the one that actually answered cleanly when tested directly.
    const model = process.env.OPENROUTER_MODEL_2 || 'nvidia/nemotron-3-super-120b-a12b:free';
    return {
      url: 'https://openrouter.ai/api/v1/chat/completions',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
        'HTTP-Referer': process.env.PUBLIC_BASE_URL || 'https://diet.talabatito.com',
        'X-Title': 'DietHub',
      },
      body: { model, max_tokens: maxTokens, messages: [...(system ? [{ role: 'system', content: system }] : []), ...msgs] },
    };
  }
  if (provider === 'ollama') {
    // Ollama's own OpenAI-compatible endpoint — same request/response shape
    // as groq/openrouter below, so no new parsing logic is needed either.
    // No API key exists to send; a harmless placeholder Bearer token is
    // included anyway since some OpenAI-compatible clients/proxies expect
    // the header to be present even when its value is ignored.
    const baseUrl = (process.env.OLLAMA_BASE_URL || 'http://localhost:11434/v1').replace(/\/$/, '');
    const model = process.env.OLLAMA_MODEL || 'llama3.1';
    return {
      url: `${baseUrl}/chat/completions`,
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ollama' },
      body: { model, max_tokens: maxTokens, messages: [...(system ? [{ role: 'system', content: system }] : []), ...msgs] },
    };
  }
  throw new Error('Unknown provider: ' + provider);
}

// Extract the assistant text from each provider's response shape.
function parseResponse(provider, json) {
  if (provider === 'gemini')      return json?.candidates?.[0]?.content?.parts?.[0]?.text || '';
  if (provider === 'groq')        return json?.choices?.[0]?.message?.content || '';
  if (provider === 'openrouter')  return json?.choices?.[0]?.message?.content || '';
  if (provider === 'openrouter2') return json?.choices?.[0]?.message?.content || '';
  if (provider === 'ollama')      return json?.choices?.[0]?.message?.content || '';
  return '';
}

// Tries every configured provider in order, falling through on ANY failure
// (bad status, network error, or an empty response) rather than only on a
// specific error code — the goal is "the feature works," not "diagnose
// exactly why one provider failed," and each failure is still logged for
// that diagnosis to happen separately.
async function chat({ system, messages, maxTokens = 600, lang = 'ar' }) {
  const providers = configuredProviders();
  if (!providers.length) {
    throw new Error('No AI provider configured — set GEMINI_API_KEY, GROQ_API_KEY, or OPENROUTER_API_KEY (all free)');
  }

  let lastError;
  for (const provider of providers) {
    try {
      const req = buildRequest(provider, { system, messages, maxTokens, lang });
      const r = await fetch(req.url, { method: 'POST', headers: req.headers, body: JSON.stringify(req.body) });
      if (!r.ok) {
        const body = await r.text().catch(() => '');
        throw new Error(`${provider} error: ${r.status}${body ? ' — ' + body.slice(0, 200) : ''}`);
      }
      const text = parseResponse(provider, await r.json());
      if (!text) throw new Error(`${provider} returned an empty response`);
      return { text, provider };
    } catch (e) {
      console.error(`[ai] ${provider} failed, trying next provider:`, e.message);
      lastError = e;
    }
  }
  throw lastError || new Error('All configured AI providers failed');
}

// ─── VISION SUPPORT (lab-photo / food-photo) ────────────────────────────────
// Added 2026-08-30: lab-results and nutrition-log photo uploads previously
// called Anthropic directly — a single paid provider with no free fallback,
// the exact architecture that already caused one real outage on the text
// chat path above (see file-top comment) before it recurred here. Only two
// providers actually have a genuine free vision-capable model, each
// verified live against its real API (not just its marketing docs) before
// being wired in: Groq's current model catalog has NO vision-capable model
// at all (confirmed via its own /v1/models list — allam-2-7b flatly rejects
// image content), so it's excluded entirely rather than just deprioritized.
// OpenAI and Anthropic have no ongoing free tier — Anthropic's is exactly
// the paid dependency being removed here — so neither belongs in a
// "free-first" chain at any position, matching the same founder policy
// that removed Anthropic from the chain above.
//
// OpenRouter gets two independent vision-capable free models (its primary
// chat model, gemma-4-31b-it:free, happens to also support vision; a
// second, different model is used for the fallback rung rather than
// reusing OPENROUTER_MODEL_2 above, whose default (nemotron-3-super-120b)
// is confirmed NOT vision-capable) before falling through to Gemini.
//
//   OPENROUTER_VISION_MODEL   (default google/gemma-4-31b-it:free)
//   OPENROUTER_VISION_MODEL_2 (default nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free —
//                               live-tested directly with a real photo before adoption)
//   GEMINI_MODEL — reuses the same var/default as the text chain above; the
//                  same model accepts inline image data too.
//
// Gemini is deliberately last, not just least-preferred — its real quota
// error (2026-08-30, this project's actual key) reads:
//   quotaId: "GenerateRequestsPerDayPerProjectPerModel-FreeTier", quotaValue: "20"
// Twenty requests PER DAY for the whole app, shared across chatbot,
// daily-brief, AND vision calls on this same key/project — not per user,
// not per hour. That's exhausted by ordinary combined traffic alone, so
// treat it as "occasionally available last resort," never as load-bearing.
// OpenRouter's own failures (visible in logs as "Worker local total
// request limit reached", e.g. "16/16") are a different kind of thing — a
// shared GLOBAL congestion signal from OpenRouter's whole free user base
// hitting that model, not a fixed per-project daily cap — so it clears and
// reopens, unlike Gemini's quota which doesn't refill until the next day.
// Founder decision (2026-08-30): rely mainly on OpenRouter's two models;
// keep Gemini in the chain but don't plan around it being available.
const VISION_PROVIDER_ORDER = ['openrouter', 'openrouter2', 'gemini'];

function configuredVisionProviders() {
  return VISION_PROVIDER_ORDER.filter(p => !!process.env[PROVIDER_ENV_KEY[p]]);
}

function buildVisionRequest(provider, { system, prompt, images, maxTokens = 1500 }) {
  const imgs = images || [];

  if (provider === 'gemini') {
    const model = process.env.GEMINI_MODEL || 'gemini-flash-latest';
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`;
    // Same "thinking burns the output budget" behavior as the text path
    // above — see that branch's comment for the live-verified numbers.
    const GEMINI_THINKING_BUFFER = 2500;
    const parts = [...imgs.map(img => ({ inline_data: { mime_type: img.mimeType, data: img.base64 } })), { text: prompt }];
    const body = {
      contents: [{ role: 'user', parts }],
      generationConfig: { maxOutputTokens: maxTokens + GEMINI_THINKING_BUFFER },
    };
    if (system) body.system_instruction = { parts: [{ text: system }] };
    return { url, headers: { 'Content-Type': 'application/json' }, body };
  }

  if (provider === 'openrouter' || provider === 'openrouter2') {
    const model = provider === 'openrouter'
      ? (process.env.OPENROUTER_VISION_MODEL || 'google/gemma-4-31b-it:free')
      : (process.env.OPENROUTER_VISION_MODEL_2 || 'nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free');
    const content = [
      { type: 'text', text: prompt },
      ...imgs.map(img => ({ type: 'image_url', image_url: { url: `data:${img.mimeType};base64,${img.base64}` } })),
    ];
    return {
      url: 'https://openrouter.ai/api/v1/chat/completions',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
        'HTTP-Referer': process.env.PUBLIC_BASE_URL || 'https://diet.talabatito.com',
        'X-Title': 'DietHub',
      },
      body: { model, max_tokens: maxTokens, messages: [...(system ? [{ role: 'system', content: system }] : []), { role: 'user', content }] },
    };
  }
  throw new Error('Unknown vision provider: ' + provider);
}

// nemotron-omni's "reasoning" rung answers via a normal OpenAI-shaped
// response with its chain-of-thought kept in a separate `reasoning` field
// (verified live) rather than leaking into `content` the way the text
// chain's rejected reasoning-model candidates did — so the existing
// choices[0].message.content parse below is already the clean answer.
function parseVisionResponse(provider, json) {
  if (provider === 'gemini') return json?.candidates?.[0]?.content?.parts?.[0]?.text || '';
  if (provider === 'openrouter' || provider === 'openrouter2') return json?.choices?.[0]?.message?.content || '';
  return '';
}

// Same "try every configured provider, fall through on any failure" shape
// as chat() above, kept as its own function rather than a branch inside
// chat() because the provider set, request shape (images + inline data vs.
// image_url content parts), and response parsing are all different enough
// that folding them together would just be an if/else fork on every line.
async function chatVision({ system, prompt, images, maxTokens = 1500 }) {
  const providers = configuredVisionProviders();
  if (!providers.length) {
    throw new Error('No vision-capable AI provider configured — set OPENROUTER_API_KEY or GEMINI_API_KEY (both free)');
  }

  let lastError;
  for (const provider of providers) {
    try {
      const req = buildVisionRequest(provider, { system, prompt, images, maxTokens });
      const r = await fetch(req.url, { method: 'POST', headers: req.headers, body: JSON.stringify(req.body) });
      const json = await r.json().catch(() => ({}));
      if (!r.ok || json.type === 'error' || json.error) {
        throw new Error(`${provider} error: ${r.status} — ${JSON.stringify(json.error || json).slice(0, 300)}`);
      }
      const text = parseVisionResponse(provider, json);
      if (!text) throw new Error(`${provider} returned an empty response`);
      return { text, provider };
    } catch (e) {
      console.error(`[ai-vision] ${provider} failed, trying next provider:`, e.message);
      lastError = e;
    }
  }
  throw lastError || new Error('All configured vision providers failed');
}

module.exports = { chat, configured, configuredProviders, buildRequest, parseResponse, chatVision, configuredVisionProviders };
