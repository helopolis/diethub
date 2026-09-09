// ─── AI LANGUAGE SERVICE ────────────────────────────────────────────────────
// Single source of truth for what language every AI-facing prompt (and every
// server-authored string adjacent to an AI call — gate messages, fallback
// replies, error text) resolves to. Built to close a real, verified gap: the
// chatbot's system prompt was previously hardcoded to Arabic regardless of
// the user's real, stored language preference (req.userObj.lang), so an
// English-UI user got Arabic AI replies. daily_brief.js's getBriefText()
// already handled its own ar/en branching correctly, but duplicated the
// language-selection logic independently — this module is also what
// eliminates that duplication, not just fixes the chatbot's hardcoding.
//
// Adding a third language later means adding one entry to LANGUAGE_INSTRUCTION
// and AI_STRINGS below — no caller (server.js, daily_brief.js, health.js, or
// either client) needs to change.

const SUPPORTED_LANGUAGES = ['ar', 'en'];
const DEFAULT_LANGUAGE = 'en';

// Resolution order, matching the mandated fallback chain exactly:
// 1. The authenticated user's own stored preference (req.userObj.lang) —
//    the real single source of truth once an account has one.
// 2. The client's current UI language, sent along on the request — covers
//    accounts created before `lang` existed on the user record, or any
//    other case where the stored preference is genuinely absent.
// 3. English, only if neither of the above resolved to a supported code.
function resolveLanguage({ userLang, appLang } = {}) {
  if (SUPPORTED_LANGUAGES.includes(userLang)) return userLang;
  if (SUPPORTED_LANGUAGES.includes(appLang)) return appLang;
  return DEFAULT_LANGUAGE;
}

// The one place the AI is told what language to answer in. Deliberately
// short and behavioral, not a translation of the product instructions —
// mixing instruction content into this block would recreate the exact
// duplication this module exists to remove.
const LANGUAGE_INSTRUCTION = {
  ar: 'اكتب ردك بالكامل باللغة العربية الفصحى المبسطة، بأسلوب طبيعي ومحادثي. حافظ على المصطلحات الطبية والغذائية الدقيقة كما هي إذا كانت الترجمة قد تُفقدها الوضوح. لا تخلط بين العربية والإنجليزية في نفس الرد إلا إذا طلب المستخدم ذلك صراحة — بما في ذلك كلمات بسيطة مثل "yesterday" أو "today"، التي يجب أن تُكتب دائماً "أمس" و"اليوم". النص سيُعرض من اليمين إلى اليسار.',
  en: 'Write your entire reply in natural, conversational English. Preserve precise medical and nutritional terminology rather than force-translating it if that would lose clarity. Do not mix English and Arabic in the same reply unless the user explicitly asks for that. The text will be displayed left-to-right.',
};

// Deterministic, server-authored strings that sit directly alongside AI
// calls (paywall gate, empty-reply fallback, plan-generation failure/
// exception text). These are not AI output, but they were previously
// hardcoded Arabic literals returned regardless of the requester's
// language — a real, verified leak: mobile's error handler falls back to
// `e.message` (the server's raw text) before its own localized generic-
// error copy, so an English-UI user could see a raw Arabic error string.
const AI_STRINGS = {
  ar: {
    paidGate: 'هذه الميزة متاحة للمشتركين فقط',
    emptyReply: 'عذراً، لم أفهم. حاول مجدداً.',
    planParseFailed: 'عذراً، تعذر بناء خطة منظمة الآن. حاول صياغة طلبك بشكل مختلف.',
    planGenError: 'عذراً، حدث خطأ أثناء بناء الخطة. حاول مجدداً.',
    chatbotError: 'خطأ في المساعد الذكي: ',
    planSaved: (title, dayCount) =>
      `✅ تم إنشاء "${title}" (${dayCount} ${dayCount === 1 ? 'يوم' : 'أيام'}) وحفظه كاقتراح ذكاء اصطناعي — غير موثّق، يمكنك مراجعته أو حذفه في أي وقت من "اقتراحاتي المحفوظة".`,
  },
  en: {
    paidGate: 'This feature is available for paid plan members only',
    emptyReply: "Sorry, I didn't understand that. Please try again.",
    planParseFailed: "Sorry, I couldn't build a structured plan right now. Try phrasing your request differently.",
    planGenError: 'Sorry, something went wrong while building the plan. Please try again.',
    chatbotError: 'AI assistant error: ',
    planSaved: (title, dayCount) =>
      `✅ Created "${title}" (${dayCount} day${dayCount === 1 ? '' : 's'}) and saved it as an AI suggestion — unverified. You can review or delete it anytime from "My Saved Suggestions."`,
  },
};

// Composes the final system-prompt string from named layers, per the
// mandated architecture (Product Instructions → Safety Instructions →
// Dynamic Language Instruction → User Health Context). `productInstructions`
// and `safetyInstructions` are supplied by the caller verbatim — this
// function only assembles and injects the language layer, it does not
// author or alter instructional content, matching the explicit "do not
// redesign prompts" boundary.
function buildSystemPrompt({ productInstructions, safetyInstructions, lang, userContext }) {
  const resolvedLang = SUPPORTED_LANGUAGES.includes(lang) ? lang : DEFAULT_LANGUAGE;
  const sections = [
    productInstructions,
    safetyInstructions,
    LANGUAGE_INSTRUCTION[resolvedLang],
    userContext ? `${resolvedLang === 'ar' ? 'الملف الصحي الكامل للمستخدم' : "User's complete health profile"}:\n${userContext}` : null,
  ].filter(Boolean);
  return sections.join('\n\n');
}

function strings(lang) {
  const resolvedLang = SUPPORTED_LANGUAGES.includes(lang) ? lang : DEFAULT_LANGUAGE;
  return AI_STRINGS[resolvedLang];
}

module.exports = { SUPPORTED_LANGUAGES, DEFAULT_LANGUAGE, resolveLanguage, buildSystemPrompt, strings, LANGUAGE_INSTRUCTION };
