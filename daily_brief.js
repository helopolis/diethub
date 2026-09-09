// ─── AI DAILY BRIEFING ──────────────────────────────────────────────────────
// Phase 1: AI-generated narrative, missing-data cards, real cross-store
// savings signal — see the module-level comments below each section.
// Phase 2a (2026-08-06): a deterministic Wellness Score, real nutrition
// totals, and goal-gap "priority" cards — all rule-based, zero AI cost, so
// the screen's core experience never depends on (or breaks with) the AI
// provider being available. AI stays additive/optional (just the narrative
// text), matching the user's own "reserve AI for optional insights" call.
// Still deliberately excludes: blood pressure, blood glucose, medication
// tracking, workout logging, weekly trend charts — real data-collection
// features this app doesn't have yet, not something a rule engine can fake.

const aiLanguage = require('./ai_language');

const SLEEP_TARGET_H = 8;
const STEPS_TARGET = 8000;

function todayCairo() {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Cairo' }).format(new Date());
}

function daysSince(isoDateOrTimestamp) {
  if (!isoDateOrTimestamp) return null;
  const then = new Date(isoDateOrTimestamp);
  if (isNaN(then)) return null;
  return Math.floor((Date.now() - then.getTime()) / 86400000);
}

// ─── AI narrative, cached once per user per day ────────────────────────────
// Prompt construction now goes through ai_language.js's buildSystemPrompt()
// (Product Instructions -> Language Instruction -> User Context), the same
// composition every AI call site in the app uses — this used to inline its
// own separate ar/en ternary and combine instructions+data into one
// user-role message instead of a real system prompt, a second, independent
// copy of the exact language-selection logic /api/chatbot also had.
async function getBriefText(store, ai, coachSummary, hp, userId, lang) {
  const date = todayCairo();
  const resolvedLang = aiLanguage.resolveLanguage({ userLang: lang });
  // Cache is keyed by date AND language — a user switching language mid-day
  // (e.g. via the in-app toggle) must get a freshly-generated brief in the
  // new language, not the first language's cached text for today.
  const cache = store.load('daily_briefs.json') || {};
  const cached = cache[userId];
  if (cached && cached.date === date && cached.lang === resolvedLang) return cached.text;
  if (!ai.configured()) return null;

  const isAr = resolvedLang === 'ar';
  const summary = coachSummary(hp, resolvedLang);
  const productInstructions = isAr
    ? `اكتب موجزاً صحياً يومياً قصيراً لهذا المستخدم (90 كلمة كحد أقصى، نص عادي بدون تنسيق أو عناوين). الهيكل: ما حدث أمس، الحالة الحالية، تركيز اليوم، جملة تحفيزية واحدة. استخدم كلمات بسيطة جداً وجملاً قصيرة يفهمها طفل في العاشرة من عمره — ليس أسلوب تقرير أو ملخص أكاديمي، ولا مصطلحات معقدة. دافئ ومشجع مثل صديق، ليس رسمياً. استخدم فقط البيانات الحقيقية أدناه، لا تخترع أرقاماً.`
    : `Write a short daily wellness briefing for this user (max 90 words, plain text, no markdown, no headers). Structure: what happened yesterday, current status, today's focus, one motivating line. Use very simple, everyday words and short sentences — write like you're explaining it to a 10-year-old, not writing a report or an academic summary. No jargon, no complex phrasing. Warm and encouraging like a friend, not formal. Use ONLY the real data given below, never invent numbers.`;
  const systemPrompt = aiLanguage.buildSystemPrompt({ productInstructions, lang: resolvedLang, userContext: summary });

  try {
    const { text } = await ai.chat({
      system: systemPrompt,
      messages: [{ role: 'user', content: isAr ? 'اكتب الموجز اليومي الآن.' : 'Write the daily briefing now.' }],
      maxTokens: 220,
    });
    if (!text) return null;
    cache[userId] = { date, lang: resolvedLang, text: text.trim() };
    store.save('daily_briefs.json', cache);
    return text.trim();
  } catch (e) {
    console.error('[daily_brief] AI generation failed:', e.message);
    return null; // graceful — screen just omits the brief text today
  }
}

// ─── Missing-data cards: presence gaps ("you haven't logged X") ───────────
function buildMissingDataCards(store, userId, lang) {
  const en = lang === 'en';
  const date = todayCairo();
  const cards = [];

  const watch = (store.load('watch_data.json') || {})[userId] || [];
  const todayEntry = watch.find(d => d.date === date);
  const latestEntry = watch[0]; // sorted newest-first by upsertWatchMetric

  if (!todayEntry || todayEntry.water == null) {
    cards.push({
      type: 'water', severity: 'warning',
      title: en ? 'No water logged today' : 'لم يتم تسجيل شرب الماء اليوم',
      body: en ? 'Log your water intake for accurate hydration guidance.' : 'سجل كمية الماء لمتابعة دقيقة لهدف الترطيب.',
      action: 'log_water',
    });
  }

  const users = store.load('users.json') || [];
  const user = users.find(u => u.id === userId);
  const measurementsAge = daysSince(user?.profile?.measurementsUpdatedAt);
  if (measurementsAge == null) {
    cards.push({
      type: 'weight', severity: 'warning',
      title: en ? 'Weight never recorded' : 'لم يتم تسجيل الوزن من قبل',
      body: en ? 'Record your weight to get accurate calorie and protein targets.' : 'سجل وزنك للحصول على أهداف سعرات وبروتين دقيقة.',
      action: 'log_weight',
    });
  } else if (measurementsAge >= 14) {
    cards.push({
      type: 'weight', severity: 'warning',
      title: en ? `Weight not updated in ${measurementsAge} days` : `لم يتم تحديث الوزن منذ ${measurementsAge} يوماً`,
      body: en ? 'Keeping your weight current improves your recommendations.' : 'تحديث وزنك بانتظام يحسّن دقة التوصيات.',
      action: 'log_weight',
    });
  }

  const syncAge = daysSince(latestEntry?.date);
  if (syncAge == null || syncAge >= 3) {
    cards.push({
      type: 'wearable', severity: 'info',
      title: en ? 'No recent smartwatch data' : 'لا توجد بيانات ساعة ذكية حديثة',
      body: en ? 'Connect or sync your device to improve activity and recovery guidance.' : 'اربط أو زامن ساعتك الذكية لتحسين توصيات النشاط والتعافي.',
      action: 'connect_watch',
    });
  }

  if (user?.profile?.takesCreatine) {
    cards.push({
      type: 'supplement', severity: 'info',
      title: en ? 'Creatine reminder' : 'تذكير الكرياتين',
      body: en ? 'Make sure you hit today\'s water and protein targets alongside your creatine.' : 'تأكد من الوصول لهدف الماء والبروتين اليوم مع الكرياتين.',
      action: null,
    });
  }

  return cards;
}

// ─── Priority cards: goal gaps ("you're behind on X"), deterministic —
// template text, no AI call. Distinct from missingData above: these fire
// even when data IS present, just short of target. ──────────────────────
function buildPriorities(lang, hp, nutritionToday, watchEntry) {
  const en = lang === 'en';
  const cards = [];

  if (nutritionToday && hp.targets.proteinTargetG) {
    const gap = hp.targets.proteinTargetG - nutritionToday.protein;
    if (gap > 10) {
      cards.push({
        type: 'protein', severity: 'info',
        title: en ? `Increase protein by ${gap}g` : `زد البروتين بمقدار ${gap} جم`,
        body: en
          ? `You're at ${nutritionToday.protein}g of your ${hp.targets.proteinTargetG}g target today.`
          : `أنت عند ${nutritionToday.protein} جم من هدف ${hp.targets.proteinTargetG} جم اليوم.`,
      });
    }
  }

  if (watchEntry?.sleep != null && watchEntry.sleep < 7) {
    cards.push({
      type: 'sleep', severity: 'warning',
      title: en ? 'Aim for 7+ hours tonight' : 'حاول تنام 7 ساعات على الأقل الليلة',
      body: en
        ? `Last recorded sleep was ${watchEntry.sleep}h, below a healthy minimum.`
        : `آخر نوم مسجل ${watchEntry.sleep} ساعة، أقل من الحد الصحي.`,
    });
  }

  return cards;
}

// ─── Real cross-store savings signal (no fabricated day-over-day trend —
// there's no price history to back that claim, only a live snapshot) ───────
function buildSavingsCard(store, lang) {
  const fp = store.load('food_prices.json');
  if (!fp?.items?.length) return null;
  const en = lang === 'en';
  const STORE_KEYS = ['carrefour', 'metro', 'royal', 'talabat', 'seoudi', 'gourmet', 'spinneys', 'hyperone'];

  let best = null;
  for (const item of fp.items) {
    const prices = STORE_KEYS.map(k => item[k]).filter(p => typeof p === 'number' && p > 0);
    if (prices.length < 2) continue;
    const min = Math.min(...prices);
    const avg = prices.reduce((a, b) => a + b, 0) / prices.length;
    const pctBelowAvg = ((avg - min) / avg) * 100;
    if (!best || pctBelowAvg > best.pctBelowAvg) {
      const cheapestStore = STORE_KEYS.find(k => item[k] === min);
      best = { item, min, avg, pctBelowAvg, cheapestStore };
    }
  }
  if (!best || best.pctBelowAvg < 10) return null; // not a real enough gap to call a "deal"

  return {
    itemName: en ? best.item.nameEn : best.item.name,
    store: best.cheapestStore,
    price: best.min,
    pctBelowAverage: Math.round(best.pctBelowAvg),
    estimatedSavingsEGP: Math.round(best.avg - best.min),
    lastUpdated: fp.lastUpdated,
  };
}

// Mirrors getMealOverride() in server.js exactly (server.js isn't set up as
// an importable module, so this is a small, deliberate duplication — keep
// in sync if that one changes). Updated for the meal_overrides scalability
// migration (architecture audit Section 13): reads the real table via
// store.getMealOverrideRow() instead of the old meal_overrides.json blob -
// same shape, so nothing downstream in this file needed to change.
function getMealOverride(store, userId, date, mealType) {
  return store.getMealOverrideRow(userId, date, mealType);
}

// ─── Real nutrition totals for today, from data already logged ────────────
// Ports the calculation that previously only lived in the web dashboard's
// client-side JS (dashboard.html's updateNutrition()) so the mobile app can
// use it too. Deliberately matches that same simplification — always
// resolves against week[0] of the static plan, manual swaps only (no live
// AI/budget-tier meal regeneration) — so totals never silently disagree
// between the website and the app for the same logged day.
function computeNutritionToday(store, userId, diet) {
  const date = todayCairo();
  const logs = store.load('nutrition_logs.json') || {};
  const todayLog = (logs[userId] || []).find(l => l.date === date);
  if (!todayLog) return null;

  const plans = store.load('meal_plans.json');
  const plan = plans?.[diet] || plans?.atkins;
  const dayMeals = plan?.week?.[0]?.meals || [];

  let cal = 0, protein = 0, carbs = 0, fat = 0;
  for (const i of (todayLog.meals || [])) {
    const meal = dayMeals[i];
    if (!meal) continue;
    const mealTypeKey = meal.typeEn ? meal.typeEn.toLowerCase() : meal.type;
    const override = getMealOverride(store, userId, date, mealTypeKey);
    const effective = (override && override.manualSwap) ? override.meal : meal;
    cal += parseInt(effective.cal) || 0;
    protein += parseInt(effective.protein) || 0;
    carbs += parseInt(effective.carbs) || 0;
    fat += parseInt(effective.fat) || 0;
  }
  for (const f of (todayLog.custom || [])) {
    cal += f.cal || 0; protein += f.protein || 0; carbs += f.carbs || 0; fat += f.fat || 0;
  }
  return { cal, protein, carbs, fat, loggedMealCount: (todayLog.meals || []).length, customCount: (todayLog.custom || []).length };
}

// ─── Deterministic Wellness Score ──────────────────────────────────────────
// Five factors from data the app already has (sleep, activity, nutrition,
// hydration, heart rate) — blood pressure and blood glucose are deliberately
// excluded (not collected anywhere), with the remaining weights renormalized
// rather than treating the missing 20% as zero. Any factor without real data
// today drops out entirely rather than dragging the score down; confidence
// reflects how many of the 5 actually had data, so a 92 with low confidence
// still reads honestly as "not much to go on yet."
function scoreSleep(watchEntry) {
  if (watchEntry?.sleep == null) return null;
  return Math.max(0, Math.min(100, Math.round((watchEntry.sleep / SLEEP_TARGET_H) * 100)));
}
function scoreActivity(watchEntry) {
  if (watchEntry?.steps == null) return null;
  return Math.max(0, Math.min(100, Math.round((watchEntry.steps / STEPS_TARGET) * 100)));
}
function scoreHydration(watchEntry, targetL) {
  if (watchEntry?.water == null || !targetL) return null;
  return Math.max(0, Math.min(100, Math.round((watchEntry.water / targetL) * 100)));
}
function scoreHeart(watchEntry) {
  if (watchEntry?.heartRate == null) return null;
  const hr = watchEntry.heartRate;
  // 55-75 bpm resting is a common "athletic-normal" band - this is a simple,
  // defensible bucket for a wellness score, not a clinical diagnostic.
  if (hr >= 55 && hr <= 75) return 100;
  if (hr < 55) return Math.max(0, 100 - (55 - hr) * 4);
  return Math.max(0, 100 - (hr - 75) * 2);
}
function scoreNutrition(nutritionToday, proteinTargetG) {
  if (!nutritionToday || !proteinTargetG) return null;
  return Math.max(0, Math.min(100, Math.round((nutritionToday.protein / proteinTargetG) * 100)));
}

function computeWellnessScore(watchEntry, targets, nutritionToday) {
  const factors = [
    { key: 'sleep', weight: 25, score: scoreSleep(watchEntry) },
    { key: 'activity', weight: 25, score: scoreActivity(watchEntry) },
    { key: 'nutrition', weight: 25, score: scoreNutrition(nutritionToday, targets.proteinTargetG) },
    { key: 'hydration', weight: 12.5, score: scoreHydration(watchEntry, targets.hydrationTargetL) },
    { key: 'heart', weight: 12.5, score: scoreHeart(watchEntry) },
  ];
  const available = factors.filter(f => f.score != null);
  const confidence = Math.round((available.length / factors.length) * 100);
  if (!available.length) return { score: null, confidence: 0, factors: factors.map(f => ({ key: f.key, score: null })) };

  const totalWeight = available.reduce((s, f) => s + f.weight, 0);
  const weighted = available.reduce((s, f) => s + f.score * f.weight, 0) / totalWeight;
  return { score: Math.round(weighted), confidence, factors: factors.map(f => ({ key: f.key, score: f.score })) };
}

// ─── Health Snapshot: real current values + a real weight trend ───────────
function buildSnapshot(store, userId, hp, watchEntry) {
  const wh = (store.load('weight_history.json') || {})[userId] || []; // newest-first
  const currentWeight = hp.demographics.weight;
  const weightTrend = (currentWeight != null && wh.length >= 2) ? +(currentWeight - wh[1].weight).toFixed(1) : null;

  return {
    weight: { value: currentWeight, trend: weightTrend },
    bodyFat: hp.demographics.bodyFat,
    heartRate: watchEntry?.heartRate ?? null,
    steps: watchEntry?.steps ?? null,
    stepsTarget: STEPS_TARGET,
    caloriesBurned: watchEntry?.caloriesBurned ?? null,
    sleepHours: watchEntry?.sleep ?? null,
    sleepTarget: SLEEP_TARGET_H,
    waterLiters: watchEntry?.water ?? null,
  };
}

// ─── Weekly Summary: real 7-day hit-rate across meals/water/steps/sleep ────
// All 4 read from data that's already stored (nutrition_logs.json /
// watch_data.json, both kept 90 days) — no new tracking, just a real
// aggregation across the last 7 days that didn't exist before. Deliberately
// NOT "today's raw value" for water/steps/sleep (a design reference showed
// that) — a "This Week" panel showing 3 of 4 metrics as today's single-day
// number would be misleading about what it's actually summarizing.
function buildWeeklySummary(store, userId, hp) {
  const days7 = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    days7.push(new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Cairo' }).format(d));
  }

  const nutritionByDate = {};
  ((store.load('nutrition_logs.json') || {})[userId] || []).forEach(l => { nutritionByDate[l.date] = l; });

  // newest-first per the existing dedup/sort in POST /api/watch-data — keep
  // the first (most recent sync) entry seen for each date.
  const watchByDate = {};
  ((store.load('watch_data.json') || {})[userId] || []).forEach(w => { if (!watchByDate[w.date]) watchByDate[w.date] = w; });

  const hydrationTargetL = hp.targets?.hydrationTargetL;

  let mealsDays = 0, waterDays = 0, stepsDays = 0, sleepDays = 0;
  days7.forEach(date => {
    const n = nutritionByDate[date];
    if (n && ((n.meals?.length || 0) + (n.custom?.length || 0)) > 0) mealsDays++;
    const w = watchByDate[date];
    if (w?.water != null && hydrationTargetL != null && w.water >= hydrationTargetL) waterDays++;
    if (w?.steps != null && w.steps >= STEPS_TARGET) stepsDays++;
    if (w?.sleep != null && w.sleep >= SLEEP_TARGET_H) sleepDays++;
  });

  return {
    meals: { days: mealsDays, total: 7 },
    water: { days: waterDays, total: 7 },
    steps: { days: stepsDays, total: 7 },
    sleep: { days: sleepDays, total: 7 },
  };
}

async function buildDailyBrief(store, ai, coachSummary, buildHealthProfile, userId, lang, weather) {
  const hp = buildHealthProfile(store, userId);
  if (!hp) return null;
  const hour = parseInt(new Intl.DateTimeFormat('en-US', { timeZone: 'Africa/Cairo', hour: '2-digit', hour12: false }).format(new Date()), 10);
  const timeOfDay = hour < 12 ? 'morning' : hour < 17 ? 'afternoon' : 'evening';

  const watch = (store.load('watch_data.json') || {})[userId] || [];
  const watchEntry = watch[0] || null; // most recent synced entry, newest-first
  const nutritionToday = computeNutritionToday(store, userId, hp.goals?.diet);

  const [brief, missingData] = await Promise.all([
    getBriefText(store, ai, coachSummary, hp, userId, lang),
    Promise.resolve(buildMissingDataCards(store, userId, lang)),
  ]);

  return {
    greeting: { username: hp.username, timeOfDay },
    brief,
    wellnessScore: computeWellnessScore(watchEntry, hp.targets, nutritionToday),
    missingData,
    priorities: buildPriorities(lang, hp, nutritionToday, watchEntry),
    snapshot: buildSnapshot(store, userId, hp, watchEntry),
    nutritionToday,
    savings: buildSavingsCard(store, lang),
    weather: weather || null,
    targets: hp.targets,
    riskFlags: hp.riskFlags,
    updatedAt: new Date().toISOString(),
  };
}

module.exports = { buildDailyBrief, buildMissingDataCards, buildSavingsCard, computeWellnessScore, computeNutritionToday, buildWeeklySummary, todayCairo };
