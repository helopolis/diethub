// ─── UNIFIED HEALTH PROFILE ───────────────────────────────────────────────────
// The ecosystem hub. Assembles every signal DietHub holds about a user —
// demographics, goals, nutrition logs, labs, wearables — into one object with
// derived energy/protein/hydration targets and actionable risk flags. This is
// the single source of truth the AI coach and every other module reads from,
// instead of each re-deriving the user's state from scattered stores.

function num(v) { const n = parseFloat(v); return Number.isFinite(n) ? n : null; }

function bmiCategory(bmi) {
  if (bmi == null) return null;
  if (bmi < 18.5) return { key: 'underweight', ar: 'نقص وزن',   en: 'Underweight' };
  if (bmi < 25)   return { key: 'normal',      ar: 'وزن طبيعي', en: 'Normal' };
  if (bmi < 30)   return { key: 'overweight',  ar: 'زيادة وزن', en: 'Overweight' };
  return            { key: 'obese',       ar: 'سمنة',      en: 'Obese' };
}

const ACTIVITY_FACTORS = { sedentary: 1.2, light: 1.375, moderate: 1.55, active: 1.725, very_active: 1.9 };

// Infer activity level from average daily steps when the user hasn't set one.
function activityFromSteps(avgSteps) {
  if (avgSteps == null) return null;
  if (avgSteps < 5000)  return 'sedentary';
  if (avgSteps < 7500)  return 'light';
  if (avgSteps < 10000) return 'moderate';
  if (avgSteps < 12500) return 'active';
  return 'very_active';
}

// Mifflin-St Jeor — the standard resting-energy estimate.
function mifflinBMR({ weight, height, age, gender }) {
  if (weight == null || height == null || age == null) return null;
  return Math.round(10 * weight + 6.25 * height - 5 * age + (gender === 'female' ? -161 : 5));
}

// Diet → protein target (g/kg) and whether it's a low-carb protocol (which
// drives hydration and which labs to watch).
const DIET_META = {
  atkins:        { proteinPerKg: 1.9, lowCarb: true  },
  keto:          { proteinPerKg: 1.8, lowCarb: true  },
  lowcarb:       { proteinPerKg: 1.8, lowCarb: true  },
  highprotein:   { proteinPerKg: 2.0, lowCarb: false },
  mediterranean: { proteinPerKg: 1.4, lowCarb: false },
  balanced:      { proteinPerKg: 1.4, lowCarb: false },
};

function buildHealthProfile(store, userId) {
  const user = (store.load('users.json') || []).find(u => u.id === userId);
  if (!user) return null;
  const p = user.profile || {};

  const weight = num(p.weight), height = num(p.height), age = num(p.age);
  const gender = p.gender === 'female' ? 'female' : 'male';
  const bmi = (weight && height) ? +(weight / Math.pow(height / 100, 2)).toFixed(1) : num(p.bmi);
  const cat = bmiCategory(bmi);

  // ── Wearables: last 7 days ──
  const wd = (store.load('watch_data.json') || {})[userId] || [];
  const recent = wd.slice(0, 7);
  const avgInt = (key) => {
    const v = recent.map(d => num(d[key])).filter(x => x != null);
    return v.length ? Math.round(v.reduce((a, b) => a + b, 0) / v.length) : null;
  };
  const avgSteps = avgInt('steps');
  const latestHR = recent[0] ? num(recent[0].heartRate) : null;
  const sleepVals = recent.map(d => num(d.sleep)).filter(x => x != null);
  const avgSleep = sleepVals.length ? +(sleepVals.reduce((a, b) => a + b, 0) / sleepVals.length).toFixed(1) : null;

  // ── Activity: explicit setting → inferred from steps → sedentary default ──
  const activityLevel = ACTIVITY_FACTORS[p.activityLevel] ? p.activityLevel
    : (activityFromSteps(avgSteps) || 'sedentary');

  // ── Energy & macro targets ──
  const bmr = mifflinBMR({ weight, height, age, gender });
  const tdee = bmr ? Math.round(bmr * ACTIVITY_FACTORS[activityLevel]) : null;
  const goalType = ['lose', 'maintain', 'gain'].includes(p.goalType) ? p.goalType : 'lose';
  let calorieTarget = null;
  if (tdee) {
    const delta = goalType === 'lose' ? -500 : goalType === 'gain' ? 300 : 0;
    const floor = gender === 'female' ? 1200 : 1500; // don't recommend unsafe deficits
    calorieTarget = Math.max(tdee + delta, floor);
  }
  const dietMeta = DIET_META[p.diet] || DIET_META.balanced;
  const proteinTargetG = weight ? Math.round(weight * dietMeta.proteinPerKg) : null;
  const hydrationTargetL = weight ? +(weight * 0.035).toFixed(1) : null;

  // ── Nutrition adherence: last 7 days ──
  const logs = (store.load('nutrition_logs.json') || {})[userId] || [];
  const loggedDaysLast7 = new Set(
    logs.filter(l => (Date.now() - new Date(l.date)) / 86400000 <= 7).map(l => l.date)
  ).size;

  // ── Labs ──
  const labList = (store.load('lab_results.json') || {})[userId] || [];
  const latestLab = labList[0] || null;
  const labAnalysis = latestLab?.analysis || null;

  // ── Risk flags: the actionable signals the coach should react to ──
  const flags = [];
  if (cat && cat.key === 'obese')       flags.push(flag('bmi', 'warning', `مؤشر كتلة الجسم: ${cat.ar}`, `BMI: ${cat.en}`));
  if (cat && cat.key === 'underweight') flags.push(flag('bmi', 'info', `مؤشر كتلة الجسم: ${cat.ar}`, `BMI: ${cat.en}`));
  if (labAnalysis?.status === 'critical') flags.push(flag('labs', 'critical', 'نتائج تحاليل تحتاج انتباه عاجل', 'Lab results need urgent attention'));
  else if (labAnalysis?.status === 'warning') flags.push(flag('labs', 'warning', 'بعض نتائج التحاليل خارج المعدل الطبيعي', 'Some lab values are out of range'));
  if (avgSleep != null && avgSleep < 6) flags.push(flag('sleep', 'warning', `متوسط النوم منخفض (${avgSleep} ساعة)`, `Low average sleep (${avgSleep}h)`));
  if (latestHR != null && latestHR > 100) flags.push(flag('heart_rate', 'warning', `معدل نبض مرتفع (${latestHR})`, `Elevated resting heart rate (${latestHR})`));
  if (dietMeta.lowCarb && weight != null) flags.push(flag('diet_labs', 'info', 'نظام قليل الكربوهيدرات — تابع وظائف الكلى والدهون', 'Low-carb diet — monitor kidney & lipid panels'));
  if (loggedDaysLast7 === 0)            flags.push(flag('engagement', 'info', 'لم تسجّل وجباتك هذا الأسبوع', 'No meals logged this week'));

  return {
    userId, username: user.username, plan: user.plan, lang: user.lang || 'ar',
    demographics: { age, gender, height, weight, bmi, bmiCategory: cat, bodyFat: num(p.bodyFat), muscleMass: num(p.muscleMass) },
    goals: { diet: p.diet || 'atkins', goalType, targetWeight: num(p.targetWeight), budget: num(p.budget) || 200, activityLevel },
    targets: { bmr, tdee, calorieTarget, proteinTargetG, hydrationTargetL },
    nutrition: { loggedDaysLast7, lastLoggedDate: logs[0]?.date || null },
    wearable: recent.length ? { source: recent[0].source, latestDate: recent[0].date, avgSteps, avgSleepH: avgSleep, latestHeartRate: latestHR } : null,
    labs: latestLab ? { date: latestLab.date, status: labAnalysis?.status || null, analysis: labAnalysis } : null,
    riskFlags: flags,
    updatedAt: new Date().toISOString(),
  };
}

function flag(type, severity, ar, en) { return { type, severity, ar, en }; }

module.exports = { buildHealthProfile, bmiCategory, mifflinBMR, activityFromSteps, ACTIVITY_FACTORS, DIET_META };
