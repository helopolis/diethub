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

// "Lose weight" and "lose fat" (same for gain) aren't the same goal in real
// sports nutrition: fat loss specifically means a gentler deficit plus a
// real protein bump to protect lean mass while cutting, and lean muscle
// gain means a smaller, cleaner surplus (to limit fat gain) plus the same
// protein bump to actually support the muscle being built - versus generic
// weight loss/gain, which doesn't care about body composition either way.
// Previously only 3 goals existed (lose/maintain/gain) and none of them
// affected protein at all, only calories.
const GOAL_TYPES = ['lose_weight', 'lose_fat', 'maintain', 'gain_weight', 'gain_muscle'];
// Accounts that picked a goal before this expansion stored the old 2-value
// scheme - normalized forward to the general variant of each direction
// (not silently reinterpreted as the fat/muscle-specific one, which would
// change their calorie target without them having chosen that) rather than
// migrated in the DB, so this never needs a one-time data migration.
function normalizeGoalType(v) {
  if (v === 'lose') return 'lose_weight';
  if (v === 'gain') return 'gain_weight';
  return GOAL_TYPES.includes(v) ? v : 'lose_weight';
}

// Hoisted to module scope (previously redeclared inside buildHealthProfile
// on every call) so db.js's verifyLookupTablesMatch() can compare the real,
// live values against the new goals table without a second, easily-drifting
// copy of the numbers - and so buildHealthProfile isn't reallocating the
// same two objects on every single request.
// lose_fat/gain_muscle use a gentler percentage than the generic
// lose_weight/gain_weight ones - real cutting/lean-bulk guidance favors a
// smaller deficit/surplus (protects muscle while cutting, limits fat gain
// while bulking) precisely because the protein bump below is doing the
// real work of preserving/building lean mass, not the calorie delta.
const DEFICIT_PCT = { lose_weight: -0.18, lose_fat: -0.15, maintain: 0, gain_weight: 0.12, gain_muscle: 0.10 };
// lose_fat/gain_muscle get a real protein boost on top of the diet's own
// baseline - the actual mechanism that makes them different goals rather
// than just a different calorie number.
const GOAL_PROTEIN_BOOST_PER_KG = { lose_fat: 0.3, gain_muscle: 0.3 };

// Real, scoped contraindication/caution notes — not an exhaustive clinical
// database, just the specific combinations this app can currently detect
// from medicalConditions and should not stay silent about. 'contraindicated'
// means "don't do this without direct physician sign-off"; 'caution' means
// "real risk factor, needs awareness, not an outright block."
const DIET_CONTRAINDICATIONS = {
  keto: [
    { condition: 'type1_diabetes', severity: 'contraindicated',
      ar: 'الكيتو يزيد من خطر الحماض الكيتوني السكري (DKA) عند مرضى السكري من النوع الأول. لا تبدأ هذا النظام إلا بإشراف طبيبك مباشرة.',
      en: 'Keto carries a real risk of diabetic ketoacidosis (DKA) in Type 1 diabetes. Do not start this diet without direct physician supervision.' },
    { condition: 'ckd', severity: 'caution',
      ar: 'هذا النظام يحتوي على دهون عالية وقد لا يناسب حالات الكلى المزمنة. استشر طبيبك أولاً.',
      en: 'This diet is high-fat and may not be appropriate with chronic kidney disease. Check with your doctor first.' },
  ],
  atkins: [
    { condition: 'ckd', severity: 'caution',
      ar: 'هذا النظام عالي البروتين، وقد لا يناسب حالات الكلى المزمنة التي تحتاج لتقليل البروتين. استشر طبيبك أولاً.',
      en: 'This diet is high-protein, which may not suit chronic kidney disease (often managed with protein restriction). Check with your doctor first.' },
  ],
  men: [
    { condition: 'ckd', severity: 'caution',
      ar: 'هذا النظام عالي البروتين نسبياً. استشر طبيبك إذا كان لديك مرض كلوي مزمن.',
      en: 'This diet is relatively high-protein. Check with your doctor if you have chronic kidney disease.' },
  ],
  men_40: [
    { condition: 'ckd', severity: 'caution',
      ar: 'هذا النظام عالي البروتين نسبياً. استشر طبيبك إذا كان لديك مرض كلوي مزمن.',
      en: 'This diet is relatively high-protein. Check with your doctor if you have chronic kidney disease.' },
  ],
  diabetic: [
    { condition: 'type1_diabetes', severity: 'caution',
      ar: 'هذا النظام مصمم كتوجيه عام لسكري النوع الثاني ولا يأخذ في الاعتبار جرعات الأنسولين. إذا كان لديك سكري النوع الأول، احسب الكربوهيدرات مع طبيبك لمطابقة جرعة الأنسولين، ولا تعتمد على هذا الرقم وحده.',
      en: "This plan is written as general Type 2 guidance and doesn't account for insulin dosing. If you have Type 1 diabetes, carb-count with your care team to match your insulin ratio — don't rely on this number alone." },
  ],
};

// Bilingual objects, not a pre-resolved string — same pattern bmiCategory
// already uses, since buildHealthProfile doesn't take a lang param; each
// caller/UI picks ar/en itself.
function checkDietContraindications(diet, medicalConditions) {
  const rules = DIET_CONTRAINDICATIONS[diet] || [];
  return rules
    .filter(r => (medicalConditions || []).includes(r.condition))
    .map(r => ({ condition: r.condition, severity: r.severity, ar: r.ar, en: r.en }));
}

// Infer activity level from average daily steps when the user hasn't set one.
function activityFromSteps(avgSteps) {
  if (avgSteps == null) return null;
  if (avgSteps < 5000)  return 'sedentary';
  if (avgSteps < 7500)  return 'light';
  if (avgSteps < 10000) return 'moderate';
  if (avgSteps < 12500) return 'active';
  return 'very_active';
}

// Mifflin-St Jeor — the standard resting-energy estimate when body
// composition isn't known. Estimates lean mass indirectly from age/gender/
// weight/height population averages.
function mifflinBMR({ weight, height, age, gender }) {
  if (weight == null || height == null || age == null) return null;
  return Math.round(10 * weight + 6.25 * height - 5 * age + (gender === 'female' ? -161 : 5));
}

// Lean body mass from a real measured body-fat % (the InBody field this
// form already collects) — real, not estimated. weight * (1 - bodyFat/100).
function leanBodyMass({ weight, bodyFat }) {
  if (weight == null || bodyFat == null || bodyFat <= 0 || bodyFat >= 100) return null;
  return +(weight * (1 - bodyFat / 100)).toFixed(1);
}

// Katch-McArdle (Katch & McArdle, 1996) — uses ACTUAL measured lean mass
// instead of estimating it from age/gender/height averages the way
// Mifflin-St Jeor does. More accurate whenever a real body-fat % is known
// (this is exactly why InBody-style scans report body fat % in the first
// place - it's the standard formula sports-nutrition coaches switch to the
// moment real body-composition data exists), which is why it's preferred
// below when available, with Mifflin-St Jeor as the fallback for users who
// only entered weight/height/age.
function katchMcArdleBMR(lbm) {
  if (lbm == null) return null;
  return Math.round(370 + 21.6 * lbm);
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
  // Demographic-targeted plans (see server.js MEAL_PLANS) - these are real,
  // selectable diets in the app, not just labels, so they need entries here
  // too or buildHealthProfile() silently falls back to "balanced" for them.
  diabetic:      { proteinPerKg: 1.6, lowCarb: true  },
  women:         { proteinPerKg: 1.4, lowCarb: false },
  women_40:      { proteinPerKg: 1.6, lowCarb: false }, // bone/muscle preservation
  men:           { proteinPerKg: 1.4, lowCarb: false },
  men_40:        { proteinPerKg: 1.6, lowCarb: false }, // bone/muscle preservation
  kids:          { proteinPerKg: 1.2, lowCarb: false },
};

function buildHealthProfile(store, userId) {
  const user = (store.load('users.json') || []).find(u => u.id === userId);
  if (!user) return null;
  const p = user.profile || {};

  const weight = num(p.weight), height = num(p.height), age = num(p.age);
  const gender = p.gender === 'female' ? 'female' : 'male';
  const bmi = (weight && height) ? +(weight / Math.pow(height / 100, 2)).toFixed(1) : num(p.bmi);
  const cat = bmiCategory(bmi);
  const bodyFat = num(p.bodyFat), muscleMass = num(p.muscleMass);
  const lbm = leanBodyMass({ weight, bodyFat });

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
  // Real logged exercise calories (swimming, running, whatever the watch
  // actually recorded) — averaged only over days a workout was actually
  // logged, not diluted by rest days. Used below to widen the slider's
  // safe upper bound for genuinely active users, not to change the base
  // TDEE itself (that already accounts for activity level via the
  // sedentary→very_active multiplier — adding this on top of TDEE too
  // would double-count the same exercise energy).
  const exerciseDays = recent.filter(d => num(d.caloriesBurned) > 50);
  const avgExerciseCal = exerciseDays.length
    ? Math.round(exerciseDays.reduce((a, d) => a + num(d.caloriesBurned), 0) / exerciseDays.length)
    : null;

  // ── Activity: explicit setting → inferred from steps → sedentary default ──
  const activityLevel = ACTIVITY_FACTORS[p.activityLevel] ? p.activityLevel
    : (activityFromSteps(avgSteps) || 'sedentary');

  // ── Labs (moved ahead of the calorie range below - a critical lab result
  // tightens the safe slider range, so it needs to be known first) ──
  const labList = (store.load('lab_results.json') || {})[userId] || [];
  const latestLab = labList[0] || null;
  const labAnalysis = latestLab?.analysis || null;

  // ── Energy & macro targets ──
  // Real body-fat % (InBody) → Katch-McArdle on measured lean mass, more
  // accurate than Mifflin-St Jeor's age/gender/height estimate. Falls back
  // to Mifflin-St Jeor when bodyFat wasn't provided (the optional field) -
  // same graceful-degradation pattern already used everywhere else here.
  const bmrFormula = lbm != null ? 'katch-mcardle' : 'mifflin-st-jeor';
  const bmr = lbm != null ? katchMcArdleBMR(lbm) : mifflinBMR({ weight, height, age, gender });
  const tdee = bmr ? Math.round(bmr * ACTIVITY_FACTORS[activityLevel]) : null;
  const goalType = normalizeGoalType(p.goalType);
  const floor = gender === 'female' ? 1200 : 1500; // don't recommend unsafe deficits
  const medicalConditions = Array.isArray(p.medicalConditions) ? p.medicalConditions : [];
  // Real safety override, not just a UI warning: a calorie deficit/surplus
  // computed from an adult-only BMR formula (Mifflin-St Jeor was never
  // validated for children) has no business being applied to a minor's
  // account, and a deficit goal during pregnancy/breastfeeding is contrary
  // to well-established prenatal nutrition guidance. Rather than invent a
  // pediatric-specific formula I can't verify, this removes the specific
  // dangerous mechanism: minors and pregnant/breastfeeding users always get
  // 'maintain' (0% delta) regardless of what goalType is stored, full stop.
  const isMinor = age != null && age < 18;
  const isPregnantOrBreastfeeding = medicalConditions.includes('pregnant') || medicalConditions.includes('breastfeeding');
  // Found by stress-testing BMI 15, not by inspection: nothing previously
  // stopped an already-underweight user from being recommended a further
  // deficit just because 'lose' is the system's own default goalType for
  // any account that never explicitly chose one. Same override mechanism as
  // minors/pregnancy — direction (lose vs. gain) needs a real clinician's
  // judgment, so this removes the deficit rather than guessing 'gain' for
  // every underweight cause (which can include ones a "just eat more"
  // default would be equally wrong for). Matches both lose_weight and
  // lose_fat - being underweight and choosing the fat-loss-specific goal is
  // exactly as unsafe as choosing the generic one.
  const isUnderweightAndLosing = cat?.key === 'underweight' && goalType.startsWith('lose');
  const goalSafetyOverride = isMinor
    ? 'age_under_18'
    : isPregnantOrBreastfeeding
    ? 'pregnancy_or_breastfeeding'
    : isUnderweightAndLosing
    ? 'underweight_bmi'
    : null;
  const effectiveGoalType = goalSafetyOverride ? 'maintain' : goalType;
  // Percentage-based deficit/surplus, not a flat ±500 kcal — a fixed amount
  // is a much bigger relative hit for someone with a 1,700 kcal TDEE than a
  // 4,000 kcal one. 18%/12% were chosen because the app's own prior fixed
  // -500 landed at ~18% for a typical TDEE, which real-world testing here
  // had already validated as a sensible moderate deficit — this just makes
  // that same ratio scale correctly instead of staying a flat number.
  let recommendedCalorieTarget = null;
  if (tdee) {
    if (goalSafetyOverride) {
      // Found by stress-testing age 5, not by inspection: the adult
      // 1200/1500 floor exists to stop a DEFICIT going unsafely low — it
      // was never meant to apply when there's no deficit at all. A young
      // child's real TDEE can genuinely sit below that adult floor (e.g.
      // ~1000 kcal), and clamping their maintenance target UP to 1500
      // would silently recommend systematic overfeeding. In override mode
      // the delta is always 0 by construction, so the target is just TDEE
      // itself — no floor involved, because there's nothing to floor.
      recommendedCalorieTarget = tdee;
    } else {
      const delta = Math.round(tdee * (DEFICIT_PCT[effectiveGoalType] ?? 0));
      recommendedCalorieTarget = Math.max(tdee + delta, floor);
    }
  }

  // ── Calorie slider range ──
  // Real, bounded safe range the user can move the slider within - not an
  // unlimited slider. Upper bound gets real extra room when the watch has
  // actually logged real exercise calories, but only partial credit (0.7x,
  // capped) - fitness trackers routinely overestimate workout burn, so
  // crediting it 1:1 risked eating back the whole deficit on workout days.
  // This is the "swimmer/runner gets more room" personalization, driven by
  // real wearable data rather than a guessed sport-type multiplier. A
  // critical lab flag overrides everything else and pulls the range in
  // tight around maintenance, per the same "labs are decision-support,
  // apply real guardrails" principle already used for the AI coach's
  // system prompt.
  const EXERCISE_CREDIT_RATIO = 0.7;
  const EXERCISE_CREDIT_CAP = 400;
  let calorieMin = null, calorieMax = null;
  if (tdee) {
    const hasCriticalLab = labAnalysis?.status === 'critical';
    if (goalSafetyOverride) {
      // Same tight-band treatment as a critical lab flag — a minor or
      // pregnant/breastfeeding user shouldn't be able to manually drag the
      // slider back into deficit territory just because the default
      // recommendation was overridden; the whole safe range narrows too.
      // Uses a low, universal sanity floor (not the adult gender `floor`
      // above) — found by stress-testing age 5: a child's real TDEE can
      // legitimately sit below the 1200/1500 adult floor, and using that
      // floor here produced calorieMin > calorieMax (an inverted, broken
      // range) whenever tdee + 200 fell under it.
      calorieMin = Math.max(tdee - 200, 600);
      calorieMax = tdee + 200;
    } else if (hasCriticalLab) {
      calorieMin = Math.max(tdee - 250, floor);
      calorieMax = tdee + 250;
    } else {
      const exerciseCredit = avgExerciseCal ? Math.min(Math.round(avgExerciseCal * EXERCISE_CREDIT_RATIO), EXERCISE_CREDIT_CAP) : 0;
      calorieMin = Math.max(tdee - 750, floor);
      calorieMax = tdee + 500 + exerciseCredit;
    }
  }

  // "Preferred zone" — a tighter band around the actual recommendation,
  // separate from the full safe min/max — so the UI can show users where
  // they should usually aim, not just the outer limits they shouldn't cross.
  let preferredCalorieMin = null, preferredCalorieMax = null;
  if (recommendedCalorieTarget && calorieMin != null) {
    preferredCalorieMin = Math.max(recommendedCalorieTarget - 150, calorieMin);
    preferredCalorieMax = Math.min(recommendedCalorieTarget + 150, calorieMax);
  }

  // ── Two modes: DietHub's recommendation, or the user's own choice within
  // the safe range above. Custom value is always clamped server-side - the
  // slider's own min/max keeps the UI honest, but a client could still send
  // an out-of-range number directly, so this is the real enforcement point. ──
  const calorieMode = p.calorieMode === 'custom' ? 'custom' : 'recommended';
  let calorieTarget = recommendedCalorieTarget;
  const customCalorieTarget = num(p.customCalorieTarget);
  if (calorieMode === 'custom' && customCalorieTarget != null && calorieMin != null) {
    calorieTarget = Math.min(Math.max(customCalorieTarget, calorieMin), calorieMax);
  }

  const dietMeta = DIET_META[p.diet] || DIET_META.balanced;
  // lose_fat/gain_muscle get a real protein boost on top of the diet's own
  // baseline (capped, not stacked without limit) - this is the actual
  // mechanism that makes them different goals rather than just a different
  // calorie number: preserving muscle while cutting or building it while
  // bulking both come down to hitting real protein, standard sports-
  // nutrition range being ~1.8-2.2g/kg once that's the explicit goal.
  const effectiveProteinPerKg = Math.min((dietMeta.proteinPerKg || 1.4) + (GOAL_PROTEIN_BOOST_PER_KG[effectiveGoalType] || 0), 2.2);
  // Protein need scales with the tissue that actually uses it (muscle),
  // not total body weight — real sports-nutrition practice once lean mass
  // is known (fat mass doesn't need dietary protein to maintain itself the
  // way muscle does). Falls back to total-weight-based (the original
  // behavior) when bodyFat wasn't provided.
  const proteinTargetG = lbm != null ? Math.round(lbm * effectiveProteinPerKg)
    : weight ? Math.round(weight * effectiveProteinPerKg) : null;
  // Creatine draws water into muscle cells - real, commonly cited guidance
  // is extra water intake while supplementing with it, not just the normal
  // weight-based target. takesCreatine is the one real, minimal supplement
  // signal this collects (matching what the form actually asks), not a
  // full supplement-interaction catalog.
  const takesCreatine = !!p.takesCreatine;
  let hydrationTargetL = weight ? +(weight * 0.035).toFixed(1) : null;
  if (takesCreatine && hydrationTargetL != null) hydrationTargetL = +(hydrationTargetL + 0.6).toFixed(1);

  // ── Nutrition adherence: last 7 days ──
  const logs = (store.load('nutrition_logs.json') || {})[userId] || [];
  const loggedDaysLast7 = new Set(
    logs.filter(l => (Date.now() - new Date(l.date)) / 86400000 <= 7).map(l => l.date)
  ).size;

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
  // Real data-integrity check, not a clinical claim: muscle mass can't
  // physically equal or exceed total body weight. Catches a mis-typed
  // InBody reading (kg vs % confusion is the common real mistake) instead
  // of silently feeding a bad number into the targets above.
  if (takesCreatine) {
    flags.push(flag('supplement', 'info',
      `تتناول كرياتين — تم رفع هدف الماء إلى ${hydrationTargetL ?? '؟'} لتر، وتأكد من الوصول لهدف البروتين ${proteinTargetG ?? '؟'} جم يومياً`,
      `Taking creatine — water target raised to ${hydrationTargetL ?? '?'}L, make sure you're hitting your ${proteinTargetG ?? '?'}g protein target daily`));
  }
  if (muscleMass != null && weight != null && muscleMass >= weight) {
    flags.push(flag('body_comp', 'warning', 'كتلة العضلات المُدخلة أكبر من أو تساوي الوزن الكلي — تحقق من الرقم', 'Entered muscle mass is >= total weight — please double-check this value'));
  }

  return {
    userId, username: user.username, plan: user.plan, lang: user.lang || 'ar',
    demographics: { age, gender, height, weight, bmi, bmiCategory: cat, bodyFat, muscleMass, leanBodyMass: lbm },
    // Raw, non-defaulted gender — demographics.gender above defaults an
    // unset value to 'male' for BMI-formula purposes (some sex has to be
    // assumed to produce a number). Reusing that default to gate a
    // female-only feature like cycle tracking would silently show it to no
    // one who hasn't explicitly set their gender, or worse, hide it
    // incorrectly — same reasoning already applied in server.js's
    // demographic-layered supplement recommendations.
    genderRaw: p.gender === 'female' || p.gender === 'male' ? p.gender : null,
    goals: {
      diet: p.diet || 'atkins', goalType, targetWeight: num(p.targetWeight), budget: num(p.budget) || 200, activityLevel, takesCreatine,
      cycleTrackingEnabled: !!p.cycleTrackingEnabled, lastPeriodStart: p.lastPeriodStart || null, cycleLength: p.cycleLength || 28,
    },
    allergies: Array.isArray(p.allergies) ? p.allergies : [],
    customAllergyText: p.customAllergyText || '',
    medicalConditions: Array.isArray(p.medicalConditions) ? p.medicalConditions : [],
    dietWarnings: checkDietContraindications(p.diet || 'atkins', p.medicalConditions),
    targets: {
      bmr, bmrFormula, tdee, proteinTargetG, hydrationTargetL,
      calorieMode, calorieTarget, recommendedCalorieTarget,
      calorieMin, calorieMax, preferredCalorieMin, preferredCalorieMax,
      deficitPct: tdee ? Math.round((DEFICIT_PCT[effectiveGoalType] ?? 0) * 100) : null,
      // goalType above (in `goals`) is what the user selected; this is what
      // was actually applied — they differ only when goalSafetyOverride is
      // set, in which case the UI should tell the user why their selected
      // goal isn't reflected in their calorie target.
      goalSafetyOverride,
    },
    nutrition: { loggedDaysLast7, lastLoggedDate: logs[0]?.date || null },
    wearable: recent.length ? { source: recent[0].source, latestDate: recent[0].date, avgSteps, avgSleepH: avgSleep, latestHeartRate: latestHR, avgExerciseCal } : null,
    labs: latestLab ? { date: latestLab.date, status: labAnalysis?.status || null, analysis: labAnalysis } : null,
    riskFlags: flags,
    updatedAt: new Date().toISOString(),
  };
}

function flag(type, severity, ar, en) { return { type, severity, ar, en }; }

// Render the unified profile as a briefing for the AI coach (ar or en, per
// the resolved AI language — see ai_language.js), so it can reference the
// user's real numbers and flags instead of giving generic advice. English
// labels below are direct translations of the existing Arabic ones (same
// real diet/goal/activity-level set already used at registration — see
// RegisterScreen.js's DIET_OPTIONS/GOAL_OPTIONS), not new business data.
const DIET_AR = { atkins:'أتكينز', keto:'كيتو', lowcarb:'قليل الكربوهيدرات', highprotein:'عالي البروتين', mediterranean:'متوسطي', balanced:'متوازن', diabetic:'مرضى السكري', women:'المرأة', women_40:'المرأة فوق الأربعين', men:'الرجل', men_40:'الرجل فوق الأربعين', kids:'الأطفال' };
// lose/gain kept for any caller still passing the pre-expansion 2-value
// scheme (coachSummary's `g.goalType` comes from buildHealthProfile's
// `goals`, which is already normalizeGoalType()'d, but this map is also
// generic enough other callers could reach it directly) - real 5-goal set
// otherwise.
const GOAL_AR = { lose_weight:'إنقاص الوزن', lose_fat:'حرق الدهون', maintain:'الحفاظ على الوزن', gain_weight:'زيادة الوزن', gain_muscle:'بناء العضلات', lose:'إنقاص الوزن', gain:'زيادة الوزن' };
const ACTIVITY_AR = { sedentary:'قليل الحركة', light:'نشاط خفيف', moderate:'نشاط متوسط', active:'نشيط', very_active:'نشيط جداً' };
const DIET_EN = { atkins:'Atkins', keto:'Keto', lowcarb:'Low-Carb', highprotein:'High-Protein', mediterranean:'Mediterranean', balanced:'Balanced', diabetic:'Diabetic', women:'Women', women_40:'Women 40+', men:'Men', men_40:'Men 40+', kids:'Kids' };
const GOAL_EN = { lose_weight:'Lose Weight', lose_fat:'Lose Fat', maintain:'Maintain Weight', gain_weight:'Gain Weight', gain_muscle:'Build Muscle', lose:'Lose Weight', gain:'Gain Weight' };
const ACTIVITY_EN = { sedentary:'Sedentary', light:'Lightly Active', moderate:'Moderately Active', active:'Active', very_active:'Very Active' };

// `lang` defaults to 'ar' to preserve every existing caller's real behavior
// unchanged unless it explicitly opts into 'en' — see ai_language.js for the
// actual resolution chain callers should use to pick the value they pass in.
function coachSummary(hp, lang = 'ar') {
  if (!hp) return '';
  const en = lang === 'en';
  const d = hp.demographics, g = hp.goals, t = hp.targets, w = hp.wearable, L = hp.labs;
  const DIET = en ? DIET_EN : DIET_AR, GOAL = en ? GOAL_EN : GOAL_AR, ACTIVITY = en ? ACTIVITY_EN : ACTIVITY_AR;
  const lines = [];
  lines.push(en ? `Name: ${hp.username}` : `الاسم: ${hp.username}`);
  lines.push(en
    ? `Age: ${d.age ?? 'unspecified'} · Gender: ${d.gender === 'female' ? 'female' : 'male'} · Height: ${d.height ?? '?'} cm · Weight: ${d.weight ?? '?'} kg`
    : `العمر: ${d.age ?? 'غير محدد'} · الجنس: ${d.gender === 'female' ? 'أنثى' : 'ذكر'} · الطول: ${d.height ?? '؟'} سم · الوزن: ${d.weight ?? '؟'} كجم`);
  if (d.bmi != null) lines.push(en
    ? `BMI: ${d.bmi}${d.bmiCategory ? ' (' + d.bmiCategory.en + ')' : ''}`
    : `مؤشر كتلة الجسم: ${d.bmi}${d.bmiCategory ? ' (' + d.bmiCategory.ar + ')' : ''}`);
  // Real InBody data, when the user provided it - only appears when present,
  // same optional-field pattern as everything else here. This is what lets
  // the coach actually reference body composition instead of just weight.
  if (d.bodyFat != null || d.muscleMass != null) {
    const parts = [];
    if (en) {
      if (d.bodyFat != null) parts.push(`body fat ${d.bodyFat}%`);
      if (d.muscleMass != null) parts.push(`muscle mass ${d.muscleMass} kg`);
      if (d.leanBodyMass != null) parts.push(`lean body mass ${d.leanBodyMass} kg`);
      lines.push(`Body composition (InBody): ${parts.join(' · ')}`);
    } else {
      if (d.bodyFat != null) parts.push(`نسبة الدهون ${d.bodyFat}%`);
      if (d.muscleMass != null) parts.push(`كتلة العضلات ${d.muscleMass} كجم`);
      if (d.leanBodyMass != null) parts.push(`الكتلة الخالية من الدهون ${d.leanBodyMass} كجم`);
      lines.push(`تكوين الجسم (InBody): ${parts.join(' · ')}`);
    }
  }
  lines.push(en
    ? `Diet: ${DIET[g.diet] || g.diet} · Goal: ${GOAL[g.goalType] || g.goalType} · Activity: ${ACTIVITY[g.activityLevel] || g.activityLevel} · Budget: ${g.budget} EGP/day`
    : `النظام: ${DIET[g.diet] || g.diet} · الهدف: ${GOAL[g.goalType] || g.goalType} · النشاط: ${ACTIVITY[g.activityLevel] || g.activityLevel} · الميزانية: ${g.budget} جنيه/يوم`);
  // Best-effort, not mechanically enforced like FOOD_DB/weather filtering —
  // this only works if the AI actually follows the instruction, so it's
  // phrased as a hard constraint rather than a mention, but it can't be
  // guaranteed the way a real code filter can.
  const allergyList = [...(hp.allergies || []), ...(hp.customAllergyText ? [hp.customAllergyText] : [])];
  if (allergyList.length) lines.push(en
    ? `STRICT ALLERGY CONSTRAINT — the user is allergic to: ${allergyList.join(', ')}. NEVER suggest, recommend, or include any food or recipe containing these, under any circumstance.`
    : `قيد حساسية صارم — المستخدم لديه حساسية من: ${allergyList.join('، ')}. لا تقترح أو توصي أو تُدرج أبداً أي طعام أو وصفة تحتوي على هذه المكونات، مهما كان السياق.`);
  if (t.calorieTarget) {
    const modeNote = t.calorieMode === 'custom'
      ? (en ? ` (the user chose this number themselves, safe range ${t.calorieMin}-${t.calorieMax})` : ` (المستخدم اختار هذا الرقم بنفسه، النطاق الآمن ${t.calorieMin}-${t.calorieMax})`)
      : '';
    const pctNote = t.deficitPct
      ? (en ? ` (${t.deficitPct > 0 ? 'surplus' : 'deficit'} ${Math.abs(t.deficitPct)}%)` : ` (${t.deficitPct > 0 ? 'فائض' : 'عجز'} ${Math.abs(t.deficitPct)}%)`)
      : '';
    lines.push(en
      ? `Estimated need: ${t.tdee} kcal · Daily target: ${t.calorieTarget} kcal${pctNote}${modeNote}`
      : `الاحتياج التقديري: ${t.tdee} سعرة · الهدف اليومي: ${t.calorieTarget} سعرة${pctNote}${modeNote}`);
  }
  if (t.proteinTargetG) lines.push(en
    ? `Protein target: ${t.proteinTargetG} g/day · Water target: ${t.hydrationTargetL} L${g.takesCreatine ? ' (raised for creatine use)' : ''}`
    : `هدف البروتين: ${t.proteinTargetG} جم/يوم · هدف الماء: ${t.hydrationTargetL} لتر${g.takesCreatine ? ' (مرفوع بسبب الكرياتين)' : ''}`);
  if (w) lines.push(en
    ? `Wearable data (7-day avg): steps ${w.avgSteps ?? '?'} · sleep ${w.avgSleepH ?? '?'}h · heart rate ${w.latestHeartRate ?? '?'}${w.avgExerciseCal ? ' · calories burned exercising (avg on training days) ' + w.avgExerciseCal : ''}`
    : `بيانات الساعة (متوسط 7 أيام): خطوات ${w.avgSteps ?? '؟'} · نوم ${w.avgSleepH ?? '؟'} ساعة · نبض ${w.latestHeartRate ?? '؟'}${w.avgExerciseCal ? ' · سعرات تمرين محروقة (متوسط أيام التمرين) ' + w.avgExerciseCal : ''}`);
  if (L) lines.push(en
    ? `Latest labs (${L.date}): status ${L.status || 'unanalyzed'}${L.analysis?.analysis_en ? ' — ' + L.analysis.analysis_en : ''}`
    : `آخر تحاليل (${L.date}): الحالة ${L.status || 'غير محللة'}${L.analysis?.analysis_ar ? ' — ' + L.analysis.analysis_ar : ''}`);
  lines.push(en
    ? `Logging consistency: ${hp.nutrition.loggedDaysLast7} of the last 7 days`
    : `الالتزام بالتسجيل: ${hp.nutrition.loggedDaysLast7} أيام من آخر 7`);
  if (hp.riskFlags.length) lines.push(en
    ? `Important alerts: ${hp.riskFlags.map(f => f.en).join(' · ')}`
    : `تنبيهات مهمة: ${hp.riskFlags.map(f => f.ar).join(' · ')}`);
  return lines.join('\n');
}

module.exports = { buildHealthProfile, coachSummary, bmiCategory, mifflinBMR, activityFromSteps, ACTIVITY_FACTORS, DIET_META, GOAL_TYPES, normalizeGoalType, DEFICIT_PCT, GOAL_PROTEIN_BOOST_PER_KG };
