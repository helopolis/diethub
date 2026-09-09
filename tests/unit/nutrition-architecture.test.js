// Regression tests for the nutrition-architecture migration (Phases 1-4 +
// meal_overrides). Runs against a fresh, isolated scratch database
// (tests/jest.setup.js), so server.js's real initData() and db.js's real
// seedFoods/seedDiets/seedMealsFromDietPlans/migrateMealOverridesBlob all
// run for real here - this exercises the actual seeding pipeline, not a
// mock of it.
//
// Specifically covers every previously-broken substring-collision case the
// architecture audit found live in production (White Rice, White Cheese,
// Hummus, Sweet Potato, Milk, Fattah, Koshari's dead gluten tag, Mozzarella
// Cheese's undetected milk allergen), so none of them can silently regress.
const app = require('../../server.js');
const db = require('../../db.js');
const { findFoodMatch } = app._testables;

describe('Food resolution — exact-match-only, no substring collisions', () => {
  // Each pair is [query, expected canonical English name]. A regression
  // here means the substring-collision bug class (fixed by moving off
  // findFoodMatch's old "longest substring wins" algorithm) has come back.
  const previouslyBrokenCases = [
    ['بطاطا', 'sweet potato'],
    ['حمص', 'hummus'],
    ['زبادي', 'plain yogurt'],
    ['لبن', 'whole milk'],
    ['فتة', 'fattah'],
    ['كشري', 'koshari'],
    ['أرز أبيض', 'white rice, cooked'],
    ['جبنة بيضاء', 'white cheese'],
    ['جبنة موزاريلا', 'mozzarella cheese, whole milk'],
  ];
  test.each(previouslyBrokenCases)('%s resolves to itself, not a substring collision (%s)', (query, expected) => {
    const match = findFoodMatch(query);
    expect(match).not.toBeNull();
    expect(match.en).toBe(expected);
  });

  test('koshari carries its real gluten allergen (previously dead code behind a duplicate entry)', () => {
    const match = findFoodMatch('كشري');
    expect(match.allergens).toContain('gluten');
  });

  test('mozzarella cheese carries its real milk allergen (previously matched "banana" via a موز substring, zero protection)', () => {
    const match = findFoodMatch('جبنة موزاريلا');
    expect(match.allergens).toContain('milk');
  });

  test('an unresolvable query returns null, never a guessed match', () => {
    expect(findFoodMatch('a food that has never existed anywhere xyz123')).toBeNull();
  });

  test('every real food in the table resolves to itself by both Arabic and English name (the audit\'s own self-match technique, made permanent)', () => {
    const foods = db.db.prepare('SELECT * FROM foods WHERE active = 1').all();
    expect(foods.length).toBeGreaterThan(0);
    for (const food of foods) {
      expect(db.resolveFood(food.name_ar)?.id).toBe(food.id);
      expect(db.resolveFood(food.name_en)?.id).toBe(food.id);
    }
  });

  test('every alias resolves to its own food, never a different one', () => {
    const aliases = db.db.prepare('SELECT * FROM food_aliases').all();
    expect(aliases.length).toBeGreaterThan(0);
    for (const alias of aliases) {
      expect(db.resolveFood(alias.alias)?.id).toBe(alias.food_id);
    }
  });
});

describe('Diets, goals, allergens, medical conditions — real tables, not JS constants', () => {
  test('all 9 real selectable diets plus the balanced fallback exist', () => {
    const ids = db.listDiets().map(d => d.id).sort();
    expect(ids).toEqual(['atkins', 'balanced', 'diabetic', 'keto', 'kids', 'mediterranean', 'men', 'men_40', 'women', 'women_40'].sort());
  });

  test('lose_fat and gain_muscle get a real protein boost; lose_weight/gain_weight/maintain do not', () => {
    expect(db.getGoal('lose_fat').protein_boost_per_kg).toBeGreaterThan(0);
    expect(db.getGoal('gain_muscle').protein_boost_per_kg).toBeGreaterThan(0);
    expect(db.getGoal('lose_weight').protein_boost_per_kg).toBe(0);
    expect(db.getGoal('gain_weight').protein_boost_per_kg).toBe(0);
    expect(db.getGoal('maintain').protein_boost_per_kg).toBe(0);
  });

  test('the 5 goals have distinct, non-overlapping deficit percentages', () => {
    const pcts = ['lose_weight', 'lose_fat', 'maintain', 'gain_weight', 'gain_muscle'].map(id => db.getGoal(id).deficit_pct);
    expect(new Set(pcts).size).toBe(5); // all 5 genuinely different, no accidental duplicates
  });

  test('keto is contraindicated for type1_diabetes and cautioned for ckd', () => {
    const rules = db.getDietContraindications('keto', ['type1_diabetes', 'ckd']);
    const bySeverity = Object.fromEntries(rules.map(r => [r.condition_id, r.severity]));
    expect(bySeverity.type1_diabetes).toBe('contraindicated');
    expect(bySeverity.ckd).toBe('caution');
  });

  test('a diet with no contraindication rules (e.g. mediterranean) returns an empty list, not an error', () => {
    expect(db.getDietContraindications('mediterranean', ['ckd', 'type1_diabetes'])).toEqual([]);
  });

  test('all 9 KNOWN_ALLERGENS categories exist in the table', () => {
    const ids = db.listAllergens().map(a => a.id).sort();
    expect(ids).toEqual(['crustaceans', 'eggs', 'fish', 'gluten', 'milk', 'nuts', 'peanuts', 'sesame', 'soybeans'].sort());
  });

  test('the 5 post-launch medical conditions (prediabetes, gestational diabetes, hypertension, hyperlipidemia, liver disease) are real, selectable rows', () => {
    const ids = db.listMedicalConditions().map(c => c.id);
    for (const id of ['prediabetes', 'gestational_diabetes', 'hypertension', 'hyperlipidemia', 'liver_disease']) {
      expect(ids).toContain(id);
    }
  });
});

describe('Meal nutrition — computed from real ingredients, not a hand-typed number', () => {
  test('a meal\'s computed macros come from summing real per-ingredient data, not a stored blob field', () => {
    const meal = db.db.prepare("SELECT * FROM meals WHERE diet_id='keto' AND day_en='Wednesday' AND meal_type='snack'").get();
    expect(meal).toBeTruthy();
    const nutrition = db.getMealNutrition(meal.id);
    // Real per-ingredient math: olives (145 kcal/100g) + feta (264 kcal/100g)
    // at their real recipe grams should land nowhere near the old, wrongly-
    // matched-to-olive-oil figure (884 kcal/100g) the audit found live.
    expect(nutrition.cal).toBeGreaterThan(50);
    expect(nutrition.cal).toBeLessThan(300);
  });

  test('every meal has at least one recipe ingredient, and every ingredient resolves to a real food', () => {
    const meals = db.db.prepare('SELECT id FROM meals').all();
    expect(meals.length).toBeGreaterThan(0);
    for (const meal of meals) {
      const ingredients = db.getMealIngredients(meal.id);
      expect(ingredients.length).toBeGreaterThan(0);
      for (const ing of ingredients) {
        expect(ing.food_id).toBeTruthy();
        expect(ing.cal_per_100g).toBeGreaterThanOrEqual(0);
      }
    }
  });
});

describe('meal_overrides table — real per-user rows, not a shared blob', () => {
  test('a saved override round-trips exactly through get/save', () => {
    db.saveMealOverrideRow('test_user_1', '2026-01-01', 'breakfast', { meal: { nameEn: 'Test', cal: 300 }, tier: 'mid', diet: 'atkins', swapsUsed: 1, manualSwap: true });
    const row = db.getMealOverrideRow('test_user_1', '2026-01-01', 'breakfast');
    expect(row.meal.nameEn).toBe('Test');
    expect(row.tier).toBe('mid');
    expect(row.diet).toBe('atkins');
    expect(row.swapsUsed).toBe(1);
    expect(row.manualSwap).toBe(true);
  });

  test('saving again for the same (user, date, mealType) overwrites, never duplicates', () => {
    db.saveMealOverrideRow('test_user_2', '2026-01-01', 'lunch', { meal: { nameEn: 'First' }, tier: 'low', diet: 'keto', swapsUsed: 0, manualSwap: false });
    db.saveMealOverrideRow('test_user_2', '2026-01-01', 'lunch', { meal: { nameEn: 'Second' }, tier: 'high', diet: 'atkins', swapsUsed: 2, manualSwap: true });
    expect(db.getMealOverrideRow('test_user_2', '2026-01-01', 'lunch').meal.nameEn).toBe('Second');
    const count = db.db.prepare('SELECT COUNT(*) c FROM meal_overrides WHERE user_id = ? AND date = ? AND meal_type = ?').get('test_user_2', '2026-01-01', 'lunch').c;
    expect(count).toBe(1);
  });

  test('deleteAllMealOverridesForUser only removes that user\'s rows', () => {
    db.saveMealOverrideRow('test_user_3', '2026-01-01', 'dinner', { meal: { nameEn: 'Keep' }, tier: 'mid', diet: 'atkins', swapsUsed: 0, manualSwap: false });
    db.saveMealOverrideRow('test_user_4', '2026-01-01', 'dinner', { meal: { nameEn: 'Also keep' }, tier: 'mid', diet: 'atkins', swapsUsed: 0, manualSwap: false });
    db.deleteAllMealOverridesForUser('test_user_3');
    expect(db.getMealOverrideRow('test_user_3', '2026-01-01', 'dinner')).toBeNull();
    expect(db.getMealOverrideRow('test_user_4', '2026-01-01', 'dinner')).not.toBeNull();
  });
});

describe('Boot-time verification functions actually fail loudly on real mismatches', () => {
  test('verifyLookupTablesMatch throws when a JS constant disagrees with the table', () => {
    expect(() => db.verifyLookupTablesMatch({
      knownAllergens: ['milk'], // wrong: real table has 9 allergens, not 1
      knownMedicalConditions: db.listMedicalConditions().map(c => c.id),
      activityFactors: { sedentary: 1.2, light: 1.375, moderate: 1.55, active: 1.725, very_active: 1.9 },
      goalTypes: db.listGoals().map(g => g.id),
      goalDeficitPct: Object.fromEntries(db.listGoals().map(g => [g.id, g.deficit_pct])),
      goalProteinBoost: Object.fromEntries(db.listGoals().map(g => [g.id, g.protein_boost_per_kg])),
    })).toThrow(/mismatch/);
  });

  test('verifyFoodResolution passes clean on the real seeded data', () => {
    expect(() => db.verifyFoodResolution()).not.toThrow();
  });
});
