// Unit tests for childBmiPercentile() (health.js) — the real CDC BMI-for-age
// percentile calculation added for the Family/Child Growth Profiles feature
// (2026-09-26). Requires health.js directly, not through server.js/db.js's
// _testables chain: this is a genuinely pure function (LMS table passed in
// as a plain argument), so it doesn't need the real database or its test
// fixture at all.
const { childBmiPercentile } = require('../../health.js');
const { CDC_BMI_AGE_LMS } = require('../../db.js');

describe('childBmiPercentile — LMS method correctness', () => {
  test('BMI exactly equal to the reference median (M) is always the 50th percentile', () => {
    // A mathematical identity of the LMS method itself, true at every age/sex -
    // this doesn't depend on the specific CDC values being "right", only on
    // the formula being implemented correctly.
    const row = CDC_BMI_AGE_LMS.find(r => r[0] === 'male' && r[1] === 120.5);
    const [, , , m] = row;
    const result = childBmiPercentile(m, 120.5, 'male', CDC_BMI_AGE_LMS);
    expect(result.percentile).toBeCloseTo(50, 1);
  });

  test('a 10-year-old boy at BMI 23 lands deep in the obese band (real clinical expectation)', () => {
    const result = childBmiPercentile(23, 120.5, 'male', CDC_BMI_AGE_LMS);
    expect(result.percentile).toBeGreaterThanOrEqual(95);
    expect(result.category.key).toBe('obese');
  });

  test('a 10-year-old boy at BMI 13 lands in the underweight band', () => {
    const result = childBmiPercentile(13, 120.5, 'male', CDC_BMI_AGE_LMS);
    expect(result.percentile).toBeLessThan(5);
    expect(result.category.key).toBe('underweight');
  });

  test('category bands follow CDC\'s real published thresholds (<5/<85/<95/>=95)', () => {
    const lowM = childBmiPercentile(4.9, 120.5, 'male', CDC_BMI_AGE_LMS); // forced low percentile via a tiny BMI
    expect(lowM.category.key).toBe('underweight');
    const row = CDC_BMI_AGE_LMS.find(r => r[0] === 'male' && r[1] === 120.5);
    const atMedian = childBmiPercentile(row[3], 120.5, 'male', CDC_BMI_AGE_LMS);
    expect(atMedian.category.key).toBe('healthy_weight');
  });

  test('interpolates between adjacent table rows for a non-exact age', () => {
    // 10 years 3 months = 123 months, between the 122.5 and 123.5 rows -
    // result should sit between what those two exact rows would each give,
    // not jump discontinuously or silently snap to the nearer one.
    const female = CDC_BMI_AGE_LMS.filter(r => r[0] === 'female');
    const before = female.find(r => r[1] === 122.5);
    const after = female.find(r => r[1] === 123.5);
    const rBefore = childBmiPercentile(17, 122.5, 'female', CDC_BMI_AGE_LMS).percentile;
    const rMid = childBmiPercentile(17, 123, 'female', CDC_BMI_AGE_LMS).percentile;
    const rAfter = childBmiPercentile(17, 123.5, 'female', CDC_BMI_AGE_LMS).percentile;
    expect(before).toBeDefined();
    expect(after).toBeDefined();
    expect(rMid).toBeGreaterThanOrEqual(Math.min(rBefore, rAfter));
    expect(rMid).toBeLessThanOrEqual(Math.max(rBefore, rAfter));
  });

  test('clamps to the table\'s own age bounds rather than extrapolating', () => {
    const belowRange = childBmiPercentile(16, 10, 'male', CDC_BMI_AGE_LMS); // 10 months old — below the table's 23.5mo floor
    const atFloor = childBmiPercentile(16, 23.5, 'male', CDC_BMI_AGE_LMS);
    expect(belowRange.percentile).toBeCloseTo(atFloor.percentile, 1);
  });

  test('returns null when required inputs are missing, never a fabricated result', () => {
    expect(childBmiPercentile(null, 120, 'male', CDC_BMI_AGE_LMS)).toBeNull();
    expect(childBmiPercentile(20, null, 'male', CDC_BMI_AGE_LMS)).toBeNull();
    expect(childBmiPercentile(20, 120, 'male', null)).toBeNull();
  });
});
