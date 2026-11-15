// SLIP-39 share making (src/js/slip39.js): splitting a master secret into
// shares, and Make shares from dice, where the user's rolls are the only
// source of randomness.
//
// Security contract: a split draws every random value from the byte source
// it is given, in the order the specification's GenerateShares draws them
// (identifier, then each split's random shares and R, group level first), and
// nothing else; with the same bytes it gives exactly the shares the reference
// implementation gives. From dice, the master secret is the first 16 or 32
// bytes of SHA-256 of the roll digits (the Key Station's hashed rolls) and
// every splitting value is read from HKDF-SHA256 of that hash, so the page
// invents nothing. Fewer rolls than the secret needs (50 for 128 bits, 100
// for 256), a character that is not a die face, an impossible threshold or
// count, and a passphrase that is not printable ASCII are refused with no
// shares.
//
// Expected values come from python-shamir-mnemonic v0.3.0 (the SLIP-0039
// reference implementation): the fixture's 19 sets with their recorded
// draws, and 5 dice sets whose SHA-256 and HKDF ran in Python's standard
// library (scripts/slip39-reference.py); and from node:crypto for the hash
// and HKDF. The shares made here also combine through the official-vector
// tested combine.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, hkdfSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { combineSlip39, parseSlip39Share, recoverSlip39, slip39DiceRollsNeeded, slip39ResplitFromDice, slip39SharesFromDice, splitSlip39 } from "../src/js/slip39.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = JSON.parse(readFileSync(join(root, "test/fixtures/slip39/reference-sets.json"), "utf8"));
const vectors = JSON.parse(readFileSync(join(root, "test/fixtures/slip39/vectors.json"), "utf8"));
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const ascii = (text) => new TextEncoder().encode(text);
const parse = (mnemonics) => mnemonics.map((mnemonic) => {
  const parsed = parseSlip39Share(mnemonic);
  assert.equal(parsed.ok, true, parsed.reason);
  return parsed.share;
});
// The reference's recorded draws, handed out in order; a request of another
// size than the next recorded draw fails the test.
const recorded = (draws) => {
  let next = 0;
  const source = (n) => {
    const draw = draws[next++];
    assert.ok(draw, "no draw left");
    assert.equal(n, draw.hex.length / 2, `draw ${next - 1} (${draw.kind}) size`);
    return Uint8Array.from(Buffer.from(draw.hex, "hex"));
  };
  source.used = () => next;
  return source;
};

for (const entry of fixture.sets) {
  test(`split reproduces the reference's shares from its own draws: ${entry.name}`, () => {
    const randomBytes = recorded(entry.draws);
    const result = splitSlip39(Buffer.from(entry.masterSecret, "hex"), {
      groupThreshold: entry.groupThreshold,
      groups: entry.groups,
      passphrase: ascii(entry.passphrase),
      iterationExponent: entry.iterationExponent,
      extendable: entry.extendable,
      randomBytes,
    });
    assert.equal(result.ok, true, result.reason);
    assert.equal(randomBytes.used(), entry.draws.length, "every draw used, none extra");
    assert.equal(result.identifier, entry.identifier);
    assert.deepEqual(result.groups, entry.mnemonics);
  });
}

for (const entry of fixture.dice) {
  test(`dice give the reference's shares end to end: ${entry.name}`, () => {
    const [threshold, count] = entry.groups[0];
    // The pool is SHA-256 of the roll digits, as node:crypto computes it.
    assert.equal(createHash("sha256").update(entry.rolls).digest("hex"), entry.pool);
    const result = slip39SharesFromDice(entry.rolls, { bytes: entry.masterSecret.length / 2, threshold, count, passphrase: ascii(entry.passphrase) });
    assert.equal(result.ok, true, result.reason);
    assert.equal(hex(result.masterSecret), entry.masterSecret);
    assert.equal(result.identifier, entry.identifier);
    assert.deepEqual(result.shares, entry.mnemonics[0]);
  });
}

test("the splitting bytes are HKDF-SHA256 of the dice hash, as node:crypto derives them", () => {
  // The 2-of-3 128-bit set draws the identifier, then R (12 bytes): 14 bytes.
  const entry = fixture.dice.find((d) => d.name === "dice 2-of-3, 128-bit");
  const stream = Buffer.from(hkdfSync("sha256", Buffer.from(entry.pool, "hex"), Buffer.alloc(0), Buffer.from("EntropyLab SLIP-39 shares"), 14));
  assert.equal(entry.draws.map((draw) => draw.hex).join(""), stream.toString("hex"));
});

test("shares from dice combine back, from any threshold subset", () => {
  const entry = fixture.dice.find((d) => d.name === "dice 5-of-7, 128-bit, extra rolls");
  const made = slip39SharesFromDice(entry.rolls, { bytes: 16, threshold: 5, count: 7 });
  const shares = parse(made.shares);
  const subsets = [];
  const pick = (start, chosen) => {
    if (chosen.length === 5) return subsets.push(chosen);
    for (let i = start; i < 7; i++) pick(i + 1, [...chosen, shares[i]]);
  };
  pick(0, []);
  assert.equal(subsets.length, 21);
  const ems = new Set(subsets.map((subset) => hex(recoverSlip39(subset).ems)));
  assert.equal(ems.size, 1);
  const combined = combineSlip39(subsets[20]);
  assert.equal(hex(combined.masterSecret), entry.masterSecret);
});

test("the same rolls always give the same shares; one more roll changes everything", () => {
  const entry = fixture.dice.find((d) => d.name === "dice 2-of-3, 128-bit");
  const again = slip39SharesFromDice(entry.rolls, { bytes: 16, threshold: 2, count: 3 });
  assert.deepEqual(again.shares, entry.mnemonics[0]);
  const more = slip39SharesFromDice(`${entry.rolls}1`, { bytes: 16, threshold: 2, count: 3 });
  assert.notEqual(hex(more.masterSecret), entry.masterSecret);
  assert.ok(more.shares.every((share, i) => share !== entry.mnemonics[0][i]));
});

test("dice: too few rolls, or anything but die faces, is refused with no shares", () => {
  const fifty = "1234561234".repeat(5);
  assert.deepEqual(slip39SharesFromDice(fifty.slice(1), { bytes: 16, threshold: 2, count: 3 }), { ok: false, reason: "too-few-rolls", have: 49, need: 50 });
  assert.equal(slip39SharesFromDice(fifty, { bytes: 16, threshold: 2, count: 3 }).ok, true);
  assert.deepEqual(slip39SharesFromDice(fifty + fifty.slice(1), { bytes: 32, threshold: 2, count: 3 }), { ok: false, reason: "too-few-rolls", have: 99, need: 100 });
  // Spaces and line breaks between rolls are allowed; other characters are not.
  assert.equal(slip39SharesFromDice(fifty.split("").join(" "), { bytes: 16, threshold: 2, count: 3 }).ok, true);
  for (const bad of [`${fifty}0`, `${fifty}7`, `${fifty}a`, `${fifty},`]) {
    const result = slip39SharesFromDice(bad, { bytes: 16, threshold: 2, count: 3 });
    assert.equal(result.reason, "not-dice", bad.slice(-1));
    assert.equal(result.position, 51);
    assert.equal(result.shares, undefined);
  }
  assert.equal(slip39SharesFromDice(fifty, { bytes: 24, threshold: 2, count: 3 }).reason, "length");
});

test("impossible splits are refused with no shares", () => {
  const ms = new Uint8Array(16).fill(7);
  const bytes = (n) => new Uint8Array(n).fill(1);
  const cases = [
    [{ groups: [[3, 2]] }, "threshold"],
    [{ groups: [[0, 2]] }, "threshold"],
    [{ groups: [[1, 3]] }, "threshold-one"],
    [{ groups: [[2, 17]] }, "count"],
    [{ groupThreshold: 2, groups: [[2, 3]] }, "group-threshold"],
    [{ groups: Array.from({ length: 17 }, () => [1, 1]) }, "count"],
    [{ groups: [[2, 3]], passphrase: new TextEncoder().encode("café") }, "passphrase"],
    [{ groups: [[2, 3]], iterationExponent: 16 }, "iteration-exponent"],
  ];
  for (const [options, reason] of cases) {
    const result = splitSlip39(ms, { randomBytes: bytes, ...options });
    assert.equal(result.ok, false, JSON.stringify(options));
    assert.equal(result.reason, reason, JSON.stringify(options));
    assert.equal(result.groups, undefined);
  }
  for (const length of [15, 17, 66]) assert.equal(splitSlip39(new Uint8Array(length), { groups: [[2, 3]], randomBytes: bytes }).reason, "length", String(length));
});

// ── Replace these shares: a re-split of the same encrypted master secret ──

test("rolls needed follow the Key Station's table: 50, 62, 75, 87 and 100 for 16 to 32 bytes", () => {
  // app.js hodlSeedLengths: hashRolls for 128, 160, 192, 224 and 256 bits.
  assert.deepEqual([16, 20, 24, 28, 32].map(slip39DiceRollsNeeded), [50, 62, 75, 87, 100]);
});

for (const entry of fixture.resplit) {
  test(`re-split gives the reference's new shares from the same rolls: ${entry.name}`, () => {
    const [threshold, count] = entry.groups[0];
    const result = slip39ResplitFromDice(parse(entry.old), entry.rolls, { threshold, count });
    assert.equal(result.ok, true, result.reason);
    assert.equal(result.identifier, entry.identifier);
    assert.equal(result.keptIdentifier, entry.keptIdentifier);
    assert.deepEqual(result.shares, entry.mnemonics);
    // The same encrypted master secret, so every passphrase opens the same wallet as before.
    assert.equal(hex(recoverSlip39(parse(entry.mnemonics.slice(-threshold))).ems), hex(recoverSlip39(parse(entry.old)).ems));
  });
}

test("the new shares restore the original wallet with its passphrase, and another passphrase's wallet too", () => {
  const entry = fixture.resplit.find((r) => r.name.startsWith("re-split 2-of-3 (extendable, passphrase)"));
  const base = fixture.sets.find((set) => set.name === entry.base);
  const fresh = parse(entry.mnemonics.slice(1, 4));
  assert.equal(hex(combineSlip39(fresh, ascii(base.passphrase)).masterSecret), base.masterSecret);
  assert.equal(hex(combineSlip39(fresh, ascii("another passphrase")).masterSecret), hex(combineSlip39(parse(entry.old), ascii("another passphrase")).masterSecret));
});

test("an old share never combines with the new ones", () => {
  for (const entry of fixture.resplit) {
    const [threshold] = entry.groups[0];
    const mixed = parse([entry.old[0], ...entry.mnemonics.slice(0, threshold - 1)]);
    assert.equal(recoverSlip39(mixed).ok, false, entry.name);
  }
});

test("re-split: too few rolls for the secret's length, a set that does not combine, or an impossible split makes nothing", () => {
  const wide = fixture.resplit.find((r) => r.name.startsWith("re-split 2-of-2 (192-bit"));
  assert.deepEqual(slip39ResplitFromDice(parse(wide.old), wide.rolls.slice(0, 74), { threshold: 2, count: 3 }), { ok: false, reason: "too-few-rolls", have: 74, need: 75 });
  const badDigest = parse(vectors[12][1]);
  const refused = slip39ResplitFromDice(badDigest, wide.rolls, { threshold: 2, count: 3 });
  assert.equal(refused.reason, "digest");
  assert.equal(refused.shares, undefined);
  assert.equal(slip39ResplitFromDice(parse(wide.old), wide.rolls, { threshold: 4, count: 3 }).reason, "threshold");
  assert.equal(slip39ResplitFromDice(parse(wide.old), `${wide.rolls}x`, { threshold: 2, count: 3 }).reason, "not-dice");
});
