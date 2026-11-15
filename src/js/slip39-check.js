// The Verify tab's "Check a SLIP-39 backup" panel (preview builds only). The
// user types SLIP-39 shares, one per field; slip39.js reads and combines
// them, and this panel shows what the backup restores: the master
// fingerprint and first receive addresses, to compare with the wallet. Its
// second mode tests a device's share randomness: two threshold sets from two
// throwaway wallets, compared for repeated or trivial random values.
//
// Security contract (test/slip39-check.test.mjs): the typed shares, the
// passphrase and everything combined from them live only in this closure,
// the panel's own DOM and slip39.js's buffers, which are zeroed after each
// run. None of it goes to storage, a clipboard, the console or the network;
// only the public fingerprint and addresses copy, through the app's shared
// public readouts.
// The master secret is used once, to derive the fingerprint and the
// addresses for every network, and is zeroed before anything is shown: a
// network change redraws stored public addresses. A refused set shows no
// wallet; status text names shares by field number and never repeats a
// typed word. The passphrase field shows bullets only (PassphraseVault).
// conceal() takes every typed share off the page until Show my shares;
// clear() (the panel's Clear, Clear Fields, End Session and pagehide)
// empties every field and the result.

import { SLIP39_DICE_ROLLS, combineSlip39, parseSlip39Share, slip39SharesFromDice, testSlip39Randomness, wipeSlip39 } from "./slip39.js";
import { HDKey } from "./hdkey.js";
import { addressFor } from "./addresses.js";
import { PassphraseVault, bindVaultField } from "./passphrase-vault.js";
import { publicFieldHtml, publicValueHtml } from "./public-data.js";

const ADDRESS_COUNT = 3;
const NETWORKS = ["mainnet", "testnet", "signet", "regtest"];
// Decryption runs PBKDF2 on the page's thread, and each step of the
// exponent doubles it: exponent 6 takes about two seconds.
const MAX_ITERATION_EXPONENT = 6;
const START_FIELDS = 2;
// The largest recovery set SLIP-39 allows: the group threshold and each
// member threshold are 4-bit fields, so at most 16 groups of 16 shares.
const MAX_FIELDS = 16 * 16;
const coinType = (network) => (network === "mainnet" ? 0 : 1);
const escapeHtml = (text) => String(text).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

// The app hands in its own readout builders (the Key Station's copyable
// field and its address table, with copy and QR controls), so the result
// reads like every other readout. These plain ones stand in when the panel
// is mounted on its own. `label` is English; the builder translates it.
const defaultFieldHtml = (label, value) => publicFieldHtml(escapeHtml(label), value);
const defaultAddressTableHtml = (rows) => `<ol start="0">${rows.map((row) => `<li>${publicValueHtml(row.address, { clipboard: false })}</li>`).join("")}</ol>`;

// Master fingerprint and the first m/84'/coin'/0'/0/i addresses on every
// network (coin type 1' and tb1/bcrt1 off mainnet). The SLIP-39 master
// secret is the BIP32 seed itself. Every private buffer is wiped before
// return; the caller owns and wipes the master secret.
function defaultDerive(masterSecret) {
  let master = null;
  const branches = [];
  try {
    master = HDKey.fromMasterSeed(masterSecret);
    const fingerprint = (master.fingerprint >>> 0).toString(16).padStart(8, "0");
    const addresses = {};
    for (const network of NETWORKS) {
      const coin = coinType(network);
      branches[coin] ??= master.derive(`m/84'/${coin}'/0'/0`);
      addresses[network] = [];
      for (let i = 0; i < ADDRESS_COUNT; i++) {
        const child = branches[coin].deriveChild(i);
        try {
          addresses[network].push(addressFor("p2wpkh", child.publicKey, network));
        } finally {
          child.wipePrivateData();
        }
      }
    }
    return { fingerprint, addresses };
  } finally {
    for (const branch of branches) branch?.wipePrivateData();
    master?.wipePrivateData();
  }
}

const SHARE_FAILURE = {
  "unknown-word": "Word {position} is not a SLIP-39 word.",
  length: "This has {words} words, which is not a SLIP-39 share length. Most shares have 20 words (128-bit) or 33 (256-bit); other secret sizes give lengths from 22 to 59.",
  checksum: "The checksum does not match: at least one word is wrong. It catches any three wrong words but cannot say which.",
  "group-threshold": "Its group threshold is larger than its group count: this is not a valid share.",
  padding: "Its padding bits are not zero: this is not a valid share.",
};
const FIELD_NAME = {
  identifier: "identifier (the first word or two differ)",
  extendable: "extendable flag",
  "iteration-exponent": "iteration exponent (the second word differs)",
  "group-threshold": "group threshold",
  "group-count": "group count",
  length: "length",
};
const SET_FAILURE = {
  "no-shares": "Enter the shares first.",
  mismatch: "Share {share} has a different {field} from share {first}: the shares are not from one backup.",
  "member-threshold": "The shares of group {group} disagree on how many of them are needed.",
  "duplicate-member": "Share {share} is a share of group {group} that is already entered. Enter each share once.",
  "too-few-groups": "This backup needs shares from {need} groups; these are from {have}.",
  "too-many-groups": "This backup needs shares from exactly {need} groups; these are from {have}. Remove the extra groups' shares.",
  "too-few-members": "Group {group} needs {need} shares; {have} entered.",
  "too-many-members": "Group {group} needs exactly {need} shares; {have} entered. Remove the extra ones.",
  digest: "The shares do not fit together: the digest check failed. At least one share is wrong or from another backup.",
  passphrase: "SLIP-39 passphrases use printable ASCII only: letters, digits, punctuation and spaces.",
  "iteration-exponent": "This backup's iteration exponent is {exponent}, which needs {iterations} PBKDF2 iterations. This page decrypts up to exponent {max}, so it does not freeze. The randomness test does not decrypt and works with any exponent.",
  "no-random-values": "{set} has no random values to compare: its thresholds are all 1. Make share sets that need 2 or more shares.",
};
const MAKE_FAILURE = {
  "not-dice": "Character {position} is not a die face: type only the numbers 1 to 6.",
  "too-few-rolls": "A {bits}-bit secret needs at least {need} rolls; {have} so far.",
  threshold: "You cannot need more shares than you make.",
  "threshold-one": "With one share needed, make just one: copies of a share are all the same share.",
  count: "Make between 1 and 16 shares.",
  passphrase: "SLIP-39 passphrases use printable ASCII only: letters, digits, punctuation and spaces.",
};
const PATTERN_TEXT = {
  zero: "{value} in {set} is all zero bytes.",
  "repeated-byte": "{value} in {set} is one byte repeated.",
  "repeated-block": "{value} in {set} is a short block of bytes repeated.",
  counter: "{value} in {set} counts in fixed steps.",
};

function sayWith(translate) {
  // A translation may or may not fill {placeholders}; fill any it leaves.
  return (text, vars) => {
    const translated = String(translate(text, vars) ?? "");
    if (!vars) return translated;
    return translated.replace(/\{(\w+)\}/g, (match, name) => (Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match));
  };
}

export function mountSlip39Check(host, {
  translate = (text) => text,
  derive = defaultDerive,
  testRandomness = testSlip39Randomness,
  // A private value's markup: the app's (data-private-value, no selection).
  privateValue = (value) => escapeHtml(value),
  fieldHtml = defaultFieldHtml,
  addressTableHtml = defaultAddressTableHtml,
  maxIterationExponent = MAX_ITERATION_EXPONENT,
  network = () => "mainnet",
  doc = document,
} = {}) {
  const say = sayWith(translate);
  // Text set once is kept as a function, so retranslate() can set it again
  // in the new language.
  const live = new Map();
  const T = (text, vars) => () => say(text, vars);
  const apply = (node, name, value) => {
    if (name === "text") node.textContent = value;
    else if (name === "class") node.className = value;
    else if (name === "hidden") node.hidden = !!value;
    else node.setAttribute(name, value);
  };
  const relabel = (node, name, text) => {
    if (!live.has(node)) live.set(node, new Map());
    live.get(node).set(name, text);
    apply(node, name, text());
  };
  const refresh = (node) => {
    for (const [name, text] of live.get(node) ?? []) apply(node, name, text());
  };
  const forget = (node) => {
    live.delete(node);
    for (const child of node.children ?? []) forget(child);
  };
  const make = (tag, props) => {
    const node = doc.createElement(tag);
    if (props) for (const name of Object.keys(props)) {
      if (typeof props[name] === "function") relabel(node, name, props[name]);
      else apply(node, name, props[name]);
    }
    return node;
  };

  // Layout follows docs/UI_Patterns.md: labels, field notes, edge notes,
  // `.row.tool-actions` action rows and `.btn` buttons.
  const mode = make("div", { class: "segmented-control", id: "slip39-check-mode", role: "group", "aria-label": T("What to do") });
  const modeButtons = [["backup", "Check a backup"], ["randomness", "Test share randomness"], ["make", "Make shares from dice"]].map(([value, text]) => {
    const button = make("button", { type: "button", class: "tab", "data-value": value, "aria-pressed": "false", text: T(text) });
    mode.appendChild(button);
    return button;
  });

  const lists = {};
  const shareList = (set) => {
    const container = make("div", { id: `slip39-check-shares-${set}` });
    const add = make("button", { type: "button", class: "btn secondary", id: `slip39-check-add-${set}`, text: T("Add a share") });
    lists[set] = { container, add, entries: [] };
    add.onclick = () => addField(set);
    return { container, add };
  };

  const backupPanel = make("div", { id: "slip39-check-backup-panel" });
  const backupShares = shareList("backup");
  const backupNote = make("p", { class: "field-note", text: T("One share per field, as written: most shares have 20 or 33 words. Blank fields are skipped. Enter exactly the shares a recovery needs.") });
  const backupAddRow = make("div", { class: "row tool-actions" });
  const passLabel = make("label", { class: "field", for: "slip39-check-pass" });
  const passText = make("span", { text: T("Passphrase (optional)") });
  const passInput = make("input", { id: "slip39-check-pass", autocomplete: "off", spellcheck: "false", autocapitalize: "off", autocorrect: "off", "data-i18n-skip": "", translate: "no", placeholder: T("Enter a passphrase, or leave blank for none") });
  const passVault = new PassphraseVault();
  const passField = bindVaultField(passInput, passVault);
  const runRow = make("div", { class: "row tool-actions" });
  const runButton = make("button", { type: "button", class: "btn primary", id: "slip39-check-run", text: T("Combine shares") });

  const randomPanel = make("div", { id: "slip39-check-random-panel", hidden: true });
  const randomIntro = make("p", { class: "edge-note is-info", id: "slip39-check-random-intro", text: T("On the device, make two share sets for two different throwaway wallets, turning it off and on in between, and enter a full recovery set of each. The shares carry the random values the device split each secret with; a working generator never repeats them between wallets. This is a tripwire for generators that repeat or are broken, not proof of good randomness.") });
  const randomWarning = make("p", { class: "edge-note is-private", id: "slip39-check-random-warning", text: T("Use throwaway wallets only. Never enter shares of a wallet that holds, or will hold, funds. No passphrase is needed.") });
  const setALabel = make("p", { class: "label section-band", text: T("First wallet's shares") });
  const setA = shareList("a");
  const setAAddRow = make("div", { class: "row tool-actions" });
  const setBLabel = make("p", { class: "label section-band", text: T("Second wallet's shares") });
  const setB = shareList("b");
  const setBAddRow = make("div", { class: "row tool-actions" });
  const compareRow = make("div", { class: "row tool-actions" });
  const compareButton = make("button", { type: "button", class: "btn primary", id: "slip39-check-compare", text: T("Compare the two sets") });

  // Make shares from dice: the rolls are the only randomness (slip39.js).
  const makePanel = make("div", { id: "slip39-check-make-panel", hidden: true });
  const makeIntro = make("p", { class: "edge-note is-info", id: "slip39-check-make-intro", text: T("Roll a fair six-sided die and type every roll. The rolls are the only randomness: they become the master secret and every value the split needs, so no device's random number generator is trusted. Then restore your hardware wallet from these shares.") });
  const sizeControl = make("div", { class: "segmented-control", id: "slip39-check-make-size", role: "group", "aria-label": T("Secret size") });
  const sizeButtons = [["16", "128-bit (20-word shares)"], ["32", "256-bit (33-word shares)"]].map(([value, text]) => {
    const button = make("button", { type: "button", class: "tab", "data-value": value, "aria-pressed": "false", text: T(text) });
    sizeControl.appendChild(button);
    return button;
  });
  const diceLabel = make("label", { class: "field", for: "slip39-check-make-dice" });
  const diceName = make("span", { text: T("Dice rolls (faces 1 to 6)") });
  const diceCount = make("span", { class: "field-note", id: "slip39-check-make-count" });
  const diceCue = make("span");
  const diceInput = make("textarea", { id: "slip39-check-make-dice", rows: "3", inputmode: "numeric", spellcheck: "false", autocomplete: "off", autocapitalize: "off", autocorrect: "off", "aria-describedby": "slip39-check-make-count" });
  const numberSelect = (id, label, chosen) => {
    const field = make("label", { class: "field", for: id });
    const select = make("select", { id });
    for (let n = 1; n <= 16; n++) select.appendChild(make("option", { value: String(n), text: String(n) }));
    field.append(make("span", { text: T(label) }), select);
    select.value = String(chosen);
    return { field, select };
  };
  const thresholdChoice = numberSelect("slip39-check-make-threshold", "Shares needed to restore", 2);
  const countChoice = numberSelect("slip39-check-make-shares", "Shares to make", 3);
  const makePassLabel = make("label", { class: "field", for: "slip39-check-make-pass" });
  const makePassInput = make("input", { id: "slip39-check-make-pass", autocomplete: "off", spellcheck: "false", autocapitalize: "off", autocorrect: "off", "data-i18n-skip": "", translate: "no", placeholder: T("Enter a passphrase, or leave blank for none") });
  const makeVault = new PassphraseVault();
  const makeField = bindVaultField(makePassInput, makeVault);
  const makeRow = make("div", { class: "row tool-actions" });
  const makeButton = make("button", { type: "button", class: "btn primary", id: "slip39-check-make-run", text: T("Make shares") });

  const concealedBlock = make("div", { id: "slip39-check-concealed", hidden: true });
  const concealedNote = make("p", { class: "edge-note is-muted", text: T("Your shares were hidden when you left the page or stopped using it. Show them again to carry on.") });
  const concealedActions = make("div", { class: "row tool-actions" });
  const unconcealButton = make("button", { type: "button", class: "btn secondary", id: "slip39-check-unconceal", text: T("Show my shares") });
  // One Clear, beside whichever action is showing (layout() moves it).
  const clearButton = make("button", { type: "button", class: "btn secondary", id: "slip39-check-clear", text: T("Clear") });

  const result = make("div", { id: "slip39-check-result", "data-state": "empty" });
  // The verdict is one note, as the fee-bump check's: a headline, then the
  // findings and what was compared, when there are any.
  const status = make("div", { class: "edge-note", id: "slip39-check-status", role: "status", "aria-live": "polite", hidden: true });
  const headline = make("p");
  const headlinePlain = make("span");
  const headlineStrong = make("strong");
  // Shares made from dice, masked until Show shares.
  const madeBlock = make("div", { id: "slip39-check-made", hidden: true });
  const madeActions = make("div", { class: "row tool-actions" });
  const madeReveal = make("button", { type: "button", class: "btn secondary", id: "slip39-check-made-reveal", "aria-pressed": "false" });
  const madeList = make("div", { id: "slip39-check-made-list" });
  const madeNote = make("p", { class: "edge-note is-info", id: "slip39-check-made-note", text: T("Write each share on its own card, word for word, and keep the cards apart. Then type a recovery set back in Check a backup to make sure every copy is right. On your hardware wallet, restore from SLIP-39 (Shamir) shares.") });
  const madeCheckRow = make("div", { class: "row tool-actions" });
  const madeCheck = make("button", { type: "button", class: "btn primary", id: "slip39-check-made-check", text: T("Check my written shares") });
  const restoredBlock = make("div", { id: "slip39-check-restored", hidden: true });
  const summary = make("p", { class: "muted", id: "slip39-check-summary" });
  const fingerprintBlock = make("div", { id: "slip39-check-fingerprint" });
  const addressLabel = make("p", { class: "label", id: "slip39-check-address-label", text: T("First receive addresses (Native SegWit)") });
  const addressBlock = make("div", { id: "slip39-check-addresses" });
  const finalNote = make("p", { class: "edge-note is-info", id: "slip39-check-final", text: T("Compare the master fingerprint and the first address with your wallet. That is the final check: SLIP-39 accepts any passphrase and cannot tell you it is wrong, so only the right one gives your wallet.") });
  const findingList = make("ul", { id: "slip39-check-findings", hidden: true });
  const checkedNote = make("p", { id: "slip39-check-checked", hidden: true });

  backupAddRow.append(backupShares.add);
  runRow.append(runButton);
  passLabel.append(passText, passInput);
  backupPanel.append(backupShares.container, backupNote, backupAddRow, passLabel, runRow);
  setAAddRow.append(setA.add);
  setBAddRow.append(setB.add);
  compareRow.append(compareButton);
  randomPanel.append(randomIntro, randomWarning, setALabel, setA.container, setAAddRow, setBLabel, setB.container, setBAddRow, compareRow);
  diceCount.append(diceCue);
  diceLabel.append(diceName, diceCount, diceInput);
  makePassLabel.append(make("span", { text: T("Passphrase (optional)") }), makePassInput);
  makeRow.append(makeButton);
  makePanel.append(makeIntro, sizeControl, diceLabel, countChoice.field, thresholdChoice.field, makePassLabel, makeRow);
  madeActions.append(madeReveal);
  madeCheckRow.append(madeCheck);
  madeBlock.append(madeActions, madeList, madeNote, madeCheckRow);
  concealedActions.append(unconcealButton);
  concealedBlock.append(concealedNote, concealedActions);
  restoredBlock.append(make("hr", { class: "result-divider" }), summary, fingerprintBlock, addressLabel, addressBlock, finalNote);
  status.append(headline, findingList, checkedNote);
  result.append(status, madeBlock, restoredBlock);
  host.replaceChildren(mode, backupPanel, randomPanel, makePanel, concealedBlock, result);

  // ── State ────────────────────────────────────────────────────────────────
  let current = "backup";
  let restored = null; // { fingerprint, addresses: { network: [...] }, shape }
  let made = null; // { shares: [words], threshold, count } while shares made from dice show
  let madeShown = false;
  let size = 16;
  let concealed = false;
  const held = {}; // the fields' text while concealed, per set
  let destroyed = false;

  function currentNetwork() {
    try {
      return network();
    } catch {
      return "mainnet";
    }
  }

  // ── Share fields ─────────────────────────────────────────────────────────
  function addField(set) {
    const list = lists[set];
    if (destroyed || concealed || list.entries.length >= MAX_FIELDS) return;
    const n = list.entries.length + 1, id = `slip39-check-${set}-share-${n}`;
    // As the Key Station's seed field: the name, a line under it that counts
    // the words (and after a check, says whether the share reads), the field.
    const label = make("label", { class: "field", for: id });
    const name = make("span", { text: T("Share {n}", { n }) });
    const note = make("span", { class: "field-note", id: `${id}-status`, "data-slip39-share-status": "", "data-slip39-set": set, "data-slip39-share": String(n), hidden: true });
    const cue = make("span");
    note.append(cue);
    const field = make("textarea", { id, rows: "3", spellcheck: "false", autocomplete: "off", autocapitalize: "off", autocorrect: "off", "data-slip39-set": set, "data-slip39-share": String(n), "aria-describedby": `${id}-status` });
    const entry = { label, field, note, cue };
    field.oninput = () => {
      if (concealed) return;
      if (result.getAttribute("data-state") !== "empty") markStale(T(current === "backup" ? "The shares changed. Combine them again." : "The shares changed. Compare the sets again."));
      else countWords(entry);
    };
    label.append(name, note, field);
    list.entries.push(entry);
    list.container.append(label);
    list.add.disabled = list.entries.length >= MAX_FIELDS;
  }

  function resetList(set) {
    const list = lists[set];
    for (const { label, field } of list.entries) {
      field.value = "";
      forget(label);
      label.remove();
    }
    list.entries = [];
    list.add.disabled = false;
    while (list.entries.length < START_FIELDS) addField(set);
  }

  // A share's line: its result after a check (the shared green or red cue),
  // or else how many words it holds, as the Key Station counts a seed.
  const setNote = (entry, state, text) => {
    if (!state) return countWords(entry);
    entry.note.setAttribute("data-slip39-share-state", state);
    entry.cue.className = state === "error" ? "meta-cue is-error" : "meta-cue";
    entry.field.classList.toggle("bad", state === "error");
    relabel(entry.cue, "text", text);
    entry.note.hidden = false;
  };
  function countWords(entry) {
    const words = entry.field.value.trim().split(/\s+/).filter(Boolean).length;
    entry.note.removeAttribute("data-slip39-share-state");
    entry.cue.className = "";
    entry.field.classList.remove("bad");
    // No target: valid shares run from 20 to 59 words, so "of 33" would
    // mislead for the rarer lengths (a 160-bit share has 23).
    relabel(entry.cue, "text", T("{entered} SLIP-39 words entered", { entered: words }));
    entry.note.hidden = words === 0;
  }
  const clearNotes = () => {
    for (const list of Object.values(lists)) for (const entry of list.entries) countWords(entry);
  };

  // Reads one set's non-blank fields: the shares, their field numbers, and
  // whether any failed to read (marked on its own field).
  function readList(set) {
    const shares = [], numbers = [];
    let failed = false;
    for (const [i, entry] of lists[set].entries.entries()) {
      if (!entry.field.value.trim()) {
        setNote(entry, null);
        continue;
      }
      const parsed = parseSlip39Share(entry.field.value);
      if (!parsed.ok) {
        failed = true;
        setNote(entry, "error", T(SHARE_FAILURE[parsed.reason] ?? SHARE_FAILURE.checksum, parsed));
        continue;
      }
      const { share } = parsed;
      shares.push(share);
      numbers.push(i + 1);
      setNote(entry, "ok", T("Checksum correct. Group {group} of {groups}, member {member}; this group needs {threshold}.", { group: share.groupIndex + 1, groups: share.groupCount, member: share.memberIndex + 1, threshold: share.memberThreshold }));
    }
    return { shares, numbers, failed };
  }
  const wipeShares = (...reads) => {
    for (const read of reads) for (const share of read.shares) wipeSlip39(share);
  };

  // ── Result ───────────────────────────────────────────────────────────────
  // The headline is bold when findings or a tally follow it in the note.
  const setStatus = (className, text) => {
    status.className = className;
    const detailed = !findingList.hidden || !checkedNote.hidden;
    headline.replaceChildren(detailed ? headlineStrong : headlinePlain);
    relabel(headlinePlain, "text", detailed ? () => "" : text);
    relabel(headlineStrong, "text", detailed ? text : () => "");
    status.hidden = !text();
  };
  const setState = (state) => result.setAttribute("data-state", state);

  // The builders' markup carries the readouts' copy and QR controls; it is
  // drawn again, in the page's language, on a network or language change.
  const renderRestored = () => {
    restoredBlock.hidden = !restored;
    if (!restored) {
      relabel(summary, "text", () => "");
      fingerprintBlock.innerHTML = "";
      addressBlock.innerHTML = "";
      return;
    }
    fingerprintBlock.innerHTML = fieldHtml("Master fingerprint", restored.fingerprint);
    refresh(addressLabel);
    renderAddresses();
  };
  const renderAddresses = () => {
    if (!restored) return;
    const network = currentNetwork(), shown = restored.addresses[network] ?? restored.addresses.mainnet;
    addressBlock.innerHTML = addressTableHtml(shown.map((address, index) => ({ index, path: `m/84'/${coinType(network)}'/0'/0/${index}`, address })));
  };

  const setFindings = (items) => {
    for (const item of findingList.children) forget(item);
    findingList.replaceChildren(...items.map(([kind, text]) => make("li", { "data-slip39-finding": kind, text })));
    findingList.hidden = items.length === 0;
  };
  const setChecked = (text) => {
    relabel(checkedNote, "text", text ?? (() => ""));
    checkedNote.hidden = !text;
  };

  // The made shares, as private values: bullets until Show shares.
  const renderMade = () => {
    madeBlock.hidden = !made;
    for (const item of madeList.children) forget(item);
    if (!made) {
      madeList.replaceChildren();
      return;
    }
    relabel(madeReveal, "text", T(madeShown ? "Hide shares" : "Show shares"));
    madeReveal.setAttribute("aria-pressed", String(madeShown));
    madeList.replaceChildren(...made.shares.map((share, i) => {
      const item = make("div", { "data-slip39-made-share": String(i + 1) });
      const value = make("div", { translate: "no", "data-i18n-skip": "" });
      value.innerHTML = privateValue(madeShown ? share : "\u2022".repeat(share.split(" ").length * 4), madeShown);
      item.append(make("p", { class: "label", text: T("Share {n} of {count}", { n: i + 1, count: made.count }) }), value);
      return item;
    }));
  };

  const resetResult = () => {
    restored = null;
    made = null;
    madeShown = false;
    renderMade();
    renderRestored();
    setFindings([]);
    setChecked(null);
    setStatus("edge-note", () => "");
    setState("empty");
  };

  // A share or the passphrase changed: nothing of the last result stays.
  const markStale = (text) => {
    resetResult();
    clearNotes();
    setState("stale");
    setStatus("edge-note is-muted", text);
  };

  const fail = (text) => {
    setState("failed");
    setStatus("edge-note is-private", text);
  };

  // A refusal as text. `numbers` maps a share's place in the set to its field.
  const refusalText = (refusal, numbers = [], setName = null) => {
    const vars = {
      ...refusal,
      share: numbers[refusal.share] ?? "",
      first: numbers[0] ?? "",
      group: refusal.group === null || refusal.group === undefined ? "" : refusal.group + 1,
      iterations: refusal.exponent === undefined ? "" : (10000 * 2 ** refusal.exponent).toLocaleString("en-US"),
    };
    const text = SET_FAILURE[refusal.reason] ?? SET_FAILURE.digest;
    return () => {
      const filled = { ...vars };
      if (refusal.reason === "mismatch") filled.field = say(FIELD_NAME[refusal.field] ?? refusal.field);
      if (refusal.set) filled.set = say(refusal.set === "a" ? "The first set" : "The second set");
      const body = say(text, filled);
      const where = setName ? say(setName) : "";
      return `${where ? `${where}: ` : ""}${body} ${say("No wallet is shown.")}`;
    };
  };

  const summaryText = (shape) => () => {
    const groups = shape.groupCount === 1
      ? say("One group; {threshold} of its shares are needed.", { threshold: shape.groups[0].threshold })
      : say("{need} of {count} groups are needed; these shares are from groups {list}.", { need: shape.groupThreshold, count: shape.groupCount, list: shape.groups.map((group) => group.index + 1).join(", ") });
    const details = say("{bits}-bit master secret, identifier {identifier}, iteration exponent {exponent}.", { bits: shape.length * 8, identifier: shape.identifier, exponent: shape.iterationExponent });
    return `${groups} ${details}${shape.extendable ? ` ${say("Extendable backup.")}` : ""}`;
  };

  function runBackup() {
    if (destroyed || concealed) return;
    resetResult();
    const read = readList("backup");
    try {
      if (read.failed) return fail(T("A share could not be read. Check the marked fields. No wallet is shown."));
      if (!read.shares.length) return fail(refusalText({ reason: "no-shares" }));
      let passphrase = null, combined = null;
      try {
        passphrase = passVault.bytes();
        combined = combineSlip39(read.shares, passphrase, { maxIterationExponent });
        if (!combined.ok) return fail(refusalText(combined, read.numbers));
        const derived = derive(combined.masterSecret);
        const { masterSecret, ...shape } = combined;
        restored = { fingerprint: derived.fingerprint, addresses: derived.addresses, shape };
      } catch {
        return fail(T("These shares could not be combined. No wallet is shown."));
      } finally {
        passphrase?.fill(0);
        wipeSlip39(combined);
      }
      setState("restored");
      setStatus("edge-note is-public", T("The shares combine: every checksum and digest is correct. This is the wallet they restore."));
      relabel(summary, "text", summaryText(restored.shape));
      renderRestored();
    } finally {
      wipeShares(read);
    }
  }

  // The roll count under the dice field, as the Key Station counts rolls.
  const countRolls = () => {
    const have = (diceInput.value.match(/[1-6]/g) ?? []).length, need = SLIP39_DICE_ROLLS[size];
    diceCount.setAttribute("data-slip39-rolls", String(have));
    diceCount.setAttribute("data-slip39-rolls-needed", String(need));
    diceCue.className = have >= need ? "meta-cue" : "";
    relabel(diceCue, "text", T("{have} of {need} rolls", { have, need }));
  };
  const setSize = (next) => {
    size = next;
    for (const button of sizeButtons) button.setAttribute("aria-pressed", String(Number(button.getAttribute("data-value")) === size));
    countRolls();
  };
  // The rolls or a setting changed: the shares shown are no longer theirs.
  const makeChanged = () => {
    if (current === "make" && result.getAttribute("data-state") !== "empty") markStale(T("The rolls or a setting changed. Make the shares again."));
  };

  function runMake() {
    if (destroyed || concealed) return;
    resetResult();
    const threshold = Number(thresholdChoice.select.value), count = Number(countChoice.select.value);
    let passphrase = null, outcome = null;
    try {
      passphrase = makeVault.bytes();
      outcome = slip39SharesFromDice(diceInput.value, { bytes: size, threshold, count, passphrase });
      if (!outcome.ok) {
        const vars = { ...outcome, bits: size * 8 }, text = MAKE_FAILURE[outcome.reason] ?? MAKE_FAILURE.count;
        return fail(() => `${say(text, vars)} ${say("No shares were made.")}`);
      }
      const derived = derive(outcome.masterSecret);
      restored = { fingerprint: derived.fingerprint, addresses: derived.addresses, shape: { identifier: outcome.identifier, extendable: false, iterationExponent: 1, groupThreshold: 1, groupCount: 1, length: size, groups: [{ index: 0, threshold, members: [] }] } };
      made = { shares: outcome.shares, threshold, count, rolls: outcome.rolls };
    } catch {
      restored = null;
      made = null;
      return fail(T("The shares could not be made."));
    } finally {
      passphrase?.fill(0);
      outcome?.masterSecret?.fill(0);
    }
    setState("made");
    setStatus("edge-note is-public", T("Made {count} shares from {rolls} rolls. Any {threshold} of them restore the wallet below.", { count, rolls: made.rolls, threshold }));
    relabel(summary, "text", summaryText(restored.shape));
    renderMade();
    renderRestored();
  }

  const valueName = ({ level, group, x }) => {
    if (level === "group") return x === 254 ? say("The random part of the group-level digest share") : say("Group {group}'s group share, drawn at random", { group: x + 1 });
    return x === 254 ? say("The random part of group {group}'s digest share", { group: group + 1 }) : say("Share {member} of group {group}, drawn at random", { member: x + 1, group: group + 1 });
  };
  const setName = (set) => say(set === "a" ? "the first set" : "the second set");
  const findingText = (finding) => () => {
    switch (finding.kind) {
      case "same-backup": return say("Both sets restore the same wallet and carry the same identifier. Either they are from one backup, or the device made the same wallet twice, which a working generator never does. Make two new throwaway wallets and test again.");
      case "same-secret": return say("Both sets restore the same wallet. The test needs two different wallets; if you made two, the device repeated its secret.");
      case "same-identifier": return say("Both sets have the same identifier. A working generator does this for about 1 in 32,768 pairs of wallets: test again with two new wallets.");
      case "repeat": return say(finding.whole ? "{a} in the first set is the same as {b} in the second set ({length} bytes)." : "{a} in the first set and {b} in the second set share {length} bytes.", { a: valueName(finding.a), b: valueName(finding.b), length: finding.length });
      case "repeat-within": return say("{a} and {b} in {set} share {length} bytes.", { a: valueName(finding.a), b: valueName(finding.b), set: setName(finding.set), length: finding.length });
      case "pattern": return say(PATTERN_TEXT[finding.pattern] ?? PATTERN_TEXT.counter, { value: valueName(finding.value), set: setName(finding.set) });
      default: return say("Unrecognised finding.");
    }
  };

  function runRandomness() {
    if (destroyed || concealed) return;
    resetResult();
    const a = readList("a"), b = readList("b");
    try {
      if (a.failed || b.failed) return fail(T("A share could not be read. Check the marked fields."));
      if (!a.shares.length || !b.shares.length) return fail(T("Enter a full recovery set of each wallet's shares."));
      let outcome;
      try {
        outcome = testRandomness(a.shares, b.shares);
      } catch {
        return fail(T("These shares could not be compared."));
      }
      if (!outcome.ok) {
        // "no-random-values" names its set in the sentence; a set that does
        // not combine gets its name in front, and field numbers from its own list.
        const { set, ...refusal } = outcome;
        if (refusal.reason === "no-random-values") return fail(refusalText(outcome));
        return fail(refusalText(refusal, (set === "b" ? b : a).numbers, set ? (set === "a" ? "The first set" : "The second set") : null));
      }
      const { findings, checked } = outcome;
      setFindings(findings.map((finding) => [finding.kind, findingText(finding)]));
      setChecked(T("Random values compared: {a} from the first set ({aBytes} bytes) and {b} from the second ({bBytes} bytes). They are the random part R of each digest share, and the shares drawn at random where 3 or more are needed.", { a: checked.a.values, aBytes: checked.a.bytes, b: checked.b.values, bBytes: checked.b.bytes }));
      if (!findings.length) {
        setState("no-repeats");
        setStatus("edge-note is-public", T("Nothing repeats between the two sets and no value is a trivial pattern. The device passed this tripwire; that is not proof of good randomness."));
      } else if (findings.every((finding) => finding.kind === "same-identifier")) {
        setState("identifier-only");
        setStatus("edge-note is-info", T("No random value repeats, but the identifier does. Test again with two new throwaway wallets."));
      } else {
        setState("repeats");
        setStatus("edge-note is-private", T("These sets repeat random values or hold trivial ones, which a working generator never does. Do not trust this device's SLIP-39 backups with funds until its maker has explained the result."));
      }
    } finally {
      wipeShares(a, b);
    }
  }

  // ── Layout, conceal and clear ────────────────────────────────────────────
  const layout = () => {
    mode.hidden = concealed;
    backupPanel.hidden = concealed || current !== "backup";
    randomPanel.hidden = concealed || current !== "randomness";
    makePanel.hidden = concealed || current !== "make";
    concealedBlock.hidden = !concealed;
    (concealed ? concealedActions : { backup: runRow, randomness: compareRow, make: makeRow }[current]).append(clearButton);
    for (const button of modeButtons) button.setAttribute("aria-pressed", String(button.getAttribute("data-value") === current));
  };

  const setMode = (next) => {
    if (destroyed || concealed) return;
    current = next;
    resetResult();
    clearNotes();
    layout();
  };

  const holdsShares = () => diceInput.value !== "" || Object.values(lists).some((list) => list.entries.some((entry) => entry.field.value !== ""));
  const conceal = () => {
    if (destroyed) return;
    // Made shares go back to bullets on every trigger, typed or not.
    if (madeShown) {
      madeShown = false;
      renderMade();
    }
    if (concealed || !holdsShares()) return;
    concealed = true;
    for (const [set, list] of Object.entries(lists)) {
      held[set] = list.entries.map((entry) => entry.field.value);
      for (const entry of list.entries) entry.field.value = "";
    }
    held.dice = diceInput.value;
    diceInput.value = "";
    layout();
  };
  const unconceal = () => {
    if (destroyed || !concealed) return;
    concealed = false;
    for (const [set, list] of Object.entries(lists)) {
      for (const [i, entry] of list.entries.entries()) entry.field.value = held[set]?.[i] ?? "";
      delete held[set];
    }
    diceInput.value = held.dice ?? "";
    delete held.dice;
    layout();
  };

  const clear = () => {
    concealed = false;
    for (const set of Object.keys(held)) delete held[set];
    for (const set of Object.keys(lists)) resetList(set);
    passField.clear();
    diceInput.value = "";
    makeField.clear();
    thresholdChoice.select.value = "2";
    countChoice.select.value = "3";
    setSize(16);
    resetResult();
    layout();
  };

  for (const button of modeButtons) button.onclick = () => setMode(button.getAttribute("data-value"));
  runButton.onclick = runBackup;
  compareButton.onclick = runRandomness;
  makeButton.onclick = runMake;
  for (const button of sizeButtons) button.onclick = () => {
    setSize(Number(button.getAttribute("data-value")));
    makeChanged();
  };
  diceInput.oninput = () => {
    if (concealed) return;
    countRolls();
    makeChanged();
  };
  thresholdChoice.select.onchange = makeChanged;
  countChoice.select.onchange = makeChanged;
  makePassInput.addEventListener("input", makeChanged);
  madeReveal.onclick = () => {
    if (destroyed || concealed || !made) return;
    madeShown = !madeShown;
    renderMade();
  };
  // The written copies are checked from paper: the backup check opens empty.
  madeCheck.onclick = () => {
    if (destroyed || concealed) return;
    resetList("backup");
    setMode("backup");
  };
  unconcealButton.onclick = unconceal;
  clearButton.onclick = clear;
  // After the vault's own input listener, so the edit is in the vault.
  passInput.addEventListener("input", () => {
    if (current === "backup" && result.getAttribute("data-state") !== "empty") markStale(T("The passphrase changed. Combine the shares again."));
  });

  // The header's network picker: the addresses and their path follow it.
  const onNetwork = () => {
    if (destroyed) return;
    refresh(addressLabel);
    renderAddresses();
  };
  doc.addEventListener("hodl:network-default", onNetwork);

  for (const set of Object.keys(lists)) resetList(set);
  setSize(16);
  layout();

  return {
    clear,
    conceal,
    // A language switch sets every label again; what was typed, combined
    // and hidden stays as it was.
    retranslate() {
      if (destroyed) return;
      for (const node of live.keys()) refresh(node);
      renderMade();
      renderRestored();
    },
    destroy() {
      clear();
      destroyed = true;
      try { doc.removeEventListener("hodl:network-default", onNetwork); } catch {}
      live.clear();
      host.replaceChildren();
    },
  };
}
