// Does the published page do what the crate says it does?
//
// `tests/ablation.rs` asserts that a guided experiment produces the outcome it
// declares. That is a claim about `codetalker-core`. This is the other half:
// that the page put in front of a reader actually reaches those configurations,
// scores them, links to them and says so. Between the two lies everything the
// crate cannot see — a renamed switch, a preset wired to the wrong scenario, a
// link that restores nothing.
//
// Run with: node .github/checks/console.mjs

import { withPage, reporter } from "./harness.mjs";

const r = reporter("console");

await r.run(() => withPage(async ({ ev, goto, logs, base }) => {
  const check = r.check;

  // ------------------------------------------------------------------ boot
  await goto(base);
  check("boot: the console is up and #fatal is hidden",
    await ev(`!document.getElementById('console').hidden &&
              document.getElementById('fatal').classList.contains('hidden')`));

  const lab = await ev(`(async () => {
    const w = await import('./pkg/codetalker_wasm.js');
    await w.default();
    const l = w.lab();
    return { steps: l.steps.length, presets: l.scenarios.length, challenges: l.challenges.length,
             outcomes: l.outcomes.map(o => o.tag),
             expectAfter: l.steps.map(s => s.expectAfter),
             presetIds: l.scenarios.map(s => s.id), presetExpect: l.scenarios.map(s => s.expect) };
  })()`);

  check("the track holds every experiment and challenge the crate ships",
    await ev(`document.querySelectorAll('.lab-track button').length`) === lab.steps + lab.challenges,
    `${lab.steps} experiments + ${lab.challenges} challenges`);
  check("every preset the crate ships has a button",
    await ev(`document.querySelectorAll('.preset').length`) === lab.presets);
  check("guided is the default first-run mode",
    await ev(`document.getElementById('mode-guided').getAttribute('aria-pressed') === 'true' &&
              !document.getElementById('lab-card').hidden`));
  // Checked against the DOM rather than by waiting for the page's own drift
  // alarm: `Log.entryAdded` is asynchronous, so reading the log here would race
  // boot and pass for the wrong reason. The alarm is still checked, at the end.
  check("every switch the crate names exists on the page",
    (await ev(`(async () => {
      const w = await import('./pkg/codetalker_wasm.js');
      await w.default();
      return w.lab().switches
        .filter(k => !document.querySelector('.switch[data-key="' + k + '"] input'));
    })()`)).length === 0,
    "missing: " + (await ev(`(async () => {
      const w = await import('./pkg/codetalker_wasm.js');
      await w.default();
      return w.lab().switches
        .filter(k => !document.querySelector('.switch[data-key="' + k + '"] input')).join();
    })()`)));

  check("every prediction the crate offers is on the form",
    await ev(`[...document.querySelectorAll('input[name=prediction]')].map(i => i.value).join()`)
      === lab.outcomes.join());

  check("first run explains what the rest of the page is", await ev(`(() => {
    const o = document.getElementById('orient');
    return !o.hidden && /live channel/.test(o.textContent) && /Predict before you apply/.test(o.textContent);
  })()`));

  // --------------------------------------------------- the full guided run
  // Predict wrongly on the first experiment and correctly after, so the scoring
  // is exercised in both directions rather than only the happy one.
  let expectedScore = 0;
  for (let i = 0; i < lab.steps; i++) {
    await ev(`document.querySelectorAll('.lab-track button')[${i}].click()`);
    const title = await ev(`document.getElementById('lab-title').textContent`);
    const before = await ev(`document.getElementById('verdict-tag').textContent`);

    check(`step ${i + 1} (${title}): beats show Predict, and Apply is disabled until one is made`,
      await ev(`(() => {
        const b = [...document.querySelectorAll('.beat')];
        return b.length === 4 && b[0].dataset.state === 'now' && b[3].dataset.state === 'todo' &&
               document.getElementById('lab-lock').disabled;
      })()`));

    check(`step ${i + 1}: the change is named as a position, not a variable`,
      await ev(`[...document.querySelectorAll('.move-chip')].length > 0 &&
                [...document.querySelectorAll('.move-chip')].every(c => / (on|off) → (on|off)$/.test(c.textContent))`),
      await ev(`[...document.querySelectorAll('.move-chip')].map(c => c.textContent).join(' / ')`));

    // Wrong on the first, right thereafter — and "right" is the crate's own
    // declared expectation, not a table copied into this file.
    const want = i === 0
      ? lab.outcomes.find((t) => t !== lab.expectAfter[0])
      : lab.expectAfter[i];
    if (i > 0) expectedScore++;
    await ev(`[...document.querySelectorAll('input[name=prediction]')]
                .find(i => i.value === ${JSON.stringify(want)}).click()`);

    check(`step ${i + 1}: Apply enables once a prediction is made`,
      await ev(`!document.getElementById('lab-lock').disabled`));

    await ev(`document.getElementById('lab-lock').click()`);
    const cls = await ev(`document.getElementById('lab-outcome').className`);
    const verdict = await ev(`document.getElementById('verdict-tag').textContent`);

    check(`step ${i + 1}: the channel produced what the experiment declares`,
      !cls.includes("drift") && verdict === lab.expectAfter[i],
      `${before} -> ${verdict}, expected ${lab.expectAfter[i]}`);
    check(`step ${i + 1}: scored ${i === 0 ? "wrong" : "right"}, as predicted`,
      cls.includes(i === 0 ? "wrong" : "right"), cls);
    check(`step ${i + 1}: beats advance to Observe and Why`,
      await ev(`(() => { const b = [...document.querySelectorAll('.beat')];
                return b[0].dataset.state === 'done' && b[2].dataset.state === 'now'; })()`));
    check(`step ${i + 1}: the debrief names an adversary and says what moved`,
      /A[1-5]/.test(await ev(`document.getElementById('lab-adversary').textContent`)) &&
      (await ev(`document.getElementById('lab-changed').textContent`)).length > 40);
  }

  check("the score line reports the right tally",
    (await ev(`document.getElementById('lab-progress').textContent`))
      .includes(`${expectedScore} of ${lab.steps}`),
    await ev(`document.getElementById('lab-progress').textContent`));

  // Experiment 1 is a null result, and saying "nothing moved" is the finding.
  await goto(base);
  await ev(`(() => { document.querySelectorAll('input[name=prediction]')[0].click();
                     document.getElementById('lab-lock').click(); })()`);
  check("a null result says so, rather than leaving the reader hunting",
    await ev(`/Nothing on the console moved/.test(document.getElementById('lab-changed').textContent)`),
    await ev(`document.getElementById('lab-changed').textContent.slice(0, 80)`));

  // ...and a real change is reported by panel name, with the transition.
  await ev(`(() => { document.querySelectorAll('.lab-track button')[2].click();
                     document.querySelectorAll('input[name=prediction]')[0].click();
                     document.getElementById('lab-lock').click(); })()`);
  check("a real change is reported by panel name and transition",
    await ev(`(() => { const t = document.getElementById('lab-changed').textContent;
      return /What moved:/.test(t) && /the verdict/.test(t) &&
             /A2 in Which adversary \\(defended → exposed\\)/.test(t); })()`),
    await ev(`document.getElementById('lab-changed').textContent.slice(0, 140)`));

  // ------------------------------------------------------------- url state
  const hash = await ev(`location.hash`);
  check("the url carries mode, step, stage and configuration",
    /m=g/.test(hash) && /s=3/.test(hash) && /st=r/.test(hash) && /c=\d{6}/.test(hash) && /k=/.test(hash),
    hash);

  await goto(base + "#m=e&c=100110&sp=1&k=x25519&a=chacha");
  check("an explore link restores switches, backend and suite",
    await ev(`(() => {
      const on = (k) => document.querySelector('.switch[data-key="'+k+'"] input').checked;
      return on('keyAgreement') && !on('aead') && !on('transport') && on('authenticate') &&
             on('ratchet') && !on('nonceReuse') &&
             document.getElementById('backend').value === 'x25519' &&
             document.getElementById('suite').value === 'chacha' &&
             document.getElementById('lab-card').hidden;
    })()`), await ev(`location.hash`));

  check("a switch that cannot act says why", await ev(`
    document.querySelector('.switch[data-key="adversaryKnowsTransport"]').classList.contains('disabled') &&
    document.querySelector('.switch[data-key="adversaryKnowsTransport"] .switch-why').textContent.length > 5`));

  await goto(base + "#m=g&s=3&st=r");
  check("a guided link opens the named experiment at its debrief",
    await ev(`!document.getElementById('lab-reveal').hidden &&
              document.getElementById('lab-progress').textContent.includes('experiment 3 of ${lab.steps}')`));

  // -------------------------------------------------------------- presets
  await goto(base);
  const presets = await ev(`(async () => {
    const out = [];
    for (const b of document.querySelectorAll('.preset')) {
      b.click();
      await new Promise(r => setTimeout(r, 20));
      out.push({ id: b.dataset.preset, pressed: b.getAttribute('aria-pressed'),
                 verdict: document.getElementById('verdict-tag').textContent,
                 explore: document.getElementById('mode-explore').getAttribute('aria-pressed') });
    }
    return out;
  })()`);
  for (const [i, p] of presets.entries()) {
    check(`preset ${p.id}: produces the verdict the crate advertises`,
      p.id === lab.presetIds[i] && p.verdict === lab.presetExpect[i],
      `${p.verdict}, expected ${lab.presetExpect[i]}`);
    check(`preset ${p.id}: marks itself active and drops to Explore`,
      p.pressed === "true" && p.explore === "true");
  }

  await ev(`document.getElementById('reset').click()`);
  check("reset returns to guided experiment 1 with the default stack",
    await ev(`(() => {
      const on = (k) => document.querySelector('.switch[data-key="'+k+'"] input').checked;
      return document.getElementById('lab-progress').textContent.startsWith('experiment 1 of') &&
             on('keyAgreement') && on('aead') && on('transport') && on('authenticate') &&
             on('ratchet') && !on('nonceReuse') && !on('adversaryKnowsTransport');
    })()`));

  // ------------------------------------------------------- layer captions
  await goto(base);
  const panels = await ev(`(async () => {
    const w = await import('./pkg/codetalker_wasm.js');
    await w.default();
    return w.explain().panels.map(p => ({ id: p.id, verdict: p.demoVerdict }));
  })()`);

  check("every layer switch carries a caption, and the Kieyoomia control does not",
    await ev(`(() => {
      const keys = [...document.querySelectorAll('.switch[data-key]')].map(e => e.dataset.key);
      return keys.filter(k => document.getElementById('why-' + k)).length === ${panels.length} &&
             !document.getElementById('why-adversaryKnowsTransport');
    })()`));

  check("captions start collapsed and toggle aria-expanded", await ev(`(() => {
    const t = document.querySelector('.why-toggle');
    const p = document.getElementById(t.getAttribute('aria-controls'));
    const shut = t.getAttribute('aria-expanded') === 'false' && p.hidden;
    t.click();
    const open = t.getAttribute('aria-expanded') === 'true' && !p.hidden;
    t.click();
    return shut && open && p.hidden;
  })()`));

  check("every caption answers the whole schema", await ev(`
    [...document.querySelectorAll('.why-panel')].every(p => {
      const dt = [...p.querySelectorAll('.why-row dt')].map(e => e.textContent);
      return dt.length === 5 && dt.includes('Job') && dt.includes('Adversary') &&
             dt.includes('1942') && dt.includes('Modern') &&
             (dt.includes('Off means') || dt.includes('On means')) &&
             [...p.querySelectorAll('.why-row dd')].every(d => d.textContent.length > 40);
    })`));

  // "Show me" is not a figure of speech.
  for (const p of panels) {
    const got = await ev(`(() => {
      const t = document.querySelector('.why-toggle[aria-controls="why-${p.id}"]');
      t.click();
      document.querySelector('#why-${p.id} .why-demo').click();
      const v = document.getElementById('verdict-tag').textContent;
      t.click();
      return v;
    })()`);
    check(`caption ${p.id}: "show me" produces the ${p.verdict} it claims`,
      got === p.verdict, `got ${got}`);
  }

  // ------------------------------------------------------------ glossary
  await goto(base);
  const terms = await ev(`(async () => {
    const w = await import('./pkg/codetalker_wasm.js');
    await w.default();
    return w.explain().glossary.length;
  })()`);
  check("the glossary lists every term the crate defines",
    await ev(`document.querySelectorAll('#glossary-list dt').length`) === terms, `${terms} terms`);
  check("every inline term resolves, is named, and is keyboard reachable", await ev(`(() => {
    const b = [...document.querySelectorAll('button.term')];
    return b.length >= 5 && b.every(x => {
      const d = x.nextElementSibling;
      return d?.classList.contains('term-def') && d.textContent.length > 40 &&
             x.getAttribute('aria-describedby') === d.id && x.tabIndex >= 0;
    });
  })()`), await ev(`document.querySelectorAll('button.term').length + " inline"`));
  check("a focused term reveals its definition", await ev(`(() => {
    const b = document.querySelector('button.term'), d = b.nextElementSibling;
    const shut = getComputedStyle(d).display === 'none';
    b.focus();
    return shut && getComputedStyle(d).display === 'block';
  })()`));

  // -------------------------------------------------- the handshake shape
  check("the authenticated handshake puts no attacker in the picture", await ev(`(() => {
    const s = document.getElementById('seq');
    return !s.classList.contains('mitm') && !/Attacker/.test(s.textContent) &&
           /pinned/.test(s.textContent) && s.querySelectorAll('.seq-beat').length === 4;
  })()`));
  check("switching authentication off redraws the peer as the attacker", await ev(`(() => {
    const flip = () => document.querySelector('.switch[data-key="authenticate"] input').click();
    flip();
    const s = document.getElementById('seq');
    const ok = s.classList.contains('mitm') && /Attacker/.test(s.textContent) &&
               /attacker/.test(document.getElementById('seq-note').textContent);
    flip();
    return ok && !document.getElementById('seq').classList.contains('mitm');
  })()`));

  check("the root key and transcript hash are collapsed, not dropped", await ev(`(() => {
    const rows = [...document.querySelectorAll('#facts-internal th')].map(e => e.textContent);
    const primary = [...document.querySelectorAll('#facts th')].map(e => e.textContent);
    return !document.querySelector('details.internals').open &&
           rows.includes('Session root key') && rows.includes('Transcript hash') &&
           !primary.includes('Session root key') && primary.includes('KEM in force');
  })()`));

  check("a focused legend key isolates its bytes and explains the field", await ev(`(() => {
    const b = [...document.querySelectorAll('#legend button')];
    b[0].focus();
    const dump = document.getElementById('hexdump');
    const lit = dump.querySelectorAll('.bytes span.lit').length;
    const dim = dump.querySelectorAll('.bytes span:not(.lit)').length;
    const text = document.getElementById('field-purpose').textContent;
    b[0].blur();
    return b.length >= 4 && lit > 0 && dim > 0 && text.length > 60 &&
           !dump.classList.contains('focusing') &&
           document.getElementById('field-purpose').textContent === '';
  })()`));

  // -------------------------------------------------- transfer challenges
  await goto(base + `#m=g&s=${lab.steps + 1}`);
  check("a challenge states a goal and withholds the answer", await ev(`(() => {
    return !document.getElementById('lab-challenge').hidden &&
           document.getElementById('lab-predict').hidden &&
           document.getElementById('challenge-brief').textContent.length > 80 &&
           document.querySelectorAll('#challenge-reqs .req').length > 0 &&
           document.getElementById('challenge-done').hidden;
  })()`));

  check("conditions tick off one at a time as the reader works", await ev(`(() => {
    const met = () => [...document.querySelectorAll('#challenge-reqs .req')]
      .filter(r => r.dataset.met === 'true').length;
    const a = met();
    document.querySelector('.switch[data-key="ratchet"] input').click();
    const b = met();
    const sel = document.getElementById('backend');
    sel.value = 'x25519'; sel.dispatchEvent(new Event('change'));
    const c = met();
    return b === a + 1 && c === b + 1 &&
           document.getElementById('challenge-state').classList.contains('solved');
  })()`), await ev(`document.getElementById('challenge-state').textContent`));

  check("solving reveals the question and the reader's own exposed rows", await ev(`(() => {
    const e = document.getElementById('challenge-exposed').textContent;
    return !document.getElementById('challenge-done').hidden &&
           document.getElementById('challenge-question').textContent.length > 40 &&
           /A3/.test(e) && /A4/.test(e) &&
           !document.getElementById('challenge-answer-box').open &&
           document.getElementById('challenge-answer').textContent.length > 200;
  })()`), await ev(`document.getElementById('challenge-exposed').textContent.slice(0, 100)`));

  await goto(base + `#m=g&s=${lab.steps + 2}`);
  check("the second challenge scores minimality, not just the verdict", await ev(`(() => {
    const met = () => [...document.querySelectorAll('#challenge-reqs .req')].map(r => r.dataset.met === 'true');
    const set = (k, on) => { const i = document.querySelector('.switch[data-key="'+k+'"] input');
                             if (i.checked !== on && !i.disabled) i.click(); };
    set('ratchet', false); set('nonceReuse', true); set('adversaryKnowsTransport', true);
    const loose = met();                       // right verdict, switches doing nothing
    set('transport', false); set('authenticate', false);
    const tight = met();                       // the smallest one
    return loose[0] && !loose[1] && tight[0] && tight[1];
  })()`), await ev(`document.getElementById('challenge-state').textContent`));

  // ------------------------------------ the whole configuration space
  await goto(base);
  const sweep = await ev(`(async () => {
    const w = await import('./pkg/codetalker_wasm.js');
    await w.default();
    const dist = {}; let threw = 0, n = 0;
    for (const backend of w.backends()) {
      for (const suite of ['aes', 'chacha']) {
        for (let mask = 0; mask < 64; mask++) {
          const aead = !!(mask & 2), transport = !!(mask & 4);
          n++;
          try {
            // Mirror run()'s masking, or this tests states the UI cannot emit.
            const r = w.transmit({
              plaintext: 'Request immediate air support at grid 214 by 0600.',
              secondMessage: 'Enemy armour massing north of the ridge line tonight.',
              backend, suite,
              keyAgreement: !!(mask & 1), aead, transport,
              authenticate: !!(mask & 8), ratchet: !!(mask & 16),
              nonceReuse: aead && !!(mask & 32),
              adversaryKnowsTransport: transport && !!(mask & 64),
            });
            dist[r.verdict] = (dist[r.verdict] || 0) + 1;
          } catch { threw++; }
        }
      }
    }
    return { n, threw, dist };
  })()`);
  check("every configuration the console can reach still runs",
    sweep.threw === 0 && sweep.n > 0, JSON.stringify(sweep));

  // Last, not first: `Log.entryAdded` arrives asynchronously, so a drift alarm
  // raised during boot is not necessarily in `logs` by the time boot returns.
  // The page logs one for any switch id, glossary term or wire-field kind the
  // crate names and it cannot resolve.
  check("no drift between the crate's names and the page's elements",
    !logs.some((l) => /which the page does not have|the glossary does not define|which nothing explains/.test(l)),
    logs.filter((l) => /does not have|does not define|nothing explains/.test(l)).join(" | "));

  check("no console errors or uncaught exceptions anywhere above",
    logs.length === 0, logs.join(" | "));
}));
