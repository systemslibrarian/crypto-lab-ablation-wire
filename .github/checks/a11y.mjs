// Can the experiment be operated and interpreted without a mouse, without
// colour perception, and at 200% zoom?
//
// A teaching demo that fails any of those is not a teaching demo for the people
// it fails. This ran by hand once and found three defects — white on the accent
// measured 2.56:1 in the dark theme, on the primary action button; the muted ink
// was hairline sub-AA in both themes; the hexdump announced 136 hex pairs to a
// screen reader. The first two had shipped. It runs in CI now for that reason.
//
// Run with: node .github/checks/a11y.mjs

import { withPage, reporter, RUN_TOGETHER } from "./harness.mjs";

const r = reporter("accessibility");

/* WCAG 2.1 relative luminance and contrast, over every element that carries its
   own text rather than a hand-picked selector list. An audit that looks only
   where trouble is expected is an audit of expectations: the first pass of this
   check used a list of twenty selectors and passed while `--ink-3` was under AA
   on half the page. */
const CONTRAST = `(() => {
  const lum = (c) => {
    const [r, g, b] = c.match(/[\\d.]+/g).slice(0, 3).map(Number).map((v) => {
      v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  // Walk up for the first painted background: an element with a transparent
  // background is drawn on whatever is behind it, not on white.
  const bgOf = (el) => {
    for (let e = el; e; e = e.parentElement) {
      const b = getComputedStyle(e).backgroundColor;
      if (b && !/rgba\\(0, 0, 0, 0\\)|transparent/.test(b)) return b;
    }
    return getComputedStyle(document.body).backgroundColor || 'rgb(255,255,255)';
  };
  const ratio = (el) => {
    const a = lum(getComputedStyle(el).color), b = lum(bgOf(el));
    return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
  };
  const bad = [];
  for (const el of document.querySelectorAll('main *, .foot *, .masthead *')) {
    const own = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
    if (!own) continue;
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') continue;
    // The dump is aria-hidden and its colours are a legend, not prose; the
    // legend keys naming those colours are checked like everything else.
    if (el.closest('[aria-hidden="true"], .hexdump')) continue;
    const px = parseFloat(cs.fontSize);
    const large = px >= 24 || (px >= 18.66 && parseInt(cs.fontWeight, 10) >= 700);
    const need = large ? 3 : 4.5;
    const got = ratio(el);
    if (got < need) {
      bad.push((el.className || el.tagName) + ' ' + got.toFixed(2) + ' < ' + need +
               ' :: ' + el.textContent.trim().slice(0, 30));
    }
  }
  return bad;
})()`;

/* Put every semantic state on screen at once, so the audit sees the colours that
   only appear for a moment: a right answer, a wrong one, a drift warning, a
   solved challenge, an exposed threat row, a reused keystream. */
const SHOW_EVERY_STATE = `(() => {
  document.querySelectorAll('.why-toggle').forEach((t) => t.click());
  document.querySelectorAll('input[name=prediction]')[0].click();
  document.getElementById('lab-lock').click();
  for (const c of ['right', 'wrong', 'drift']) {
    const p = document.createElement('p');
    p.className = 'lab-outcome ' + c;
    p.textContent = 'Correct — Length and timing only.';
    document.getElementById('lab-reveal').appendChild(p);
  }
  for (const k of ['authenticate', 'ratchet', 'nonceReuse']) {
    document.querySelector('.switch[data-key="' + k + '"] input').click();
  }
  const st = document.getElementById('challenge-state');
  st.classList.add('solved');
  st.textContent = 'Solved — every condition met.';
  document.getElementById('lab-challenge').hidden = false;
})()`;

await r.run(() => withPage(async ({ ev, send, goto, base }) => {
  const check = r.check;

  // -------------------------------------------------------------- contrast
  for (const scheme of ["dark", "light"]) {
    await send("Emulation.setEmulatedMedia", {
      features: [{ name: "prefers-color-scheme", value: scheme }],
    });
    await goto(base);
    await ev(SHOW_EVERY_STATE);
    const bad = await ev(CONTRAST);
    check(`contrast: every text/background pair meets WCAG AA (${scheme})`,
      bad.length === 0, bad.slice(0, 4).join(" | "));
  }
  await send("Emulation.setEmulatedMedia", { features: [] });

  // ------------------------------------------------------- zoom and mobile
  // 200% zoom halves the CSS viewport, so 640px is the desktop-at-200% case.
  for (const [w, name] of [[640, "200% zoom (640px)"], [390, "mobile (390px)"], [320, "narrow (320px)"]]) {
    await goto(base, w, 800);
    const ok = await ev(`document.documentElement.scrollWidth <=
                         document.documentElement.clientWidth + 1`);
    check(`layout: the page does not scroll sideways at ${name}`, ok,
      await ev(`document.documentElement.scrollWidth + '/' + document.documentElement.clientWidth`));
  }
  // Wide content is allowed to scroll — inside its own box, never the page.
  await goto(base, 390, 800);
  check("layout: the hexdump scrolls inside itself rather than the page",
    await ev(`getComputedStyle(document.getElementById('hexdump')).overflowX !== 'visible'`));

  // ------------------------------------------- keyboard, with no pointer
  await goto(base);
  const kb = await ev(`(() => {
    const out = { steps: [] };
    const n = document.querySelectorAll('.lab-track button').length;
    for (let i = 0; i < 5; i++) {
      const t = document.querySelectorAll('.lab-track button')[i];
      t.focus(); t.click();
      const radio = document.querySelectorAll('input[name=prediction]')[0];
      radio.focus(); radio.checked = true; radio.dispatchEvent(new Event('change'));
      const reachable = document.activeElement === radio &&
                        !document.getElementById('lab-lock').disabled;
      const lock = document.getElementById('lab-lock');
      lock.focus(); lock.click();
      out.steps.push(reachable && !document.getElementById('lab-reveal').hidden);
    }
    const c = document.querySelectorAll('.lab-track button')[5];
    c.focus(); c.click();
    const sw = document.querySelector('.switch[data-key="ratchet"] input');
    sw.focus();
    out.challenge = !document.getElementById('lab-challenge').hidden &&
                    document.activeElement === sw && !sw.disabled;
    // A positive tabindex reorders the whole document and is never the fix.
    out.noPositiveTabindex = ![...document.querySelectorAll('[tabindex]')]
      .some((e) => parseInt(e.getAttribute('tabindex'), 10) > 0);
    // The frame tablist promises arrow keys in its ARIA; it has to keep that.
    const tabs = [...document.querySelectorAll('.frame-tab')];
    tabs[0].focus();
    tabs[0].dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
    out.tablist = document.activeElement === tabs[1] &&
                  tabs[1].getAttribute('aria-selected') === 'true' &&
                  tabs.filter((t) => t.tabIndex === 0).length === 1;
    return out;
  })()`);
  check("keyboard: all five experiments operable without a pointer",
    kb.steps.every(Boolean), JSON.stringify(kb.steps));
  check("keyboard: the challenges and their switches are reachable", kb.challenge);
  check("keyboard: the frame tablist answers arrow keys with a roving tabindex", kb.tablist);
  check("keyboard: nothing hijacks the tab order with a positive tabindex", kb.noPositiveTabindex);

  // ------------------------------------------------------- screen reader
  await goto(base);
  const sr = await ev(`(() => ({
    wire: document.getElementById('wire-sr').textContent,
    dumpHidden: document.getElementById('hexdump').getAttribute('aria-hidden') === 'true',
    verdictLive: document.querySelector('#verdict .body').getAttribute('aria-live'),
    revealLive: document.getElementById('lab-reveal').getAttribute('aria-live'),
    unnamed: [...document.querySelectorAll('button, input, select')]
      .filter((e) => !e.disabled && !(e.textContent || '').trim() &&
                     !e.getAttribute('aria-label') && !e.getAttribute('aria-labelledby') &&
                     !e.labels?.length && e.type !== 'radio')
      .map((e) => e.id || e.className).slice(0, 5),
    // Status must survive monochrome: the word carries it, the colour agrees.
    statusInWords: [...document.querySelectorAll('.threat-status')]
      .every((s) => /defended|exposed|out-of-scope/.test(s.textContent)),
  }))()`);
  check("screen reader: the frame has a structured equivalent to the hexdump",
    /Frame 1 on the wire, \d+ bytes in \d+ fields/.test(sr.wire) && sr.dumpHidden,
    sr.wire.slice(0, 100));
  check("screen reader: every control has an accessible name",
    sr.unnamed.length === 0, sr.unnamed.join(", "));
  check("screen reader: the verdict and the debrief are announced",
    sr.verdictLive === "polite" && sr.revealLive === "polite");
  check("colour is never the only carrier: every threat status is spelled out",
    sr.statusInWords);

  // ----------------------------------------------------- run-together text
  // Sibling spans authored as separate fields are inline by default, so they
  // render as one word. It has happened twice here, from the same assumption
  // about `<span>`, and both times it was caught by someone looking at a render
  // rather than by anything checking. Swept across the states that build their
  // rows from templates, since that is where the pattern lives.
  const joined = [];
  for (const url of ["", "#m=g&s=3&st=r", "#m=g&s=5&st=r", "#m=g&s=6", "#m=g&s=7",
                     "#m=e&c=001110&sp=1", "#m=e&c=111101&sp=1"]) {
    await goto(base + url);
    await ev(`document.querySelectorAll('.why-toggle').forEach((t) => t.click())`);
    await ev(`document.querySelector('details.internals').open = true`);
    for (const found of await ev(RUN_TOGETHER("main *, .masthead *, .foot *"))) {
      joined.push(url || "/" , found);
    }
  }
  check("no two fields render as one word", joined.length === 0, joined.slice(0, 6).join(" | "));

  // --------------------------------------------------------- motion
  // The global reduce rule kills the animation, which would leave the observe
  // beat pointing at nothing. An outline has to take over.
  for (const motion of ["no-preference", "reduce"]) {
    await send("Emulation.setEmulatedMedia", {
      features: [{ name: "prefers-reduced-motion", value: motion }],
    });
    await goto(base);
    const got = await ev(`(() => {
      document.querySelector('.switch[data-key="ratchet"] input').click();
      const row = document.querySelector('.threat-row[data-adv="A3"]');
      const cs = getComputedStyle(row);
      return { flagged: row.classList.contains('flash'),
               anim: cs.animationName, outline: cs.outlineStyle };
    })()`);
    const ok = motion === "reduce"
      ? got.flagged && got.anim === "none" && got.outline === "solid"
      : got.flagged && got.anim === "flashring";
    check(`observe beat: what changed is marked under prefers-reduced-motion: ${motion}`,
      ok, JSON.stringify(got));
  }
}));
