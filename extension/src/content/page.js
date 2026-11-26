// Runs on web pages once the user allows the extension on all sites (see the
// settings page). It tells the background worker which page this is and which
// feeds it advertises (for the toolbar dot), and — when highlighting is on for
// this site — sends the page's visible text to the user's IntelFeed server to
// find known entities, marks them, and shows a card on hover.
//
// Everything the server returns is written with textContent: into <mark>
// elements in the page for the highlights, and into a closed shadow root for
// the card and the panel. Nothing from the server or the page is parsed as HTML.

(function () {
  if (window.top !== window || window.__intelfeedPage) return;
  window.__intelfeedPage = true;
  // Never on IntelFeed itself — it links its own entities. The background
  // worker already excludes the signed-in server's host, but that misses any
  // other instance (dev at localhost:3001 while signed in to prod, a second
  // server, an IP instead of the hostname), so the app also marks its own page.
  // apple-mobile-web-app-title covers servers built before the marker.
  if (document.querySelector('meta[name="application-name"][content="IntelFeed"], meta[name="apple-mobile-web-app-title"][content="IntelFeed"]')) return;

  const MAX_TEXT = 120000;
  const MAX_MARKS = 600;
  const SKIP = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEXTAREA", "INPUT", "SELECT", "OPTION", "SVG", "CANVAS", "IFRAME", "MARK"]);
  const MARK_ATTR = "data-intelfeed";

  let matches = [];
  let theme = null;

  const send = (message) =>
    new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(message, (reply) => resolve(chrome.runtime.lastError ? null : reply));
      } catch {
        resolve(null); // the extension was reloaded under this page
      }
    });

  function feedLinks() {
    return [...document.querySelectorAll('link[rel~="alternate"][href]')].map((el) => ({
      href: el.href,
      type: (el.type || "").toLowerCase(),
      title: el.title || "",
    }));
  }

  function textNodes() {
    const nodes = [];
    if (!document.body) return nodes;
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        if (!node.nodeValue || node.nodeValue.trim().length < 2) return NodeFilter.FILTER_REJECT;
        for (let el = node.parentElement; el && el !== document.body; el = el.parentElement) {
          if (SKIP.has(el.tagName.toUpperCase()) || el.isContentEditable || el.hasAttribute(MARK_ATTR)) {
            return NodeFilter.FILTER_REJECT;
          }
        }
        return NodeFilter.FILTER_ACCEPT;
      },
    });
    while (walker.nextNode()) nodes.push(walker.currentNode);
    return nodes;
  }

  function pageText(nodes) {
    let text = "";
    for (const node of nodes) {
      if (text.length >= MAX_TEXT) break;
      text += node.nodeValue + "\n";
    }
    return text.slice(0, MAX_TEXT);
  }

  // ── marking ─────────────────────────────────────────────────────────

  function unmark() {
    for (const mark of document.querySelectorAll(`mark[${MARK_ATTR}]`)) {
      mark.replaceWith(document.createTextNode(mark.textContent));
    }
    document.body?.normalize();
  }

  function markAll(nodes) {
    const byForm = new Map();
    for (const [i, m] of matches.entries()) for (const form of m.forms) if (!byForm.has(form)) byForm.set(form, i);
    const pattern = IntelFeedMatcher.buildPattern([...byForm.keys()]);
    let count = 0;
    for (const node of nodes) {
      if (count >= MAX_MARKS) break;
      const found = IntelFeedMatcher.findMatches(node.nodeValue, pattern);
      if (!found.length || !node.parentNode) continue;
      const frag = document.createDocumentFragment();
      let at = 0;
      for (const f of found) {
        if (count >= MAX_MARKS) break;
        const m = matches[byForm.get(f.form)];
        frag.append(node.nodeValue.slice(at, f.start));
        const mark = document.createElement("mark");
        mark.setAttribute(MARK_ATTR, String(byForm.get(f.form)));
        mark.textContent = f.form;
        const color = m.color || "#888888";
        // The app's highlight (InlineEntityHighlighter.module.css): a dotted
        // underline in the entity's colour, no background; solid with a faint
        // tint on hover (see the mouseover handler). 3px where the app has 2px:
        // at a site's own text size the app's weight reads lighter.
        mark.style.cssText = [
          "background:transparent",
          "color:inherit",
          "border-bottom:3px dotted " + color,
          "padding:0 0 1px",
          "transition:background-color .15s",
        ].join(";");
        // No cursor of its own: the page's (text, or a link's pointer) stays,
        // since hovering is what opens the card.
        frag.append(mark);
        at = f.end;
        count += 1;
      }
      frag.append(node.nodeValue.slice(at));
      node.parentNode.replaceChild(frag, node);
    }
  }

  // ── hover card ──────────────────────────────────────────────────────

  let host;
  let card;
  let hideTimer;
  let shownMark = null;

  // Same as TYPE_LABELS in lib/notes.js and contrastText in lib/theme.js below:
  // a content script can't import modules, so keep the copies in step.
  const TYPE_LABELS = {
    threat_actor: "Threat actor",
    malware: "Malware",
    cve: "CVE",
    cwe: "CWE",
    ttp: "ATT&CK technique",
    country: "Country",
    tool: "Tool",
    vendor: "Vendor",
    product: "Product",
    mitigation: "Mitigation",
    sector: "Sector",
    observable: "Indicator",
    campaign: "Campaign",
  };

  // Black or white, whichever reads on a fill (contrastText in lib/theme.js).
  function contrastText(hex) {
    const m = /^#?([0-9a-f]{6})$/i.exec(String(hex || "").trim());
    if (!m) return "#ffffff";
    const [r, g, b] = [0, 2, 4].map((i) => {
      const c = parseInt(m[1].slice(i, i + 2), 16) / 255;
      return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.179 ? "#000000" : "#ffffff";
  }

  /** "Nov 25, 2026 (7h ago)", the app's date with its age. */
  function dateWithAge(iso) {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    const date = d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
    const mins = Math.max(0, Math.round((Date.now() - d.getTime()) / 60000));
    const days = Math.round(mins / 1440);
    const age =
      mins < 60
        ? `${mins}m`
        : mins < 1440
          ? `${Math.round(mins / 60)}h`
          : days < 30
            ? `${days}d`
            : days < 365
              ? `${Math.round(days / 30)}mo`
              : `${Math.round(days / 365)}y`;
    return `${date} (${age} ago)`;
  }

  // The card mirrors the app's entity popover (frontend/src/components/EntityPopover).
  function ensureCard() {
    if (card) return card;
    host = document.createElement("intelfeed-card");
    host.style.cssText = "all:initial;position:absolute;z-index:2147483647;top:0;left:0;";
    const shadow = host.attachShadow({ mode: "closed" });
    const v = (theme && theme.vars) || {};
    const border = v.border || "#30363d";
    const text = v["text-primary"] || "#e6edf3";
    const muted = v["text-secondary"] || "#8b949e";
    const accent = v.accent || "#f78166";
    const tertiary = v["bg-tertiary"] || "#21262d";
    const style = document.createElement("style");
    style.textContent = `
      .card { box-sizing: border-box; width: 340px; max-width: calc(100vw - 16px); padding: 10px 16px;
        border: 1px solid ${border}; border-radius: 8px; background: ${v["bg-secondary"] || "#161b22"};
        color: ${text}; font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif;
        box-shadow: 0 4px 12px rgba(0,0,0,.15); }
      .head { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
      .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;
        letter-spacing: .5px; text-transform: uppercase; }
      .who { display: flex; align-items: center; gap: 12px; margin: 6px 0 8px; }
      .thumb { flex: none; width: 36px; height: 36px; border-radius: 4px; object-fit: cover; border: 1px solid ${border};
        background: ${tertiary}; }
      .name { font: 500 15px/1.35 ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-word; }
      .bad { color: ${v.danger || "#f85149"}; }
      .artifacts { margin-bottom: 8px; padding: 0 0 6px; border-bottom: 1px solid ${border}; }
      .artifact { display: flex; flex-direction: column; padding: 2px 0; }
      .artifact .val { font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
      .links { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 8px; }
      .links a { padding: 2px 6px; border: 1px solid ${border}; border-radius: 4px; background: ${tertiary};
        color: ${accent}; font-size: 12px; text-decoration: none; }
      .links a:hover { background: ${accent}; border-color: ${accent}; color: ${contrastText(accent)}; }
      .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 2px 16px; margin-bottom: 8px; padding: 6px 0;
        border-top: 1px solid ${border}; border-bottom: 1px solid ${border}; }
      .item { display: flex; flex-direction: column; padding: 2px 0; min-width: 0; }
      .full { grid-column: 1 / -1; }
      .label { font-size: 11px; color: ${muted}; text-transform: uppercase; letter-spacing: .3px; }
      .value { font-size: 13px; font-weight: 500; }
      .desc { font-size: 12px; color: ${muted}; line-height: 1.4; }
      .desc.open { display: block; max-height: 220px; overflow-y: auto; white-space: pre-line; }
      .more { padding: 0; border: 0; background: none; color: ${accent}; font: inherit; font-size: 11px; cursor: pointer; }
      .more:hover { text-decoration: underline; }
      .recent { margin-bottom: 8px; padding: 0 0 6px; }
      .recent ul { list-style: none; margin: 4px 0 0; padding: 0; }
      .recent li a { display: flex; flex-direction: column; padding: 4px 0; text-decoration: none; min-width: 0; }
      .recent .title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; font-weight: 500;
        color: ${text}; }
      .recent li a:hover .title { color: ${accent}; }
      .recent .meta, .recent .none { font-size: 11px; color: ${muted}; }
      .actions { display: flex; flex-wrap: wrap; gap: 6px; }
      .btn { flex: 1; min-width: 60px; box-sizing: border-box; padding: 6px 10px; border: 1px solid ${border};
        border-radius: 4px; background: ${tertiary}; color: ${muted}; font: inherit; font-size: 13px;
        text-align: center; text-decoration: none; cursor: pointer; }
      .btn:hover { background: ${accent}; border-color: ${accent}; color: ${contrastText(accent)}; }
      .btn:disabled { opacity: .5; cursor: default; }
      select.btn { flex-basis: 100%; text-align: left; }
      select.btn:hover { background: ${tertiary}; color: ${text}; }
      .msg { width: 100%; font-size: 12px; color: ${muted}; }
      .msg:empty { display: none; }`;
    card = document.createElement("div");
    card.className = "card";
    card.addEventListener("mouseenter", () => clearTimeout(hideTimer));
    card.addEventListener("mouseleave", scheduleHide);
    shadow.append(style, card);
    document.documentElement.append(host);
    return card;
  }

  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (text != null) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  }

  function show(mark) {
    const m = matches[Number(mark.getAttribute(MARK_ATTR))];
    if (!m) return;
    clearTimeout(hideTimer);
    const card = ensureCard();
    card.replaceChildren();

    const view = m.view || { badges: [], facts: [], aliases: [], links: [], artifacts: [], descMax: 220 };

    const head = el("div", null, "head");
    const badge = el("span", TYPE_LABELS[m.type] || m.type.replace(/_/g, " "), "badge");
    badge.style.background = m.color || "#888888";
    badge.style.color = contrastText(m.color || "#888888");
    head.append(badge);
    for (const b of view.badges) {
      const extra = el("span", b.text, "badge");
      // Solid like the type badge, or toned: the colour on a faint tint of itself
      extra.style.background = b.solid ? b.color : `${b.color}26`;
      extra.style.color = b.solid ? contrastText(b.color) : b.color;
      head.append(extra);
    }
    const who = el("div", null, "who");
    if (view.image) {
      const img = el("img", null, "thumb");
      img.alt = "";
      img.referrerPolicy = "no-referrer";
      img.addEventListener("error", () => img.remove());
      img.src = view.image;
      who.append(img);
    }
    who.append(el("span", m.name, "name"));
    card.append(head, who);

    // The grid, in the app's order: the type's facts, then Articles and First
    // seen (the other way round for CVEs and techniques), aliases, description.
    const grid = el("div", null, "grid");
    const item = (label, value, cls = "value", full = false) => {
      const row = el("div", null, full ? "item full" : "item");
      row.append(el("span", label, "label"), typeof value === "string" ? el("span", value, cls) : value);
      grid.append(row);
    };
    for (const f of view.facts) item(f.label, f.value, f.tone === "bad" ? "value bad" : "value");
    const articles = () => m.articleCount != null && item("Articles", String(m.articleCount));
    const seen = () => view.firstSeen && item("First seen", dateWithAge(view.firstSeen));
    if (view.seenFirst) {
      seen();
      articles();
    } else {
      articles();
      seen();
    }
    if (view.aliases.length) item("Also known as", view.aliases.join(", "), "value", true);
    if (m.description) item("Description", description(m.description, view.descMax), null, true);
    if (grid.childElementCount) card.append(grid);

    if (view.artifacts.length) {
      const box = el("div", null, "artifacts");
      box.append(el("div", "Detection artifacts", "label"));
      for (const a of view.artifacts) {
        const row = el("div", null, "artifact");
        row.append(el("span", a.label, "label"), el("span", a.value.length > 90 ? a.value.slice(0, 90) + "…" : a.value, "val"));
        box.append(row);
      }
      card.append(box);
    }

    card.append(recentFor(m));
    if (view.links.length) {
      const links = el("div", null, "links");
      for (const l of view.links) {
        const a = el("a", l.label);
        a.href = l.url;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        links.append(a);
      }
      card.append(links);
    }
    card.append(actionsFor(m));
    shownMark = mark;
    host.style.display = "block";
    place(mark);
  }

  /** Below the word, or above it when there's no room below. Again when the card grows. */
  function place(mark) {
    const r = mark.getBoundingClientRect();
    const width = Math.min(340, window.innerWidth - 16);
    const left = Math.max(8, Math.min(r.left, window.innerWidth - width - 8));
    const below = r.bottom + 6;
    const height = card.offsetHeight || 140;
    const top = below + height > window.innerHeight && r.top > height + 6 ? r.top - height - 6 : below;
    host.style.left = `${left + window.scrollX}px`;
    host.style.top = `${top + window.scrollY}px`;
  }

  /** The description cut at 220 characters, with Show more / Show less for the rest. */
  function description(full, max = 220) {
    const span = el("span", null, "desc");
    const long = full.length > max;
    let open = false;
    const draw = () => {
      span.className = open ? "desc open" : "desc";
      span.replaceChildren(open || !long ? full : full.slice(0, max).trimEnd() + "…");
      if (!long) return;
      const more = el("button", open ? "Show less" : "Show more", "more");
      more.type = "button";
      more.addEventListener("click", () => {
        open = !open;
        draw();
        if (shownMark) place(shownMark);
      });
      span.append(" ", more);
    };
    draw();
    return span;
  }

  /** The entity's latest articles, filled in when they arrive. */
  function recentFor(m) {
    const box = el("div", null, "recent");
    const body = el("div", "Loading…", "none");
    box.append(el("div", "Recent articles", "label"), body);
    const render = (items) => {
      if (!items.length) {
        body.textContent = "None in the last 90 days.";
        return;
      }
      const list = el("ul");
      for (const a of items) {
        const li = el("li");
        const link = el("a");
        link.href = a.href;
        link.target = "_blank";
        link.rel = "noopener";
        link.title = a.title || "";
        link.append(
          el("span", a.title || "Untitled", "title"),
          el("span", [a.feed, a.published ? dateWithAge(a.published) : null].filter(Boolean).join(" · "), "meta"),
        );
        li.append(link);
        list.append(li);
      }
      body.replaceWith(list);
    };
    if (m.recent) render(m.recent);
    else
      send({ type: "articles", entityType: m.type, id: m.id }).then((reply) => {
        if (Array.isArray(reply)) {
          m.recent = reply;
          if (box.isConnected) {
            render(reply);
            if (shownMark) place(shownMark);
          }
        } else if (box.isConnected) {
          box.remove();
        }
      });
    return box;
  }

  function button(label, onClick) {
    const b = el("button", label, "btn");
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  }

  function linkButton(label, href) {
    const a = el("a", label, "btn");
    a.href = href;
    a.target = "_blank";
    a.rel = "noopener";
    return a;
  }

  /** Profile / Search / Copy / Watch, and Add to intel profile for a country. */
  function actionsFor(m) {
    const row = el("div", null, "actions");
    const msg = el("div", null, "msg");
    const say = (text) => (msg.textContent = text);

    row.append(linkButton("Profile", m.href));
    if (m.searchHref) row.append(linkButton("Search", m.searchHref));
    row.append(
      button("Copy", async () => {
        try {
          await navigator.clipboard.writeText(m.name);
          say(`Copied "${m.name}".`);
        } catch (e) {
          say("The page did not allow copying to the clipboard.");
        }
      }),
    );

    if (m.watchable) {
      const watch = button(m.watched ? "Unwatch" : "Watch", async () => {
        watch.disabled = true;
        const reply = await send({ type: "watch", entityType: m.type, id: m.id, on: !m.watched });
        watch.disabled = false;
        if (!reply || reply.error) return say(reply?.error || "Could not change the watchlist.");
        m.watched = reply.watched;
        watch.textContent = m.watched ? "Unwatch" : "Watch";
        say(m.watched ? `${m.name} is on your watchlist. Articles about it rank higher for you.` : `${m.name} was removed from your watchlist.`);
      });
      row.append(watch);
    }

    if (m.type === "country") {
      const pick = el("select", null, "btn");
      const first = el("option", "Add to intel profile…");
      first.value = "";
      pick.append(first);
      let loaded = false;
      pick.addEventListener("focus", async () => {
        if (loaded) return;
        loaded = true;
        const profiles = await send({ type: "profiles" });
        if (!Array.isArray(profiles)) return say(profiles?.error || "Could not load intel profiles.");
        if (!profiles.length) return say("You have no intel profiles yet. Create one in IntelFeed first.");
        for (const p of profiles) {
          const o = el("option", p.countryIds.includes(m.id) ? `${p.name} (already included)` : p.name);
          o.value = p.id;
          o.disabled = p.countryIds.includes(m.id);
          pick.append(o);
        }
      });
      pick.addEventListener("change", async () => {
        if (!pick.value) return;
        const reply = await send({ type: "addToProfile", profileId: pick.value, countryId: m.id });
        pick.value = "";
        if (!reply || reply.error) return say(reply?.error || "Could not update the intel profile.");
        say(reply.added ? `${m.name} was added to the regions of "${reply.name}".` : `"${reply.name}" already includes ${m.name}.`);
      });
      row.append(pick);
    }
    row.append(msg);
    return row;
  }

  function scheduleHide() {
    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => {
      if (host) host.style.display = "none";
    }, 250);
  }

  document.addEventListener("mouseover", (event) => {
    const mark = event.target instanceof Element && event.target.closest(`mark[${MARK_ATTR}]`);
    if (!mark) return;
    mark.style.borderBottomStyle = "solid";
    mark.style.backgroundColor = "rgba(127,127,127,.15)";
    show(mark);
  });
  document.addEventListener("mouseout", (event) => {
    const mark = event.target instanceof Element && event.target.closest(`mark[${MARK_ATTR}]`);
    if (!mark) return;
    mark.style.borderBottomStyle = "dotted";
    mark.style.backgroundColor = "transparent";
    scheduleHide();
  });

  // ── the CVE / ATT&CK panel ──────────────────────────────────────────

  let panelHost;
  let panelUrl = null; // the page the panel was shown (or closed) on

  function fact(label, value) {
    const row = el("div", null, "fact");
    row.append(el("span", label, "label"), el("span", value));
    return row;
  }

  function cveFacts(c) {
    const out = [];
    if (c.cvss != null) out.push(fact("CVSS score", `${c.cvss}${c.severity ? ` (${c.severity.toLowerCase()})` : ""}`));
    out.push(fact("CISA KEV list", c.kev ? `Yes${c.kevDue ? `. US federal agencies must fix it by ${c.kevDue}.` : ""}` : "No"));
    if (c.epss != null) {
      // Rounded down: 0.99999 is "99.9%", never a certain "100.0%".
      const pct = (Math.floor(c.epss * 1000) / 10).toFixed(1);
      out.push(fact("EPSS", `${pct}% chance of exploitation in the next 30 days`));
    }
    if (c.exploit) out.push(fact("Exploit", c.exploit.replace(/_/g, " ")));
    out.push(fact("Articles in IntelFeed", String(c.articles ?? 0)));
    if (c.rules != null) out.push(fact("Detection rules for it", String(c.rules)));
    out.push(
      fact(
        "Your stack",
        c.stack.length
          ? c.stack.map((s) => `${s.asset}${s.posture ? ` (detection: ${s.posture.replace(/_/g, " ")})` : ""}`).join("; ")
          : "Does not affect any vendor or product in your stack",
      ),
    );
    return out;
  }

  function showPanel(ctx) {
    if (panelHost) panelHost.remove();
    panelHost = document.createElement("intelfeed-panel");
    panelHost.style.cssText = "all:initial;position:fixed;z-index:2147483646;right:16px;bottom:16px;";
    const shadow = panelHost.attachShadow({ mode: "closed" });
    const v = (theme && theme.vars) || {};
    const style = document.createElement("style");
    style.textContent = `
      .panel { box-sizing: border-box; width: 340px; max-width: calc(100vw - 32px); max-height: 70vh; overflow: auto;
        padding: 12px 14px; border: 1px solid ${v.border || "#30363d"}; border-radius: 10px;
        background: ${v["bg-secondary"] || "#161b22"}; color: ${v["text-primary"] || "#e6edf3"};
        font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; box-shadow: 0 10px 30px rgba(0,0,0,.4); }
      .top { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 6px; }
      .kicker { font-size: 11px; font-weight: 600; letter-spacing: .02em; text-transform: uppercase; color: ${v.accent || "#f78166"}; }
      .title { font-size: 14px; font-weight: 600; margin-bottom: 8px; }
      .fact { display: grid; grid-template-columns: 130px 1fr; gap: 8px; padding: 4px 0; border-top: 1px solid ${v.border || "#30363d"}; }
      .label { color: ${v["text-secondary"] || "#8b949e"}; }
      ul { margin: 4px 0 0; padding-left: 18px; }
      li { margin: 3px 0; }
      .small { font-size: 12px; color: ${v["text-secondary"] || "#8b949e"}; }
      a { color: ${v.accent || "#f78166"}; text-decoration: none; }
      a:hover { text-decoration: underline; }
      .open { display: inline-block; margin-top: 10px; font-weight: 600; }
      button { font: inherit; border: 0; background: transparent; color: ${v["text-secondary"] || "#8b949e"};
        cursor: pointer; font-size: 18px; line-height: 1; padding: 0 2px; }`;
    const box = el("div", null, "panel");
    const top = el("div", null, "top");
    top.append(el("span", "IntelFeed", "kicker"));
    const close = el("button", "×");
    close.title = "Close this panel";
    close.setAttribute("aria-label", "Close this panel");
    close.addEventListener("click", () => {
      panelHost.remove();
      panelHost = null;
    });
    top.append(close);
    box.append(top);

    if (!ctx.found) {
      box.append(el("div", ctx.id, "title"));
      const source = ctx.kind === "cve" ? "a feed or a CVE source (NVD, CISA KEV) reports it" : "an article in one of your feeds mentions it";
      box.append(el("p", `${ctx.id} is not in IntelFeed yet. IntelFeed adds it when ${source}.`, "small"));
    } else if (ctx.kind === "cve") {
      box.append(el("div", ctx.id, "title"), ...cveFacts(ctx));
    } else {
      box.append(el("div", `${ctx.id} ${ctx.name}`, "title"));
      if (ctx.rules != null) box.append(fact("Detection rules", `${ctx.rules} in IntelFeed are mapped to this technique`));
      const recent = el("div", null, "fact");
      recent.append(el("span", "Recent articles", "label"));
      const right = el("div");
      if (ctx.recent.length) {
        const list = el("ul");
        for (const e of ctx.recent) {
          const li = el("li");
          const a = el("a", e.title);
          a.href = e.href;
          a.target = "_blank";
          a.rel = "noopener";
          li.append(a, el("div", [e.feed, e.published ? e.published.slice(0, 10) : null].filter(Boolean).join(" · "), "small"));
          list.append(li);
        }
        right.append(list);
      } else {
        right.append(el("span", "None in the last 90 days"));
      }
      recent.append(right);
      box.append(recent);
    }
    if (ctx.href) {
      const open = el("a", "Open in IntelFeed", "open");
      open.href = ctx.href;
      open.target = "_blank";
      open.rel = "noopener";
      box.append(open);
    }
    shadow.append(style, box);
    document.documentElement.append(panelHost);
  }

  async function contextPanel() {
    const ctx = IntelFeedMatcher.contextFromUrl(location.href);
    if (!ctx || panelUrl === location.href) return;
    panelUrl = location.href;
    const data = await send({ type: "context", kind: ctx.kind, id: ctx.id });
    if (data && !data.error) showPanel(data);
  }

  // ── the run ─────────────────────────────────────────────────────────

  let running = false;

  async function run() {
    if (running) return;
    running = true;
    try {
      const seen = await send({ type: "pageSeen", url: location.href, feeds: feedLinks() });
      if (!seen) return;
      theme = seen.theme;
      if (seen.contextPanel) contextPanel();
      if (!seen.highlight) return;
      const nodes = textNodes();
      const text = pageText(nodes);
      if (!text.trim()) return;
      const reply = await send({ type: "scan", url: location.href, text });
      if (!reply || !reply.matches || !reply.matches.length) return;
      matches = reply.matches;
      markAll(textNodes());
    } finally {
      running = false;
    }
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "unhighlight") {
      unmark();
      matches = [];
      if (host) host.style.display = "none";
    } else if (message?.type === "rescan") {
      unmark();
      run();
    }
  });

  run();
  // Pages that build themselves after load: look once more when they've settled.
  setTimeout(() => {
    if (!matches.length) run();
  }, 3000);
})();
