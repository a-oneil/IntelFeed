# IntelFeed browser extension

This page is for anyone who wants to install the browser extension, or build
and release it. It covers what the extension does, how to install it, what it
sends to the server, and how CI publishes a new version.

The extension works with any IntelFeed server: you give it the server address
and your username and password. It runs in Chrome, Edge (and other Chromium
browsers) and Firefox 142 or later. The source is in
[`extension/`](../extension/). It is not in any browser's extension store;
releases come from this repo.

---

## What it does

| Where | What |
| --- | --- |
| Toolbar button | Shows whether the page is already in IntelFeed, with the feed it came from and an **Open** button, then two tabs: **Send to IntelFeed** and **Save as note**. **Send to IntelFeed** takes an optional note and tags; the tags sit in a collapsed **Tags** section that shows how many are selected. On a page already in IntelFeed there is nothing to send: the popup shows **Save as note** and **Add to report** without the tabs. The note becomes a Note on the article, the same kind the reader's Notes panel makes. |
| Toolbar button, after a send or on a page already in IntelFeed | **Found in this article**, collapsed, with the number of entities: the threat actors, malware, tools, CVEs and techniques linked to it, each opening its profile, plus how many detection rules and indicators came from it. While IntelFeed is still processing the page it says so and updates. When the article is part of a story thread, a **Story** block above it shows the story's title and "N articles from M sites" and opens the story. |
| Toolbar button, on a page not yet in IntelFeed | **Already covered by N sites**: articles from the last 14 days whose titles share most of this page's title keywords, so you can see whether the story has come in from elsewhere before you send it, and the story thread they belong to. |
| Notification | After you send a new page, a notification says what IntelFeed found once it has finished with it: "Found 2 actors, 3 CVEs, 5 techniques." Clicking it opens the article. Can be turned off in the settings (**Sending**). |
| Toolbar button, on a PDF | **Send PDF to IntelFeed** uploads the file itself (the browser's PDF viewer can't be read by an extension), with the note and tags; the PDF's address is kept as the article's address. **Send page to IntelFeed** in the right-click menu does the same on a PDF. Only PDFs at an http or https address can be sent. |
| Toolbar button, when the server can't be reached | The popup says so and **Send** still works. A page or link you send is kept in the browser and sent, oldest first, when the server answers again (after the next session renewal, every 5 minutes, or **Send now**). The toolbar button shows how many are waiting. Up to 25 are kept, about 8 MB in all; a page too large to keep is saved as its address, and the server fetches it later. A PDF is not kept. A page the server refuses is listed as not sent. |
| Toolbar button: Save as note | Saves a link to the page, with an optional note and any selected text as a quote, without adding the page to IntelFeed. **Save to** picks where it goes: a **Telemetry source** (its notes in **Telemetry Sources**), an **Entity** (a note on an actor, malware, tool, CVE, technique, campaign, vendor, product, sector, country or mitigation, found by searching or picked from the entities on the page), or **Notes** (a note of its own, titled with the page's title). The telemetry source is filled in when the page looks like it is about one, from earlier links saved from the same part of the site or a product named in the address or title, and the extension remembers your pick for that part of the site. When the page looks like it is about a source and isn't in IntelFeed, the popup opens on this tab; otherwise **Save to** starts on the kind you used last. |
| Toolbar dot | Green when the page you're on is already in IntelFeed; your theme's accent color when the site has a feed, or is a GitHub repo, you don't follow yet. |
| On the page | Known threat actors, malware, CVEs, CWEs, ATT&CK techniques, tools, vendors, products, countries, sectors, mitigations and indicators are underlined in their IntelFeed color. Hovering one shows a card laid out like the app's entity popover, from the entity the server returned with the match: its type (with KEV and severity on a CVE), its Wikipedia picture when it has one, the same facts as the app (CVSS, EPSS, proof-of-concept and exploit status for a CVE; motivation, origin and targets for an actor; and so on), other names, the description (cut short, with **Show more**), detection artifacts for a tool, its three latest articles from the last 90 days, the same reference links (CVE.org, NVD, MITRE ATT&CK, Malpedia, Wikipedia, VirusTotal…), and **Profile**, **Search** (the app's search for that name), **Copy** and, where it applies, **Watch**. Can be turned off for one site from the popup (the switch under the site's name), or everywhere in the settings. |
| Toolbar button, on a site with a feed | Lists the RSS/Atom/JSON feeds the page advertises, each with **Follow**. On a subreddit (`reddit.com/r/<name>`) it offers the subreddit itself, followed as a `reddit` feed like the Reddit starter pack's. When a page advertises no feed, IntelFeed checks the site's usual feed addresses (`/feed`, `/rss`, `/feed.xml`, `/rss.xml`, `/atom.xml`, `/index.xml`, `/feed/atom`, `/feeds/posts/default`) and lists the first one that answers with a feed. |
| Toolbar button, on a GitHub repository | **Follow** under the site's name: adds the repo as a `github_repo` feed. The branch and file patterns are filled in from the page and can be edited first under **Branch and file patterns**. |
| Right-click a page | **Send page to IntelFeed**. The toolbar badge shows ✓ (green: added, gray: already there) or `!`; when the send fails, a notification gives the reason. |
| Right-click a link | **Send link to IntelFeed**. The server fetches the linked page. |
| Hover card buttons | **Profile** opens the entity in IntelFeed and **Search** opens the app's search for its name. **Watch** / **Unwatch** adds the entity to your watchlist (the `watch` mode of `/api/intelligence/watchlist`). An entity that is muted or in My Stack has no **Watch** button, because watching it would replace that mode. **Copy** copies its name. On a country, **Add to intel profile…** adds the country to a profile's regions; intel profiles are scoped by countries and sectors, so other entity types don't offer it. |
| CVE and ATT&CK pages | On a page whose address names one CVE (NVD, cve.org, a vendor advisory), a panel in the bottom-right corner shows the CVSS score, CISA KEV status and due date, EPSS, exploit status, article count, the number of detection rules for the CVE, and the vendors or products in your stack it affects with their detection posture. On an attack.mitre.org technique page it shows the number of rules mapped to the technique and the five newest articles mentioning it in the last 90 days. |
| Toolbar popup: Add to report | Under **Send to IntelFeed**. Adds the page to IntelFeed if it isn't there yet (with the note, tags and selection), then attaches that article to the draft report you pick (`POST /api/intel-reports/{id}/attach`). |
| Right-click selected text: Save selection as a detection rule | Opens a window with the selection as written (line breaks kept), the detected rule language, and a live syntax check (`/api/detection-rules/validate`). **Save to IntelFeed** stores it as a draft rule with the page's address as its source, linked to the page's article when the page is already in IntelFeed. **Convert** then has IntelFeed's AI rewrite it in another rule language, saved as a separate linked rule. |
| Address bar | Type `if`, a space and a search, then Enter: opens `<server>/search?q=…`. |
| Right-click selected text | **Look up "…" in IntelFeed** opens a search for it. Defanged indicators (`hxxp`, `[.]`, `(.)`, `[at]`) are refanged first. Can be turned off in the settings. |

The popup, the settings page and the toolbar icon use your IntelFeed theme
(the one picked under Settings in the app, else the instance default). It is
fetched again each time you open the popup or the settings page, and when the
page script needs it, at most once every 10 minutes. Buttons filled with the accent get black
or white text by the accent's brightness, as in the app.

**The dot and highlighting need access to every page.** After signing in,
open the extension settings, go to **Web pages** and press **Grant permission**; the browser asks once.
Without it, the toolbar button and right-click menu still work on any page you
use them on (the browser's `activeTab` permission), but nothing runs on pages
by itself. Pages already open when you allow it need a reload.

**Sending a page sends what your browser shows**, not just the URL. The
server reads the article out of the page and sanitizes it exactly as it does a
page it fetched itself, so paywalled articles you are signed in to, pages that
build themselves with JavaScript, intranet pages and sites whose robots.txt
turns away crawlers all work. If you selected text first, it is saved as the
entry's excerpt. The page's own published date and author are kept when the
page states them.

A sent page is an ordinary entry on the shared **Manual Uploads** feed and
goes through the same pipeline as a polled article (autolinking, AI analysis,
signals). Sending a page that is already in IntelFeed, from any feed you can
see, does not create a second entry: the extension shows the existing one and
still adds your note and tags to it.

## Install

Each version is published on the repo's
[Releases page](https://github.com/a-oneil/IntelFeed/releases) as
`extension-v<version>`, with one file per browser.

**Chrome, Edge, Brave**

1. Download `intelfeed-extension-chrome-<version>.zip` and unzip it into a
   folder you keep (the browser loads it from there).
2. Open `chrome://extensions` (or `edge://extensions`) and turn on
   **Developer mode**.
3. Choose **Load unpacked** and select the folder.

To update, unzip the new version over the same folder and press the reload
arrow on the extension's card. The sign-in is kept.

**Firefox**

- When the release has `intelfeed-extension-firefox-<version>.xpi`, open it in
  Firefox and accept the prompt. It is signed by Mozilla as an *unlisted*
  add-on: signed, but not listed on addons.mozilla.org.
- When the release has only `intelfeed-extension-firefox-<version>.zip`
  (unsigned), Firefox keeps it only until it restarts: open
  `about:debugging` → **This Firefox** → **Load Temporary Add-on** and pick
  the zip. Firefox Developer Edition and Nightly can keep unsigned add-ons
  with `xpinstall.signatures.required` set to `false`.

## Sign in

The settings page opens when the extension is installed (later: right-click
the toolbar button → **Options**).

1. **Server address**: the address you open IntelFeed at, e.g.
   `https://intel.example.com`. The browser then asks to allow the extension
   to access that one site. The extension asks for no other site access;
   the daily update check reads GitHub's public releases API, which needs none.
2. **Username** and **password**.

The password is sent once, to `POST /api/auth/login`, and is not stored. The
extension keeps the same access and refresh tokens the web app keeps, in the
browser's extension storage, and renews them twice a day and whenever the
browser starts. A refresh token lasts 7 days and each renewal issues a new
one, so the extension stays signed in as long as the browser is used at least
once a week. **Sign out** revokes both tokens on the server.

An `http://` address shows a warning: the password and session cross the
network unencrypted.

## What it sends, and when

| When | Request | Contents |
| --- | --- | --- |
| Signing in | `POST /api/auth/login` | Username and password |
| Opening the toolbar popup on a page | `GET /api/entries/ingest/lookup?url=`, `GET /api/tags`, `GET /api/feeds`, `GET /api/telemetry-sources/catalog`, `GET /api/telemetry-sources`, `GET /api/telemetry-sources/notes/suggest`, `GET /api/intel-reports?status=draft` | The page's URL and title |
| Opening the toolbar popup on a page already in IntelFeed | `GET /api/entries/ingest/{id}/results`, every 5 seconds while it is still processing and the popup is open | The entry's ID |
| Opening the toolbar popup on a page not yet in IntelFeed | `GET /api/entries/ingest/coverage` | The page's URL and title |
| Opening the toolbar popup on a page that advertises no feed (not a subreddit, GitHub repo or PDF) | `POST /api/feeds/discover` (one answer per site, kept for a day) | The page's URL |
| Typing in **Save as note** → **Entity** | `GET /api/intelligence/search` | What you typed |
| Loading a page, with the dot on | `GET /api/entries/ingest/lookup?url=` (cached 5 minutes per URL), `GET /api/feeds` (cached 30 minutes) | The page's URL |
| Loading a page, with highlighting on for the site | `POST /api/autolink/scan` (cached 10 minutes per URL), `GET /api/intelligence/watchlist` (cached 5 minutes) | Up to 120,000 characters of the page's visible text |
| Hovering an underlined name | `GET /api/entities/{type}/{id}/entries-window` (cached 5 minutes per entity) | The entity's type and ID |
| Hovering an underlined name, then Watch / Add to intel profile | `GET`/`PUT`/`DELETE /api/intelligence/watchlist`, `GET /api/intel-profiles`, `GET`/`PUT /api/intel-profiles/{id}` | The entity's type and ID |
| Opening a CVE or ATT&CK technique page, with the panel on | `GET /api/cves/{id}`, `GET /api/intelligence/exposure`, `GET /api/detection-rules?cve=` or `?technique=`, `GET /api/ttps/by-technique/{id}`, `GET /api/entities/ttp/{id}/entries-window` | The CVE or technique ID from the page's address |
| Add to a report | `POST /api/entries/ingest/page`, `POST /api/intel-reports/{id}/attach` | As Send, plus the report ID |
| Save selection as a detection rule | `POST /api/detection-rules/validate`, `POST /api/detection-rules`, `POST /api/detection-rules/{id}/convert` | The selected text, its rule language, a title and the page's address |
| Once a day, and **Check now** in settings | `GET https://api.github.com/repos/a-oneil/IntelFeed/releases` | Nothing about you or the page; this is the one request that goes to GitHub instead of your server |
| Signing in, opening the popup or settings page, and when the page script needs the theme (at most every 10 minutes) | `GET /api/auth/me`, `GET /api/themes/{id}` or `/api/themes/default`, `GET /api/themes/schema` | Nothing |
| Send | `POST /api/entries/ingest/page` | URL, title, the page's HTML, selected text, published date and author if the page states them, your note and tags |
| Send link | `POST /api/entries/ingest/page` | The link's URL only |
| Send, on a PDF | The PDF's own address (from the browser, with its cookies), `GET /api/entries/ingest/capabilities`, `POST /api/entries/ingest/pdf` | The PDF file, its address, your note and tags |
| Once a minute for up to 30 minutes after sending a new page | `GET /api/entries/ingest/{id}/results` | The entry's ID |
| Sending what was waiting for the server | `POST /api/entries/ingest/page` | What the original send would have sent |
| Save as note | `POST /api/telemetry-sources/notes`, `POST /api/entity-notes` or `POST /api/notes`, by **Save to** | The source's name or the entity's type and ID, the page's URL and title, your note, and the selected text |
| Follow (feed, subreddit or repository) | `POST /api/feeds` | The feed URL, the subreddit's name, or the repo's owner, name, branch and file patterns |
| Look up | none | Opens `<server>/search?q=…` in a new tab |

Until you grant the all-sites permission (Settings → **Web pages**), nothing
is sent from a page you only visit: the extension reads a page only when you open its popup or use its
right-click menu. After it, every page's address goes to your server while the
dot is on, and its visible text while highlighting is on for that site. Pages
of any IntelFeed instance are skipped: the signed-in server's host by match
pattern, and any other instance by the `application-name` meta tag the web app
carries. The full page HTML is sent only
when you press Send. Every request goes to your server, except the daily update check, which asks GitHub for the list of releases.

Highlights are `<mark>` elements added to the page; the hover card and the
CVE/ATT&CK panel are built inside a closed shadow root. Both are filled with
DOM text nodes: nothing the server returns is inserted into the page as HTML.
Links on the card are shown only when they start with `https://`. Because the
highlights are part of the page, the site's own scripts can see which names
were marked.

The server records the sender in the entry's `metadata.uploaded_by` and the
extension version in `metadata.client`, and marks the entry
`metadata.source = "extension_page"` (a sent link is `url_ingest`), so content
that came from a browser rather than the server's own fetch can be told apart.

## How it is built

Plain JavaScript modules with no dependencies and no bundler. Only the
background worker talks to the server; the popup and settings page ask it
through `chrome.runtime` messages. Refresh tokens are single-use, so two parts
of the extension refreshing at once would sign the user out; one fetcher
avoids that. Because the worker holds host permission for the server, the
server needs no CORS entry for the extension.

| File | Role |
| --- | --- |
| `extension/manifest.json` | The manifest (Chrome form). The build derives the Firefox one |
| `extension/src/background.js` | Right-click menus, the dot and badge, session renewal, theme, registering the page script, the message handlers |
| `extension/src/ui.css` | Styles shared by the popup, the settings page and the rule window |
| `extension/src/content/page.js`, `matcher.js` | The page script: reports the page and its feeds, highlights entities, the hover card |
| `extension/src/lib/theme.js` | Applies the user's IntelFeed theme to the popup, the settings page and the rule window |
| `extension/src/lib/api.js` | Sign in, refresh, authenticated requests |
| `extension/src/lib/store.js` | What the extension keeps in `chrome.storage.local`, and the default feature switches |
| `extension/src/lib/messages.js` | How the popup, settings page and rule window ask the background worker for something |
| `extension/src/lib/capture.js` | Runs in the page: HTML, selection, meta tags, JSON-LD, feed links |
| `extension/src/lib/page-meta.js` | Published date, author, feed links, subreddit, GitHub repo, request bodies |
| `extension/src/lib/lookup.js` | Refanging and the lookup URL |
| `extension/src/lib/outbox.js` | The queue of sends waiting for the server: limits, what is worth retrying |
| `extension/src/lib/findings.js` | What the server found, in words (the popup and the notification) |
| `extension/src/lib/pdf.js` | Whether a tab is a PDF, and the upload's file name |
| `extension/src/lib/telemetry.js` | Remembering which telemetry source was picked for which part of a site |
| `extension/src/lib/card-view.js` | What the hover card shows per entity type: the app's popover facts, badges, other names and reference links |
| `extension/src/lib/notes.js` | Save as note: the note's text, which entities can take a note, which kind the tab opens on; the names shown for entity types |
| `extension/src/lib/watchlist.js` | Which entities get a **Watch** button on the hover card |
| `extension/src/lib/rule-format.js` | Detecting a rule's language for the rule window |
| `extension/src/lib/version.js` | Comparing versions and picking the newest extension release |
| `extension/src/popup/` | The toolbar popup |
| `extension/src/rule/` | The "save selection as a detection rule" window |
| `extension/scripts/build.mjs` | Writes `dist/chrome/`, `dist/firefox/` and a zip of each |
| `extension/src/lib/mark.js` | The IntelFeed mark, as SVG and drawn on a canvas |
| `extension/src/lib/logo.js` | Puts the mark in the headers of the popup, settings page and rule window |
| `extension/src/lib/toolbar-icon.js` | Redraws the toolbar icon in your IntelFeed theme's accent |
| `scripts/dev/render_icons.cjs` | Renders `icons/icon-*.png` (with the web and Android icons) from the IntelFeed mark: heavier lines and nodes at 16 and 32 px, the regular weights on a dark tile at 48 and 128. Dev-only; uses the frontend's Playwright |
| `extension/src/options/` | The settings page. Each `<section class="panel" data-title>` is one section with its own entry in the side menu |

```bash
cd extension
npm test                          # node's built-in test runner
npm run build                     # dist/ — load dist/chrome unpacked, or dist/firefox/manifest.json temporarily
scripts/build_extension.sh        # from the repo root: bump the patch version, test, build
```

The Firefox build differs only in its manifest: a `background.scripts` entry
instead of a service worker, and `browser_specific_settings` with the add-on
id `intelfeed@a-oneil.github.io`, the minimum version and the data-collection
declaration (`authenticationInfo`, `websiteContent`, `browsingActivity`).

## Releases

The `extension` job in `.github/workflows/ci.yml` runs when anything under
`extension/` changes. It runs the tests, builds both zips, runs Mozilla's
`web-ext lint` on the Firefox build and attaches the zips to the run.

On `main`, when `extension/manifest.json` has a version with no
`extension-v<version>` release yet, the job publishes that release. So a merge
that bumps the version (`scripts/build_extension.sh`) is what ships; other
changes are built and tested only.

Firefox signing needs two repository secrets, `AMO_JWT_ISSUER` and
`AMO_JWT_SECRET`: an API key from an addons.mozilla.org account
(**Developer Hub → Manage API Keys**). With them the release carries the
signed `.xpi`; without them it carries the unsigned zip and the job logs a
warning. Mozilla signs each version once, so signing runs only when a release
is published.
