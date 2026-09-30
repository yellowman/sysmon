# sysmon-web design

sysmon-web borrows the shared shell and navigation grammar from Liminal,
not Liminal's visual theme. The monitoring surfaces keep sysmon's own
color, typography, density, status and data-display conventions.

That split is the whole idea. Two products can share how an application
is laid out and navigated without one of them being reskinned as the
other. If the grammar below only held up by also copying Liminal's
colors, it would not be a design language, just the way Liminal looks.

## The shared grammar

These are the parts sysmon-web takes from Liminal, and the parts a
third product would be expected to take too.

- **Navigation answers "where am I?"** It lists destinations and marks
  the current one. It is not a toolbar: page actions, filters and
  buttons belong to the page.
- **Selection has two signals**: a faint fill in the application's
  accent and a 2px marker at the leading edge, plus a heavier weight.
  Where you are never rests on color alone.
- **Destinations stand apart from account and administration.** The
  separation is whitespace, not divider lines.
- **Global scope lives in the shell.** Anything that changes what every
  page is looking at sits at the top of the navigation, under the
  product name, rather than being repeated in pages.
- **Pages own their contents.** Adopting the shell never implies
  adopting another product's cards, tokens, typography, buttons or
  tables.
- **Mobile is the same navigation**, behind a menu button as a drawer -
  not a second navigation model to keep in step with the first.
- **Status is never color alone**, and chrome stays restrained: the
  shell should be the quietest thing on the screen.

## sysmon-web's expression

What stays sysmon's own:

- **Color.** Accent is blue-600 (`#2563eb`), the blue in the wordmark.
  Pages are gray-50 (`#f9fafb`) with white surfaces; status keeps its
  emerald, amber and red.
- **Type.** Inter for text, JetBrains Mono for identifiers, addresses
  and anything a person might copy.
- **Icons.** Font Awesome, shipped in the binary like everything else
  under `/static/` - no CDN, because a monitoring console has to work on
  a network with no route to the internet.
- **Surfaces.** The existing cards, dashboard figures, alert
  presentation, map, tables and density are unchanged by the shell.

## The rail

`templates/base.html` renders it once for every page.

- **Width** 11.5rem (184px), set in one CSS variable (`--rail-w`) that
  both the rail and the content offset read, so they cannot drift.
- **Labels are always shown.** Liminal can use a 48px icon-only rail;
  sysmon-web does not. SNMP Traps, Templates, Fleet, Metrics and
  Configuration are not destinations an operator should decode from a
  tooltip, least of all during an outage.
- **Order, top to bottom:**
  1. The wordmark, linking to the dashboard.
  2. The site selector - which sysmond the whole console is looking at.
     Shown only when more than one box is connected; a single-box
     install has nothing to choose between. A selection pointing at a
     site that has left the fleet says so here rather than silently
     falling back to all sites.
  3. Watching the network: Dashboard, Hosts, Map, SNMP Traps, History,
     Metrics.
  4. Managing what watches it: Fleet, Templates.
  5. At the bottom, apart from both: Configuration and Admin, shown
     only to admins.
  6. The account: who is signed in, and Log out.
- **Active state:** `#eff6ff` fill, a 2px `#2563eb` marker, weight 600,
  and a blue icon. The link also carries `aria-current="page"`.
  Inactive links are gray-600 text with gray-400 icons.
- **Admin-only destinations are hidden, and also gated.** Hiding a link
  is tidiness, not a control: the server refuses or redirects every
  admin-only page and API for a non-admin regardless of what the rail
  shows.
- **Below 1024px** the rail becomes a drawer behind a menu button in a
  slim top bar. The same element, the same links, taller touch targets.
  Escape, the close button or the backdrop dismisses it.
- **CSS decides the resting state**, not Alpine. The drawer is closed
  and the desktop rail is shown before any script runs, so neither
  flashes the wrong way while the page loads.

### Adding a destination

Put it in the group that matches what the page is for - watching the
network, or managing the monitoring - and give it a Font Awesome icon
that no other destination uses. An admin-only page goes in the bottom
group, and gets a server-side gate as well as its `x-show`; the rail is
never the only thing standing between a user and a page.

## Not done, on purpose

- **No shared package.** Two implementations are not enough to know
  which parts of the grammar are real. If a third product adopts it,
  that is the point to extract it into a standalone design document.
- **Pages were not restyled** when the shell changed. The map and
  configuration editor still carry their own site picker, because they
  act on exactly one box and cannot use "All sites"; folding them into
  the global selector is a page-level change of its own.
