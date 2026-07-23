# Network Behavior

No telemetry is sent by the application.
Continuo sends no telemetry and no keyboard, mouse, clipboard, or
transferred-file content to an Internet service. Peer content stays on the
authenticated local peer connection. Updates, licensing, downloads, payments,
and user-opened website links are separate documented Internet traffic.

Each expected flow below records its destination, purpose, trigger, payload
category, disablement, and whether it includes input content.

## Peer connection (local network)

### Paired Mac on LAN (Bonjour-discovered)

- **Purpose:** Encrypted keyboard, mouse, clipboard, and file transfer between paired Macs
- **Trigger:** Active session with a paired peer
- **Payload:** Peer application data, encrypted on the authenticated local connection
- **Can disable?:** Yes: deny Local Network access or unpair the Mac
- **Input content?:** Yes, on the authenticated LAN connection only

## Internet endpoints

### `github.com` / `objects.githubusercontent.com`

- **Purpose:** Fallback release binaries and release metadata
- **Trigger:** Primary-download fallback or a user-initiated GitHub download
- **Payload:** Signed binary and metadata such as version and checksums
- **Can disable?:** Avoid the fallback or manual GitHub download
- **Input content?:** No

### `api.lemonsqueezy.com` (and related Lemon Squeezy hosts)

- **Purpose:** Validate Continuo Pro licence keys
- **Trigger:** Entering or refreshing a licence in Settings
- **Payload:** Licence key, product identifier, and activation metadata
- **Can disable?:** Yes: stay on the Free tier
- **Input content?:** No

### `usecontinuo.app` `/download/*`

- **Purpose:** Download signed Continuo disk images
- **Trigger:** A user opens a download or release link, or chooses Check Now
- **Payload:** Signed DMG binary and download request metadata
- **Can disable?:** Manual downloads are user-initiated; automatic update checks can be disabled in Settings
- **Input content?:** No

### `usecontinuo.app` `/changelog/*`

- **Purpose:** Show the release index and per-version changelog
- **Trigger:** A user opens a changelog link
- **Payload:** Static HTML, JSON, or Markdown release metadata
- **Can disable?:** User-initiated only
- **Input content?:** No

### `usecontinuo.app` `/api/trial/*`

- **Purpose:** Start and check the 14-day Pro trial
- **Trigger:** Trial activation or a trial-status refresh
- **Payload:** One-way device hash, trial timestamps, and signed trial token
- **Can disable?:** Yes: stay on the Free tier
- **Input content?:** No

### `usecontinuo.app` (documentation and support links)

- **Purpose:** Open Continuo documentation and support pages from in-app help
- **Trigger:** A user opens a help link
- **Payload:** Static web pages
- **Can disable?:** User-initiated only
- **Input content?:** No

## Verification status

The security transport package itself adds no analytics or telemetry endpoint.
The destinations above describe expected application flows and must be checked
against the signed release with traffic capture before public launch.

Browser visits to the marketing site, support email, and Lemon Squeezy checkout
are user-directed website or third-party flows rather than app transport. They
carry only information the user or browser supplies, never peer input content.
