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

### `api.polar.sh` (and related Polar hosts)

- **Purpose:** Payment checkout and the licence customer portal, in a browser
- **Trigger:** A user opens Buy Pro, a Mac seat add-on, or the customer portal, each of which opens a browser
- **Payload:** Payment and account data, handled entirely by Polar
- **Can disable?:** Yes: nothing here runs unless a purchase or portal link is opened
- **Input content?:** No
- **Note:** The application itself never contacts Polar. Licence validation and activation go to the `usecontinuo.app` endpoint below, and only that server talks to Polar. No product identifier is sent from this Mac.

### `usecontinuo.app` `/api/license/*`

- **Purpose:** Validate, activate, restore, and deactivate this Mac's Continuo Pro licence, and list the Macs on it
- **Trigger:** Entering or refreshing a licence in Settings, restoring after a reinstall, activating another Mac, or freeing a seat
- **Payload:** Licence key, one-way device hash, device name, and the signed entitlement response
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

Browser visits to the marketing site, support email, and Polar checkout
are user-directed website or third-party flows rather than app transport. They
carry only information the user or browser supplies, never peer input content.
