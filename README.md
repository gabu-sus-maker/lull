# LULL — server, accounts and co-op

This folder is everything Cloudflare needs. You don't install anything: you put these files in a GitHub repository, and Cloudflare builds the server from it. After that, every time you upload a changed file to GitHub, Cloudflare redeploys by itself.

```
wrangler.toml        settings Cloudflare reads (names, database classes, limits)
package.json         pins the Cloudflare tool version Cloudflare's builder uses
src/worker.js        the server: accounts, cloud saves, co-op rooms
public/index.html    the game (the same single file you already play)
public/test.html     connection test page  → your-address/test
public/admin.html    your admin page       → your-address/admin
tests/               the tests I run (you can ignore these)
game/                the game's source code and build script (backup — see "Updating")
```

---

## 1. Put it on GitHub (5 minutes)

1. Sign in at **github.com**.
2. Top right **+** → **New repository**.
   - Name: **`lull`** (it must match the name in `wrangler.toml`).
   - **Private** is fine and recommended.
   - Don't tick any of the "Add a README / .gitignore / licence" boxes.
   - **Create repository**.
3. On the empty repository page, click the link **uploading an existing file**.
4. Unzip `lull-server.zip` on your computer. Open the unzipped folder, select **everything inside it** (the files *and* the `src`, `public`, `tests`, `game` folders) and drag it all onto the GitHub page. Folders keep their structure when you drag them.
5. Wait until every file is listed, then press **Commit changes**.

Check: the repository's front page should show `wrangler.toml`, `package.json`, `README.md` and the folders `src`, `public`, `tests` and `game`.

## 2. Connect it to Cloudflare (5 minutes)

1. Sign in at **dash.cloudflare.com**. Because of Cloudflare's age rules, if you're under 18 the account should be in a parent's name.
2. Left menu: **Workers & Pages** → **Create application**.
3. Choose to import from **GitHub**.
   - If asked, let Cloudflare connect to your GitHub account.
   - When GitHub asks which repositories Cloudflare may see, you can choose **Only select repositories** → `lull`.
4. Pick the `lull` repository.
   - Keep the project name **`lull`**.
   - Leave the build command empty.
   - The deploy command should be `npx wrangler deploy` (the default).
5. Press **Save and Deploy**.
6. Wait for the build to finish (about a minute). Cloudflare shows your address, something like **`https://lull.yourname.workers.dev`**.

If the build fails: open the build log, copy the red lines, and send them to me.

## 3. Set your admin key (2 minutes)

The admin key lets **you** (and nobody else) make password-reset codes and see usage. It lives only in Cloudflare, never in the game file.

1. **Workers & Pages** → `lull` → **Settings** → **Variables and Secrets** → **Add**.
2. Type: **Secret**. Name: **`ADMIN_KEY`**. Value: a long phrase only you know, at least 12 characters (for example four random words and a number). **Save** (or **Deploy**).
3. Write it down somewhere safe. If you lose it, just set a new one the same way.

## 4. Check it works

| Open | You should see |
|---|---|
| `https://lull.yourname.workers.dev` | The game. The title menu now has **Together (online)** and **Sign in**. |
| `…/test` | Three green lines and "Good for co-op". |
| `…/admin` | The admin page. Type your key and press **Show usage**: it should list today's date. |

---

## Playtest checklist (please do this before I build the co-op story)

This is the step Blueprint Siege never had: real networks, real friends.

**A. On each network (school Wi-Fi, home Wi-Fi, a phone hotspot)**

Open `…/test`. Note:
- what the three lines say;
- the "verdict".

**B. With 2–4 friends** (everyone signs up first: *Sign in* → *Create an account*)

1. One person: **Together → Make a room**, then reads the 4-letter code out loud.
2. Everyone else: **Together → Join a room**, then types the code.
3. Pick characters (← →), everyone presses **I'm ready**, the host presses **Start**.
4. In the network test level, try each thing below and note anything that looks wrong or laggy.
   - [ ] You can all see each other moving smoothly.
   - [ ] Someone takes a bottle; it disappears for everyone.
   - [ ] **I** (bag), pick an item, **G**: hand it to a friend standing next to you.
   - [ ] **T + number**: says something aloud. Only people near you should see it.
   - [ ] **R + number**: radio. Everyone on the channel hears it, and there's no name on it, only a colour.
   - [ ] **C**: change channel. People on other channels shouldn't hear you.
   - [ ] **R + Space Space Space**: a click code.
   - [ ] Fight a Hollowed together. Do your hits register? Do theirs hurt when it looks like they should?
   - [ ] Let someone get knocked down. Another player holds **E** next to them to help them up.
   - [ ] Turn a torch on (**F**) in the dark east end. Friends should see your beam.
   - [ ] The host quits (**Esc → Leave the game**). The game should carry on for everyone else.
   - [ ] Someone closes their tab and rejoins with the same code. They should come back with their bag.

**C. Afterwards, tell me:**
- what broke or felt off;
- the **/test** results from each place;
- from `/admin` → **Show usage**: today's *messages* number;
- from the Cloudflare dashboard (`lull` → **Metrics**, or Durable Objects): the *requests* number for the same day. Comparing the two settles the budget question below.

---

## Accounts: what's stored and what isn't

- **Stored:** username, a *hash* of the password (PBKDF2-SHA256, 100,000 rounds, random salt), the cloud save, and the date each account was created. **Nobody can read the passwords, including you.** That's deliberate: if a friend reused a password from somewhere else, it's still safe.
- **Not stored:** emails, real names, IP addresses (only a daily count of new accounts per network, to stop spam).
- **Wrong passwords:** after 5, that username is locked for 1 minute, then 2, 4… up to an hour.
- **Forgotten password:** open `/admin`, type their username, press **Make reset code**, and tell them the 8-letter code in person. They use **Sign in → I have a reset code**. Codes work once, for 24 hours.
- **No free-text chat anywhere.** Only preset phrases, so there's nothing to moderate.
- **Your existing progress is safe.** The first time someone signs in on a computer that already has progress, the game asks whether to attach it to the account. If the two ever disagree, it asks which one to keep, merges the endings either way, and keeps the other copy as a backup on that computer.

## The daily budget (honest version)

The free Cloudflare plan allows 100,000 Durable Object requests a day. I measured the game with four real browsers:

| What the 4 players are doing | Messages per hour |
|---|---|
| Standing around | ~7,000 |
| All walking about | ~70,000 |
| All fighting | ~115,000 |

Cloudflare's paid plan counts 20 WebSocket messages as one request. Its documentation doesn't say whether the free plan does the same:
- **If it does**, you effectively have no limit.
- **If it doesn't**, you get roughly **1–2 hours of busy 4-player co-op per day, shared by everyone**.

The usage figure in `/admin`, compared with Cloudflare's own number, will tell us which is true.

The meter only **warns**: the lobby's connection test shows the percentage used, and nothing is blocked on a guess. If Cloudflare's real limit is ever reached, online play stops working until midnight UTC (1 am UK in winter) and the game says so. Solo and local saving keep working. The fix, if you ever need it, is Workers Paid at $5/month.

To change the warning level, edit `DAILY_BUDGET` in `wrangler.toml`. Edit it on GitHub, not in the Cloudflare dashboard: the dashboard value gets overwritten on the next deploy.

## Updating the game later

When I send a new version:
1. On GitHub, open the folder that changed (usually `public/`).
2. Choose **Add file → Upload files**, drag the new file in (same name replaces the old one), then **Commit changes**.

Cloudflare rebuilds automatically within a minute or two.

The `game/` folder is the game's source code: the `src/*.js` pieces plus `build.py`, which joins them into `public/index.html`. It's in here so that a lost workspace can never lose the game again.

## How it works (one paragraph)

- One Cloudflare **Worker** serves the game and the API.
- One **Durable Object** called `Accounts` holds users, saves and the usage meter in SQLite.
- Each co-op room is its own **Durable Object**, reached by its 4-letter code over a WebSocket (normal HTTPS, port 443, no peer-to-peer).
- The room is the referee. It decides who got a pickup, delivers gifts, and only passes "say aloud" to people standing near the speaker. Radio messages carry no name. The room never sends a player anything they couldn't perceive.
- One player's game (the host) runs the Hollowed. If the host leaves, the next player takes over.
- **Combat timing:** your own game decides whether *you* got hit, and your hits count based on what *your* screen showed. That way lag can't eat your hits.
