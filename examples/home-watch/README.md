# home-watch

The GOOSE Watch pattern for your home or small-office network, in one file (`home.ts`). It listens to ARP, the "who has this address?" chatter every device on a LAN makes, and it tells you three things:

| Rule | Severity | What it means |
|---|---|---|
| `NEW_DEVICE` | 1 | A device you haven't listed joined the network. |
| `ARP_SCAN` | 2 | One device asked for 20+ addresses in 10 s: someone is mapping your network. |
| `ROUTER_IMPERSONATION` | 3 | A device that isn't your router claims the router's address (ARP spoofing, man-in-the-middle). |

A local AI can add a reading with honest doubt. **It never decides.** Severity 2 and 3 always say "a human checks now", and so does any AI reading that is unsure or suspicious.

It is **passive**: it only listens and never sends a packet (a test checks this).

## Try it in one minute (no network access needed)

You need [bun](https://bun.sh) and `tshark` (Wireshark's command-line tool).

```sh
bun home.ts demo
```

It writes a demo night at home (`home-demo/night.pcap`) and watches it. At 03:12 an unknown phone joins. At 03:14 an unknown laptop scans the network, and at 03:15 it pretends to be the router.

With a local AI (optional; [Ollama](https://ollama.com) ≥ 0.35 with a decision model such as `nimble` or `tev1`):

```sh
bun home.ts demo --model nimble:latest
```

On the synthetic demo, nimble read the scan as `network_scan 0.99` and the fake router as `impersonation 1.00`. It also read the intruder's first appearance as a harmless `new_gadget_or_guest 0.91`. The scan rule caught the intruder two lines later. That is the point of the pattern.

## Use it on your own network

1. **Learn what's normal.** Capture ARP for a day, then make your device list:

   ```sh
   sudo tshark -i wlan0 -f arp -a duration:86400 -w normal.pcap
   bun home.ts learn normal.pcap --gateway 192.168.1.1 > known.json
   ```

   Open `known.json` and give each MAC a name you recognise ("kitchen tablet", "printer"). Delete anything you don't recognise; you'll find out what it is soon enough.

2. **Watch live:**

   ```sh
   sudo "$(which bun)" home.ts watch --iface wlan0 --known known.json --model nimble:latest
   ```

   Capturing needs root or membership of the `wireshark` group. Run it on a machine that is always on: a Raspberry Pi, a home server or the Home Assistant host.

3. **Only on networks you own or manage.** Capturing other people's traffic without permission is illegal in most places.

## Make it yours

The whole pattern is four small parts. Change any one of them:

- **Rules** (`class Rules`): add your own. For example, raise `NEW_DEVICE` to severity 2 between 00:00 and 06:00, or alert when a known camera talks to an address outside your LAN.
- **Facts** (`facts()`): measure things in code and hand the AI the results, never raw packets. Phones' private Wi-Fi addresses have bit `0x02` set in the first byte, so that is a fact, not a guess.
- **Causes** (`CAUSES`): the plain-language options the AI chooses between. Keep them few and non-overlapping.
- **Who decides** (`needsHuman()`): code, never the AI.

Phones with "private Wi-Fi address" turned on show up as a new device on each network, and sometimes again later. That's expected: list the new address, or turn the feature off for your home network.

Read `docs/PATTERN.md` in the repo for the pattern applied to any domain.
