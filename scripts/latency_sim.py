"""Latency simulator for EchoWithin realtime netcode (Phase 5 verify step).

TCP forward proxy that adds configurable one-way delay, jitter, and periodic
stalls (mobile-blackout emulation) between a local browser client and a dev
server. Point it at your LOCAL server (never prod)::

    python scripts/latency_sim.py --listen 8611 --target 127.0.0.1 --port 8000 \
        --delay-ms 150 --jitter-ms 40 --stall-every-s 20 --stall-ms 2000

Then open http://localhost:8611 and play Pong/Slime online rooms in two tabs.
Read window.__pongNetstats / window.__slimeNetstats on both sides and compare
against the direct-connection baseline (see commit.md).

Why no packet-loss flag: this is a TCP proxy, so dropping forwarded bytes
would corrupt the TLS/WS stream instead of emulating loss (TCP retransmits
loss itself). Delay + jitter + stalls reproduce the symptoms that matter here
(snapshot gaps, stale ordering, guard holds). For true loss testing use
Windows `clumsy` or Linux `tc netem` instead.

Stdlib only. No secrets, no network calls besides the proxy itself.
"""

import argparse
import asyncio
import random
import sys
import time


async def relay(reader, writer, delay_ms, jitter_ms, stall, tag, stats):
    loop = asyncio.get_running_loop()
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            stats[tag] += len(chunk)
            if stall.get('active'):
                # Blackout: hold (don't drop) so order is preserved, then burst.
                remaining = stall['until'] - loop.time()
                if remaining > 0:
                    await asyncio.sleep(remaining)
            delay = max(0, delay_ms + random.uniform(-jitter_ms, jitter_ms)) / 1000.0
            if delay:
                await asyncio.sleep(delay)
            writer.write(chunk)
            await writer.drain()
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def stall_loop(stall, every_s, stall_ms):
    if not every_s or not stall_ms:
        return
    loop = asyncio.get_running_loop()
    while True:
        await asyncio.sleep(every_s)
        stall['active'] = True
        stall['until'] = loop.time() + stall_ms / 1000.0
        print('[latency_sim] STALL %.1fs (buffering, order preserved)' % (stall_ms / 1000.0), flush=True)
        await asyncio.sleep(stall_ms / 1000.0)
        stall['active'] = False
        print('[latency_sim] stall over, bursting buffered bytes', flush=True)


async def stats_loop(stats, interval_s=10):
    last = dict(stats)
    while True:
        await asyncio.sleep(interval_s)
        up = (stats['up'] - last['up']) / interval_s
        down = (stats['down'] - last['down']) / interval_s
        print('[latency_sim] throughput up=%.0f B/s down=%.0f B/s (totals up=%d down=%d)' % (
            up, down, stats['up'], stats['down']), flush=True)
        last = dict(stats)


async def handle(client_r, client_w, args, stall, stats):
    try:
        server_r, server_w = await asyncio.open_connection(args.target, args.port)
    except Exception as exc:
        print('[latency_sim] cannot reach %s:%s: %s' % (args.target, args.port, exc), flush=True)
        client_w.close()
        return
    peer = client_w.get_extra_info('peername')
    print('[latency_sim] relay %s <-> %s:%s' % (peer, args.target, args.port), flush=True)
    stats['conns'] += 1
    try:
        await asyncio.gather(
            relay(client_r, server_w, args.delay_ms, args.jitter_ms, stall, 'up', stats),
            relay(server_r, client_w, args.delay_ms, args.jitter_ms, stall, 'down', stats),
        )
    finally:
        stats['conns'] -= 1
        for w in (server_w, client_w):
            try:
                w.close()
            except Exception:
                pass


async def amain(args):
    stall = {'active': False, 'until': 0.0}
    stats = {'up': 0, 'down': 0, 'conns': 0}
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, args, stall, stats), '127.0.0.1', args.listen)
    print('[latency_sim] listening on 127.0.0.1:%d -> %s:%d '
          'delay=%dms jitter=%dms stall=%dms/%ds' % (
              args.listen, args.target, args.port,
              args.delay_ms, args.jitter_ms, args.stall_ms, args.stall_every_s), flush=True)
    print('[latency_sim] open http://127.0.0.1:%d in TWO tabs and play' % args.listen, flush=True)
    async with server:
        await asyncio.gather(
            server.serve_forever(),
            stall_loop(stall, args.stall_every_s, args.stall_ms),
            stats_loop(stats),
        )


def main(argv=None):
    p = argparse.ArgumentParser(description='EchoWithin netcode latency simulator')
    p.add_argument('--listen', type=int, default=8611)
    p.add_argument('--target', default='127.0.0.1')
    p.add_argument('--port', type=int, default=8000)
    p.add_argument('--delay-ms', type=int, default=150,
                   help='base one-way delay (Denmark->Nairobi ~150ms)')
    p.add_argument('--jitter-ms', type=int, default=40)
    p.add_argument('--stall-every-s', type=int, default=0,
                   help='0 disables stalls; e.g. 20 for a stall every 20s')
    p.add_argument('--stall-ms', type=int, default=2000)
    args = p.parse_args(argv)
    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        print('\n[latency_sim] stopped', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
