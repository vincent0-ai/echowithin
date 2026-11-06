/*
 * Shared connection-quality chip for realtime games.
 *
 * Probes RTT with the existing net_ping / net_pong socket pair and colours the
 * badge: green is LAN-grade (< 90 ms), amber is playable (< 180 ms), red means
 * input delay is noticeable enough to affect a game.
 *
 * Usage (after the chip element exists and the socket may be created later):
 *   EWNetQuality.attach(() => state.socket, {
 *     isActive: () => state.mode === 'online' && !!state.roomId,
 *     onSample: (ms) => { state.rttMs = ms; }
 *   });
 */
(function () {
  'use strict';

  var GREEN = '#15803d';
  var AMBER = '#a16207';
  var RED = '#b91c1c';
  var PROBE_MS = 2000;
  var TICK_MS = 500;

  function now() {
    return (typeof performance !== 'undefined' && performance.now)
      ? performance.now()
      : Date.now();
  }

  function attach(getSocket, options) {
    options = options || {};
    var chipId = options.chipId || 'net-quality';
    var isActive = options.isActive || function () {
      var s = getSocket && getSocket();
      return !!(s && s.connected);
    };
    var onSample = options.onSample || null;
    var rtt = 0;
    var lastPing = -Infinity; // probe on the first active tick, then every 2 s
    var boundSocket = null;

    function paint() {
      var el = document.getElementById(chipId);
      if (!el) return;
      if (!isActive()) {
        el.style.display = 'none';
        return;
      }
      var ms = Math.round(rtt || 0);
      var color = ms <= 0 ? 'var(--text-secondary)' : (ms < 90 ? GREEN : (ms < 180 ? AMBER : RED));
      var label = ms <= 0 ? 'Connection quality'
        : (ms < 90 ? 'Connection quality: excellent'
          : (ms < 180 ? 'Connection quality: playable' : 'Connection quality: poor'));
      el.style.display = 'inline-flex';
      el.style.alignItems = 'center';
      el.style.color = color;
      el.style.borderColor = color;
      el.textContent = ms > 0 ? 'RTT ' + ms + ' ms' : 'RTT \u2014';
      el.title = label;
      el.setAttribute('aria-label', label);
    }

    function onPong(data) {
      var sent = data && Number(data.t);
      if (!Number.isFinite(sent)) return;
      var sample = Math.max(0, now() - sent);
      rtt = rtt ? Math.round(rtt * 0.7 + sample * 0.3) : Math.round(sample);
      if (onSample) onSample(rtt);
      paint();
    }

    function tick() {
      var socket = getSocket && getSocket();
      if (!socket) {
        paint();
        return;
      }
      if (boundSocket !== socket) {
        boundSocket = socket;
        if (typeof socket.on === 'function') socket.on('net_pong', onPong);
      }
      if (!isActive()) {
        paint();
        return;
      }
      if (socket.connected === false) {
        rtt = 0;
        paint();
        return;
      }
      var t = now();
      if (t - lastPing > PROBE_MS) {
        lastPing = t;
        try {
          socket.emit('net_ping', { t: t });
        } catch (_) {}
      }
      paint();
    }

    paint();
    var timer = setInterval(tick, TICK_MS);
    if (typeof window !== 'undefined' && window.addEventListener) {
      window.addEventListener('beforeunload', function () {
        clearInterval(timer);
      });
    }
    return { refresh: paint };
  }

  window.EWNetQuality = { attach: attach };
})();
