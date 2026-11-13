// Simple bar chart for the Overview timeline — no external dependencies.
(function () {
  var canvas = document.getElementById("timeline");
  if (!canvas) return;
  var points;
  try {
    points = JSON.parse(canvas.dataset.points || "[]");
  } catch (e) {
    return;
  }
  if (!points.length) return;

  var ctx = canvas.getContext("2d");
  var W = canvas.width, H = canvas.height, pad = 34;
  var max = Math.max.apply(null, points.map(function (p) { return p.packets; }));
  var bw = (W - pad * 2) / points.length;

  ctx.strokeStyle = "#30363d";
  ctx.fillStyle = "#8b949e";
  ctx.font = "11px system-ui, sans-serif";
  ctx.textAlign = "center";

  points.forEach(function (p, i) {
    var h = max ? (p.packets / max) * (H - pad * 2) : 0;
    var x = pad + i * bw + 2;
    ctx.fillStyle = p.packets > 40 ? "#f85149" : "#58a6ff";
    ctx.fillRect(x, H - pad - h, bw - 4, h);
    ctx.fillStyle = "#8b949e";
    ctx.fillText(p.packets, x + (bw - 4) / 2, H - pad - h - 4);
    ctx.fillText(p.minute.slice(11), x + (bw - 4) / 2, H - 12);
  });
})();
