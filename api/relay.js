// Relay: fetches the real subscription with one fixed device identity.
// Environment variables (Vercel -> Settings -> Environment Variables):
//   PANEL_BASE, HWID, USER_AGENT, DEVICE_OS, VER_OS, DEVICE_MODEL

const PASS_HEADERS = [
  "content-type",
  "subscription-userinfo",
  "profile-title",
  "profile-update-interval",
  "profile-web-page-url",
  "support-url",
  "x-hwid-active",
  "x-hwid-not-supported",
  "x-hwid-max-devices-reached",
  "x-hwid-limit",
];

export default async function handler(req, res) {
  const token = String(req.query.token || "").replace(/^\/+/, "");
  const base = (process.env.PANEL_BASE || "").replace(/\/+$/, "");
  if (!token || !base) {
    res.status(400).send("misconfigured");
    return;
  }

  const headers = {
    "x-hwid": process.env.HWID || "",
    "user-agent": process.env.USER_AGENT || "",
  };
  if (process.env.DEVICE_OS) headers["x-device-os"] = process.env.DEVICE_OS;
  if (process.env.VER_OS) headers["x-ver-os"] = process.env.VER_OS;
  if (process.env.DEVICE_MODEL) headers["x-device-model"] = process.env.DEVICE_MODEL;

  try {
    const upstream = await fetch(`${base}/${token}`, { headers, redirect: "follow" });

    res.status(upstream.status);
    res.setHeader("cache-control", "no-store");
    for (const name of PASS_HEADERS) {
      const value = upstream.headers.get(name);
      if (value) res.setHeader(name, value);
    }

    const buffer = Buffer.from(await upstream.arrayBuffer());
    res.send(buffer);
  } catch {
    res.status(502).send("upstream error");
  }
}
