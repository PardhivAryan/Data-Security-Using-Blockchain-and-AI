window.Api = (() => {
  const API_BASE = `${window.location.origin}/api`;
  const getToken = () => localStorage.getItem("token") || "";

  const makeHeaders = (isJson = true) => {
    const h = { "Accept": "application/json" };
    if (isJson) h["Content-Type"] = "application/json";
    const t = getToken();
    if (t) h["Authorization"] = `Bearer ${t}`;
    return h;
  };

  const parseOrText = async (res) => {
    const txt = await res.text();
    if (!txt) return null;
    try { return JSON.parse(txt); } catch { return txt; }
  };

  const handle = async (res) => {
    const data = await parseOrText(res);
    if (!res.ok) {
      const msg = (data && data.detail) ? data.detail : (typeof data === "string" ? data : "Request failed");
      throw new Error(`${res.status} ${msg}`);
    }
    return data;
  };

  const post = async (path, body) => {
    const res = await fetch(API_BASE + path, {
      method: "POST",
      headers: makeHeaders(true),
      body: JSON.stringify(body ?? {}),
    });
    return handle(res);
  };

  const safePost = async (path, body) => {
    try { return await post(path, body); } catch { return null; }
  };

  return { post, safePost };
})();