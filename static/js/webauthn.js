window.WebAuthn = (() => {
  const b64urlToBuf = (b64url) => {
    const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
    const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
    const str = atob(b64);
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
    return bytes.buffer;
  };

  const bufToB64url = (buf) => {
    const bytes = new Uint8Array(buf);
    let str = "";
    for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };

  const prepRegistration = (publicKey) => {
    const pk = structuredClone(publicKey);
    pk.challenge = b64urlToBuf(pk.challenge);
    pk.user.id = b64urlToBuf(pk.user.id);
    if (pk.excludeCredentials) {
      pk.excludeCredentials = pk.excludeCredentials.map(c => ({ ...c, id: b64urlToBuf(c.id) }));
    }
    return pk;
  };

  const prepAuthentication = (publicKey) => {
    const pk = structuredClone(publicKey);
    pk.challenge = b64urlToBuf(pk.challenge);
    if (pk.allowCredentials) {
      pk.allowCredentials = pk.allowCredentials.map(c => ({ ...c, id: b64urlToBuf(c.id) }));
    }
    return pk;
  };

  const createCredential = async (publicKey) => {
    if (!window.PublicKeyCredential) throw new Error("WebAuthn not supported in this browser.");
    const pk = prepRegistration(publicKey);
    const cred = await navigator.credentials.create({ publicKey: pk });

    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        attestationObject: bufToB64url(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : undefined,
      }
    };
  };

  const getAssertion = async (publicKey) => {
    if (!window.PublicKeyCredential) throw new Error("WebAuthn not supported in this browser.");
    const pk = prepAuthentication(publicKey);
    const cred = await navigator.credentials.get({ publicKey: pk });

    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        authenticatorData: bufToB64url(cred.response.authenticatorData),
        signature: bufToB64url(cred.response.signature),
        userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
      }
    };
  };

  return { createCredential, getAssertion };
})();