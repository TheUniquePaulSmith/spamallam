/* WebAuthn <-> JSON helpers (base64url encoding per the WebAuthn JSON format). */
"use strict";

function b64urlToBuf(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  const bin = atob(s + pad);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function prepareCreationOptions(options) {
  const pk = options.publicKey ? options.publicKey : options;
  pk.challenge = b64urlToBuf(pk.challenge);
  pk.user.id = b64urlToBuf(pk.user.id);
  (pk.excludeCredentials || []).forEach((c) => { c.id = b64urlToBuf(c.id); });
  return { publicKey: pk };
}

function prepareRequestOptions(options) {
  const pk = options.publicKey ? options.publicKey : options;
  pk.challenge = b64urlToBuf(pk.challenge);
  (pk.allowCredentials || []).forEach((c) => { c.id = b64urlToBuf(c.id); });
  return { publicKey: pk };
}

function credentialToJSON(cred) {
  const out = {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults(),
    authenticatorAttachment: cred.authenticatorAttachment || null,
    response: {},
  };
  const r = cred.response;
  out.response.clientDataJSON = bufToB64url(r.clientDataJSON);
  if (r.attestationObject) out.response.attestationObject = bufToB64url(r.attestationObject);
  if (r.authenticatorData) out.response.authenticatorData = bufToB64url(r.authenticatorData);
  if (r.signature) out.response.signature = bufToB64url(r.signature);
  if (r.userHandle) out.response.userHandle = bufToB64url(r.userHandle);
  if (r.getTransports) out.response.transports = r.getTransports();
  return out;
}
