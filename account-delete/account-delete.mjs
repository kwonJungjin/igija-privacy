// 생성 이유: 웹의 본인확인·삭제 확인·읽기 전용 영수증을 닫힌 경로로 분리한다. 실제 배포는 별도다.
import { config as defaultConfig } from "./config.mjs";

export const CALLBACK = "https://kwonjungjin.github.io/igija-privacy/account-delete/";
export const CONTRACT = "IGIJA_ACCOUNT_CONTROL_V14_WAVE2_1";
export const ATTEMPT_KEY = "igija.account-delete.pkce.v1";
export const RECEIPT_KEY = "igija.account-delete.receipt.v1";
const DAY = 86_400_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HANDLE = /^[0-9a-f]{64}$/;
const ROOT_STATES = ["NOT_ENROLLED", "ACTIVE", "DELETE_PENDING", "AUTH_DELETE_PENDING", "DELETED"];
const OP_STATES = ["PENDING", "WAITING_EFFECTS", "SUCCESS", "FAILED", "UNKNOWN", "CANCELLED", "ABSORBED"];
const positive = n => Number.isSafeInteger(n) && n > 0;
const base64 = bytes => btoa(String.fromCharCode(...bytes));
const url64 = bytes => base64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
const hex = bytes => Array.from(bytes, n => n.toString(16).padStart(2, "0")).join("");
// 원문 없이 정해진 오류 종류만 전달한다.
function fail(code) { throw new Error(code); }
// 응답 객체의 필드가 계약과 정확히 일치하는지 검사한다.
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
    Object.keys(value).sort().join() !== [...keys].sort().join()) fail("INVALID_RESPONSE");
}
// 명시 ON과 공개 프로젝트 설정이 모두 맞을 때만 웹 전송을 연다.
function validConfig(c) {
  return c?.enabled === true && /^[a-z0-9]{20}$/.test(c.projectRef) &&
    /^sb_publishable_[A-Za-z0-9_-]{12,512}$/.test(c.publishableKey);
}

// 계정과 기기 좌표의 조합을 검증한 뒤 화면에 필요한 상태만 남긴다.
export function parseRootStatus(value) {
  exact(value, ["enrolled", "root_state", "root_generation", "active_device_subject_id", "active_device_generation"]);
  const absent = value.active_device_subject_id === null && value.active_device_generation === null;
  const device = UUID.test(value.active_device_subject_id) && positive(value.active_device_generation);
  if (typeof value.enrolled !== "boolean" || !ROOT_STATES.includes(value.root_state) || (!absent && !device)) fail("INVALID_RESPONSE");
  if (value.root_state === "NOT_ENROLLED") {
    if (value.enrolled || value.root_generation !== null || !absent) fail("INVALID_RESPONSE");
  } else if (!value.enrolled || !positive(value.root_generation) ||
    value.root_state === "ACTIVE" && !device || value.root_state === "DELETED" && !absent) fail("INVALID_RESPONSE");
  return Object.freeze({ ...value });
}
// 원래 요청의 결과와 완료 차단 여부만 받아들인다.
export function parseReceipt(value, operationId) {
  exact(value, ["operation_id", "state", "completion_blocked"]);
  if (value.operation_id !== operationId || !["PENDING", "SUCCESS", "UNKNOWN"].includes(value.state) ||
    typeof value.completion_blocked !== "boolean") fail("INVALID_RESPONSE");
  return Object.freeze({ ...value });
}
// 접수 응답을 검증하며 최종 삭제 완료 증거로 사용하지 않는다.
function parseSubmission(value, id) {
  const extra = value && (Object.hasOwn(value, "absorbed_device_replacements") || Object.hasOwn(value, "adopted_child_operations"));
  exact(value, extra ? ["operation_id", "state", "absorbed_device_replacements", "adopted_child_operations"] : ["operation_id", "state"]);
  if (value.operation_id !== id || !OP_STATES.includes(value.state) || extra &&
    ![value.absorbed_device_replacements, value.adopted_child_operations].every(n => Number.isSafeInteger(n) && n >= 0)) fail("INVALID_RESPONSE");
  return value;
}

// 저장소는 PKCE 임시 의도와 결과 조회 능력만 보관한다. access/refresh/provider token은 쓰지 않는다.
export function createDeleteClient(configuration, dependencies) {
  const c = Object.freeze({ ...configuration });
  const { storage, fetcher, crypto: crypt, history, location } = dependencies;
  const now = dependencies.now ?? Date.now;
  const origin = validConfig(c) ? `https://${c.projectRef}.supabase.co` : null;
  let epoch = 0, auth = null, root = null, confirmation = null, busy = false, controller = null;
  let receipt = null, receiptResult = null, storageProblem = false;
  let message = origin ? "사용하던 카카오 계정으로 본인확인해 주세요." : "현재 웹 계정 삭제는 준비 중입니다.";
  const snapshot = () => Object.freeze({ enabled: !!origin, busy, signedIn: auth !== null,
    root, confirming: confirmation !== null, hasReceipt: receipt !== null,
    receiptExpiresAt: receipt?.expiresAt ?? null, receiptResult, storageProblem, message });
  // 기능 OFF 또는 저장소 손상 시 새 동작을 막는다.
  function needEnabled() { if (!origin) fail("SAFE_OFF"); if (storageProblem) fail("STORAGE_UNAVAILABLE"); }
  // 읽기 확인까지 끝난 저장만 네트워크 전송의 선행조건으로 인정한다.
  function persist(key, value) {
    try { const raw = JSON.stringify(value); storage.setItem(key, raw); if (storage.getItem(key) !== raw) fail("STORAGE_UNAVAILABLE"); }
    catch { fail("STORAGE_UNAVAILABLE"); }
  }
  // 본인확인 임시 의도와 명시 회수한 조회 정보만 지운다.
  function remove(key) {
    try { storage.removeItem(key); if (storage.getItem(key) !== null) fail("STORAGE_UNAVAILABLE"); }
    catch { fail("STORAGE_UNAVAILABLE"); }
  }
  // 탭 저장소의 제한된 JSON만 읽고 손상을 빈 기록으로 바꾸지 않는다.
  function load(key) {
    try { const raw = storage.getItem(key); if (raw === null) return null; if (raw.length > 4096) fail("STORAGE_UNAVAILABLE"); return JSON.parse(raw); }
    catch { fail("STORAGE_UNAVAILABLE"); }
  }
  // 본인확인 세션이 없거나 만료되면 삭제 확인을 닫는다.
  function checkAuth() {
    if (!auth || auth.expiresAt <= now()) { auth = null; root = null; confirmation = null; fail("AUTH_REQUIRED"); }
  }
  // 계정 전환이나 종료 뒤 도착한 응답은 버린다.
  function current(captured) { if (captured !== epoch) fail("STALE_RESPONSE"); }
  // 진행 중 요청을 취소하고 메모리 인증 상태를 끝낸다.
  function invalidate() {
    epoch++; controller?.abort(); controller = null; auth = null; root = null; confirmation = null; busy = false;
  }
  // 한 번에 한 사용자 동작만 실행하고 수명 좌표를 고정한다.
  async function action(work) {
    needEnabled(); if (busy) fail("BUSY"); busy = true;
    const captured = epoch;
    try { return await work(captured); }
    finally { if (captured === epoch) busy = false; }
  }
  // 같은 프로젝트의 고정 경로로만 유한 요청을 보내고 응답 크기를 제한한다.
  async function post(path, body, jwt, captured) {
    current(captured);
    const local = new AbortController(); controller = local;
    const timer = setTimeout(() => local.abort(), 12000);
    try {
      const headers = { apikey: c.publishableKey, "content-type": "application/json" };
      if (jwt !== null) headers.authorization = `Bearer ${jwt}`;
      const response = await fetcher(origin + path, { method: "POST", headers, body: JSON.stringify(body),
        signal: local.signal, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" });
      current(captured);
      if (!response.ok || response.headers.get("content-type")?.split(";")[0].trim() !== "application/json") fail("REQUEST_UNCONFIRMED");
      const reader = response.body?.getReader(); if (!reader) fail("INVALID_RESPONSE");
      let size = 0; const chunks = [];
      try {
        while (true) {
          const part = await reader.read(); current(captured);
          if (local.signal.aborted) fail("REQUEST_UNCONFIRMED");
          if (part.done) break;
          size += part.value.byteLength; if (size > 65536) fail("INVALID_RESPONSE"); chunks.push(part.value);
        }
      } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const part of chunks) { bytes.set(part, offset); offset += part.length; }
      const result = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      current(captured); return result;
    } catch (error) {
      current(captured); throw error;
    } finally { clearTimeout(timer); if (controller === local) controller = null; }
  }
  // 상태 조회와 명시 삭제 요청 두 동작 외에는 전송하지 않는다.
  function control(actionName, payload, captured) {
    if (!["ROOT_STATUS", "ROOT_DELETE_REQUEST"].includes(actionName)) fail("ACTION_INVALID");
    checkAuth();
    return post("/functions/v1/account-delete-request", { contract_version: CONTRACT, action: actionName, payload }, auth.jwt, captured);
  }
  // 원래 프로젝트와 요청에 묶인 결과 조회 정보를 복원한다.
  function readSavedReceipt() {
    const saved = load(RECEIPT_KEY);
    if (!saved) return;
    exact(saved, ["version", "projectRef", "operationId", "handle", "createdAt", "expiresAt"]);
    if (saved.version !== 1 || saved.projectRef !== c.projectRef || !UUID.test(saved.operationId) || !HANDLE.test(saved.handle) ||
      !positive(saved.createdAt) || saved.createdAt > now() || saved.expiresAt !== saved.createdAt + 30 * DAY) fail("STORAGE_UNAVAILABLE");
    receipt = Object.freeze(saved);
  }
  // 콜백 코드와 일회 본인확인 의도를 검증하고 결과 조회 정보를 복원한다.
  async function initialize() {
    // Query/fragment는 검증·저장소·네트워크 이전에 제거한다. 반환 문자열이나 로그에 code를 넣지 않는다.
    const rawUrl = location.href;
    const hadCallback = rawUrl.includes("?") || rawUrl.includes("#");
    if (hadCallback) history.replaceState(null, "", CALLBACK);
    if (!origin) return snapshot();
    try { readSavedReceipt(); }
    catch { storageProblem = true; message = "이 탭의 결과 확인 정보를 읽지 못했습니다. 삭제 요청은 보내지 않았습니다."; return snapshot(); }
    if (!hadCallback) { if (receipt) message = "이 탭에 보관된 삭제 요청이 있습니다. 결과 확인 버튼을 눌러 주세요."; return snapshot(); }
    const initialEpoch = epoch;
    try {
      await action(async captured => {
        const attempt = load(ATTEMPT_KEY);
        // 인증 의도는 교환 전에 한 번만 소비한다. 삭제할 수 없으면 교환하지 않는다.
        remove(ATTEMPT_KEY);
        exact(attempt, ["version", "projectRef", "verifier", "nonce", "startedAt"]);
        if (attempt.version !== 1 || attempt.projectRef !== c.projectRef || !/^[A-Za-z0-9_-]{43}$/.test(attempt.verifier) ||
          !/^[A-Za-z0-9_-]{43}$/.test(attempt.nonce) || !positive(attempt.startedAt) || now() < attempt.startedAt || now() - attempt.startedAt > 600000) fail("CALLBACK_INVALID");
        const url = new URL(rawUrl);
        if (rawUrl.length > 4096 || url.origin + url.pathname !== CALLBACK || url.username || url.password || url.port) fail("CALLBACK_INVALID");
        const entries = [...url.searchParams];
        if (url.hash) {
          if (entries.length !== 1 || entries[0][0] !== "igija_flow") fail("CALLBACK_INVALID");
          entries.push(...new URLSearchParams(url.hash.slice(1)));
        }
        if (entries.length < 2 || entries.length > 5 || new Set(entries.map(([key]) => key)).size !== entries.length ||
          entries.some(([key]) => !["igija_flow", "code", "error", "error_code", "error_description"].includes(key))) fail("CALLBACK_INVALID");
        const params = Object.fromEntries(entries);
        if (params.igija_flow !== attempt.nonce) fail("CALLBACK_INVALID");
        if (params.error && !params.code) { message = "카카오 본인확인을 완료하지 않았습니다. 삭제 요청은 보내지 않았습니다."; return; }
        if (url.hash || entries.length !== 2 || !/^[A-Za-z0-9_-]{1,2048}$/.test(params.code ?? "")) fail("CALLBACK_INVALID");
        const token = await post("/auth/v1/token?grant_type=pkce", { auth_code: params.code, code_verifier: attempt.verifier }, null, captured);
        if (typeof token.access_token !== "string" || token.access_token.length > 8192 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token.access_token) ||
          token.token_type?.toLowerCase() !== "bearer") fail("AUTH_REQUIRED");
        const part = token.access_token.split(".")[1];
        const claims = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(atob(part.replaceAll("-", "+").replaceAll("_", "/")), char => char.charCodeAt(0))));
        if (claims.iss !== origin + "/auth/v1" || !UUID.test(claims.sub) || claims.role !== "authenticated" || claims.is_anonymous === true ||
          !positive(claims.exp) || claims.exp * 1000 <= now() || (token.user?.id !== undefined && token.user.id !== claims.sub)) fail("AUTH_REQUIRED");
        current(captured);
        auth = Object.freeze({ jwt: token.access_token, subject: claims.sub, expiresAt: claims.exp * 1000 });
        message = "본인확인을 마쳤습니다. ‘내 이기자 계정 상태 확인’을 눌러 주세요.";
      });
    } catch { if (epoch === initialEpoch) message = "본인확인을 마치지 못했습니다. 삭제 요청은 보내지 않았습니다. 본인확인부터 다시 진행해 주세요."; }
    return snapshot();
  }
  // 임시 PKCE와 nonce를 먼저 저장한 뒤 고정 카카오 인증 주소를 만든다.
  async function beginOAuth() {
    needEnabled(); if (busy) fail("BUSY"); invalidate();
    return action(async captured => {
      const verifier = url64(crypt.getRandomValues(new Uint8Array(32)));
      const nonce = url64(crypt.getRandomValues(new Uint8Array(32)));
      const challenge = url64(new Uint8Array(await crypt.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
      current(captured);
      persist(ATTEMPT_KEY, { version: 1, projectRef: c.projectRef, verifier, nonce, startedAt: now() });
      const url = new URL(origin + "/auth/v1/authorize");
      url.search = new URLSearchParams({ provider: "kakao", redirect_to: `${CALLBACK}?igija_flow=${nonce}`,
        code_challenge: challenge, code_challenge_method: "s256", scope: "" }).toString();
      return url.href;
    });
  }
  // 인증된 현재 계정 상태만 조회하며 가입이나 동의를 만들지 않는다.
  async function refreshRoot() {
    return action(async captured => {
      checkAuth(); root = null; confirmation = null;
      const result = parseRootStatus(await control("ROOT_STATUS", {}, captured)); current(captured); root = result;
      message = result.root_state === "NOT_ENROLLED" ? "이 카카오 계정에 연결된 이기자 계정이 없습니다. 삭제 요청은 보내지 않습니다. 본인확인 과정의 인증 기록까지 없다는 뜻은 아닙니다." :
        result.root_state === "ACTIVE" ? "이기자 계정을 확인했습니다. 아래 삭제 범위를 읽어 주세요." :
        result.root_state === "DELETED" ? "이 계정의 삭제 상태가 확인됐습니다. 보관된 요청이 있다면 결과 확인 버튼으로 최종 결과를 조회해 주세요." :
        "계정 삭제가 진행 중입니다. 보관된 요청의 결과를 확인해 주세요. 새 삭제 요청은 보내지 않습니다.";
      return snapshot();
    });
  }
  // 사용자가 확인한 주체와 세대를 마지막 확인창에 결박한다.
  function prepareDelete(accepted) {
    needEnabled(); checkAuth(); if (busy || accepted !== true || receipt || root?.root_state !== "ACTIVE") fail("CONFIRMATION_REQUIRED");
    confirmation = Object.freeze({ epoch, subject: auth.subject, generation: root.root_generation });
    return snapshot();
  }
  // 조회 정보를 먼저 보존하고 명시 확인한 삭제 요청을 한 번 보낸다.
  async function submitDelete() {
    return action(async captured => {
      checkAuth();
      const agreed = confirmation; confirmation = null;
      if (!agreed || agreed.epoch !== captured || agreed.subject !== auth.subject || root?.root_state !== "ACTIVE" ||
        agreed.generation !== root.root_generation || receipt) fail("CONFIRMATION_REQUIRED");
      const handle = crypt.getRandomValues(new Uint8Array(32));
      const digest = base64(new Uint8Array(await crypt.subtle.digest("SHA-256", handle)));
      const createdAt = now();
      const pending = Object.freeze({ version: 1, projectRef: c.projectRef, operationId: crypt.randomUUID(),
        handle: hex(handle), createdAt, expiresAt: createdAt + 30 * DAY });
      handle.fill(0); current(captured); checkAuth();
      try { persist(RECEIPT_KEY, pending); }
      catch { message = "결과 확인 정보를 저장하지 못해 삭제 요청을 보내지 않았습니다."; fail("STORAGE_UNAVAILABLE"); }
      receipt = pending; receiptResult = null;
      // 영속화 뒤의 실패를 미전송으로 단정하지 않는다. 원래 요청의 조회 정보는 보존한다.
      try {
        parseSubmission(await control("ROOT_DELETE_REQUEST", { operation_id: pending.operationId,
          expected_root_generation: agreed.generation, receipt_digest: digest, confirmed: true }, captured), pending.operationId);
        current(captured); root = null;
        message = "삭제 요청 응답을 받았습니다. 아직 완료로 표시하지 않습니다. ‘이 요청의 결과 다시 확인’을 눌러 주세요.";
      } catch (error) {
        if (captured === epoch) { root = null; message = "삭제 요청의 접수 결과가 불명확합니다. 다시 요청하지 말고 보관된 요청의 결과를 확인해 주세요."; }
        throw error;
      }
      return snapshot();
    });
  }
  // 로그인 인증값 없이 같은 요청의 확정 결과만 조회한다.
  async function refreshReceipt() {
    return action(async captured => {
      const pending = receipt;
      if (!pending) fail("RECEIPT_MISSING");
      if (now() >= pending.expiresAt) { message = "이 요청의 30일 결과 확인 기간이 지났습니다. 완료 여부를 임의로 판단하지 마세요. 도움이 필요하면 문의해 주세요."; return snapshot(); }
      let result;
      try {
        result = parseReceipt(await post("/rest/v1/rpc/account1_root_delete_receipt", {
          p_operation_id: pending.operationId, p_receipt_handle: `\\x${pending.handle}`,
        }, null, captured), pending.operationId);
      } catch (error) {
        if (captured === epoch) message = "이번 결과 조회를 완료하지 못했습니다. 보관된 요청은 유지했습니다. 나중에 결과를 다시 확인해 주세요.";
        throw error;
      }
      current(captured); if (receipt !== pending) fail("STALE_RESPONSE"); receiptResult = result;
      message = result.state === "SUCCESS" && !result.completion_blocked ? "계정 삭제 완료를 확인했습니다." :
        result.state === "PENDING" && !result.completion_blocked ? "계정 삭제가 진행 중입니다. 나중에 이 버튼으로 다시 확인해 주세요." :
        "계정 삭제 완료를 확인하지 못했습니다. 처리 중이거나 확인이 필요한 상태입니다. 새 요청을 보내지 말고 나중에 결과를 다시 확인해 주세요.";
      return snapshot();
    });
  }
  // 본인확인만 종료하며 보낸 삭제 요청은 취소하지 않는다.
  function endSession() { invalidate(); message = "이 화면의 본인확인을 종료했습니다. 이미 보낸 삭제 요청은 취소되지 않습니다."; return snapshot(); }
  // 전송 전 확인창만 닫는다.
  function cancelConfirmation() { confirmation = null; return snapshot(); }
  // 사용자 확인 뒤 이 탭의 조회 정보만 회수한다.
  function forgetReceipt(accepted) {
    if (busy || accepted !== true) fail("CONFIRMATION_REQUIRED");
    remove(RECEIPT_KEY); receipt = null; receiptResult = null; confirmation = null;
    message = "이 탭의 결과 확인 정보를 지웠습니다. 서버의 삭제 요청을 취소하거나 다시 보내지는 않았습니다.";
    return snapshot();
  }
  return Object.freeze({ snapshot, initialize, beginOAuth, refreshRoot, prepareDelete, submitDelete, refreshReceipt,
    endSession, cancelConfirmation, forgetReceipt });
}

// 실제 화면은 고정 DOM의 textContent만 갱신한다. 사용자/서버 문자열을 HTML로 삽입하지 않는다.
if (typeof document !== "undefined") {
  const byId = id => document.getElementById(id);
  let client;
  try {
    client = createDeleteClient(defaultConfig, { storage: sessionStorage, crypto, fetcher: fetch, history, location });
  } catch {
    if (location.search || location.hash) history.replaceState(null, "", CALLBACK);
    byId("status").textContent = "브라우저 저장 기능을 사용할 수 없어 삭제 요청을 시작하지 않았습니다.";
  }
  if (client) {
    // 고정 요소의 글자와 버튼 상태만 갱신한다.
    function render() {
      const state = client.snapshot();
      const available = state.enabled && !state.busy && !state.storageProblem;
      byId("status").textContent = state.message;
      byId("login").disabled = !available;
      byId("check-root").disabled = !available || !state.signedIn;
      byId("end-session").disabled = !state.signedIn && !state.busy;
      byId("scope").hidden = state.root?.root_state !== "ACTIVE" || state.hasReceipt;
      byId("review-delete").disabled = !available || !byId("scope-agree").checked;
      byId("confirm").hidden = !state.confirming;
      byId("submit-delete").disabled = !available || !state.confirming;
      byId("receipt").hidden = !state.hasReceipt;
      byId("check-receipt").disabled = !available;
      byId("forget-receipt").disabled = state.busy;
      byId("receipt-state").textContent = state.hasReceipt ? "이 탭에 결과 확인 정보가 보관되어 있습니다." : "";
      byId("receipt-expiry").textContent = state.receiptExpiresAt ? `결과 조회 유효기간: ${new Date(state.receiptExpiresAt).toLocaleString("ko-KR")}까지(요청 준비 뒤 최대 30일).` : "";
    }
    // 비동기 UI 동작의 진행 상태와 닫힌 오류를 표시한다.
    async function run(work) {
      try { const pending = work(); render(); await pending; render(); }
      catch (error) {
        render();
        if (error?.message === "STALE_RESPONSE") return;
        const state = client.snapshot();
        byId("status").textContent = state.hasReceipt ? state.message : error?.message === "STORAGE_UNAVAILABLE" ?
          "결과 확인 정보를 저장하지 못해 삭제 요청을 보내지 않았습니다. 브라우저 저장 설정을 확인해 주세요." :
          "요청을 완료하지 못했습니다. 본인확인과 현재 상태를 확인한 뒤 다시 진행해 주세요.";
      }
    }
    byId("login").addEventListener("click", () => run(async () => {
      const url = await client.beginOAuth(); location.assign(url);
    }));
    byId("check-root").addEventListener("click", () => run(() => client.refreshRoot()));
    byId("end-session").addEventListener("click", () => { client.endSession(); byId("scope-agree").checked = false; render(); });
    byId("scope-agree").addEventListener("change", () => { client.cancelConfirmation(); render(); });
    byId("review-delete").addEventListener("click", () => run(() => client.prepareDelete(byId("scope-agree").checked)));
    byId("cancel-delete").addEventListener("click", () => { client.cancelConfirmation(); render(); });
    byId("submit-delete").addEventListener("click", () => run(() => client.submitDelete()));
    byId("check-receipt").addEventListener("click", () => run(() => client.refreshReceipt()));
    byId("forget-receipt").addEventListener("click", () => run(() => client.forgetReceipt(window.confirm(
      "이 탭의 결과 확인 정보를 지울까요? 이미 보낸 삭제 요청은 계속 진행됩니다. 정보를 지우면 이 탭에서 그 요청의 결과를 다시 확인할 수 없습니다."))));
    void run(() => client.initialize());
  }
}
