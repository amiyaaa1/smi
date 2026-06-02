import json
import os
import re
import threading
import time
import uuid
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

APP = FastAPI(title="SimplAI OpenAI Relay", version="0.1.0")
APP.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FIXED_OPENAI_MODEL = "claude-opus-4.6-simplai"
SIMPLAI_AGENT_NAME = "UNO Rule & Web Research Agent"
SIMPLAI_AGENT_PIPELINE_ID = "agent-6a0bdd80c3da0fcaf9194b3b"
SIMPLAI_VERSION_ID = "2"
SIMPLAI_PROFILE_DIR = "/tmp/simplai_profile_reg"
CLOAKBROWSER_PATH = "/root/netlify2api/CloakBrowser"

SIMPLAI_AUTH = {
    "access_token": os.getenv("SIMPLAI_ACCESS_TOKEN", "59b935b2-928f-44bf-a913-3a942b00c3cf"),
    "user_id": os.getenv("SIMPLAI_USER_ID", "3649"),
    "tenant_id": os.getenv("SIMPLAI_TENANT_ID", "3307"),
    "project_id": os.getenv("SIMPLAI_PROJECT_ID", "2629"),
}

TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)
SIMPLAI_SSE_WRAPPER_RE = re.compile(r"^---->(.*)<----$", re.DOTALL)


class SimplAIClient:
    def __init__(self) -> None:
        self._auth = dict(SIMPLAI_AUTH)
        self._lock = threading.Lock()
        self._http = requests.Session()
        self._http.headers.update({
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
            "referer": "https://app.simplai.ai/",
            "x-device-id": "simplai",
        })

    def _headers(self) -> Dict[str, str]:
        return {
            "pim-sid": self._auth["access_token"],
            "x-user-id": self._auth["user_id"],
            "x-seller-profile-id": self._auth["user_id"],
            "x-seller-id": self._auth["user_id"],
            "x-client-id": self._auth["user_id"],
            "x-tenant-id": self._auth["tenant_id"],
            "x-project-id": self._auth["project_id"],
        }

    def _request(self, method: str, url: str, retry: bool = True, **kwargs: Any) -> requests.Response:
        headers = kwargs.pop("headers", {})
        merged_headers = {**self._headers(), **headers}
        resp = self._http.request(method, url, headers=merged_headers, timeout=kwargs.pop("timeout", 60), **kwargs)
        if resp.status_code in (401, 511) and retry:
            self.refresh_from_browser()
            return self._request(method, url, retry=False, headers=headers, **kwargs)
        return resp

    def refresh_from_browser(self) -> None:
        with self._lock:
            self._remove_profile_locks()
            try:
                import sys
                if CLOAKBROWSER_PATH not in sys.path:
                    sys.path.insert(0, CLOAKBROWSER_PATH)
                from cloakbrowser import launch_persistent_context  # type: ignore
            except Exception as exc:  # pragma: no cover
                raise RuntimeError(f"Unable to load CloakBrowser: {exc}") from exc

            ctx = launch_persistent_context(SIMPLAI_PROFILE_DIR, headless=True)
            try:
                page = ctx.new_page()
                page.set_default_timeout(90000)
                page.goto("https://app.simplai.ai/api/auth/session", wait_until="networkidle")
                data = json.loads(page.locator("body").inner_text())
                self._auth["access_token"] = data["accessToken"]
                self._auth["user_id"] = str(data["user"]["details"]["id"])
                self._auth["tenant_id"] = str(data["user"]["details"]["tenantId"])
            finally:
                ctx.close()

    @staticmethod
    def _remove_profile_locks() -> None:
        for name in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
            path = os.path.join(SIMPLAI_PROFILE_DIR, name)
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass

    def start_conversation(self, prompt: str) -> Tuple[str, str]:
        payload = {
            "model": SIMPLAI_AGENT_NAME,
            "language_code": "EN",
            "source": "APP",
            "app_id": SIMPLAI_AGENT_PIPELINE_ID,
            "model_id": SIMPLAI_AGENT_PIPELINE_ID,
            "version_id": SIMPLAI_VERSION_ID,
            "state_override": {
                "sys": {
                    "user_timezone": os.getenv("TZ", "Asia/Shanghai"),
                    "language_code": "en-US",
                }
            },
            "action": "START_SCREEN",
            "query": {
                "message": prompt,
                "message_type": "text",
                "message_category": "",
            },
        }
        resp = self._request(
            "POST",
            "https://edge-service.simplai.ai/interact/api/v1/intract/conversation",
            json=payload,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"SimplAI start failed: {resp.text[:500]}")
        try:
            data = resp.json()["result"]
            return data["conversation_id"], data["message_id"]
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Unexpected SimplAI start response: {resp.text[:500]}") from exc

    def poll_response(self, conversation_id: str, timeout_s: int = 300, poll_interval: float = 1.5) -> str:
        deadline = time.time() + timeout_s
        last_text = ""
        while time.time() < deadline:
            resp = self._request(
                "GET",
                f"https://edge-service.simplai.ai/interact/api/v1/intract/conversation/{conversation_id}",
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail=f"SimplAI poll failed: {resp.text[:500]}")
            data = resp.json().get("result", {})
            messages = data.get("response") or []
            if messages:
                msg = messages[-1]
                last_text = msg.get("query_result") or ""
                if msg.get("message_status") == 2:
                    return last_text
            time.sleep(poll_interval)
        raise HTTPException(status_code=504, detail=f"Timed out waiting for SimplAI response. Last text: {last_text[:200]}")

    def iter_stream_events(self, message_id: str) -> Iterator[Dict[str, Any]]:
        with requests.get(
            f"https://edge-external.simplai.ai/interact/api/v1/intract/data/{message_id}/stream",
            headers={"Accept": "text/event-stream"},
            stream=True,
            timeout=(10, 300),
        ) as resp:
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail=f"SimplAI stream failed: {resp.text[:500]}")
            for raw_line in resp.iter_lines(decode_unicode=True):
                if not raw_line or not raw_line.startswith("data:"):
                    continue
                payload = raw_line[5:].strip()
                match = SIMPLAI_SSE_WRAPPER_RE.match(payload)
                if match:
                    payload = match.group(1)
                try:
                    yield json.loads(payload)
                except json.JSONDecodeError:
                    continue


CLIENT = SimplAIClient()


def extract_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out: List[str] = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    text = item.get("text")
                    if isinstance(text, str):
                        out.append(text)
                elif "text" in item and isinstance(item["text"], str):
                    out.append(item["text"])
            elif isinstance(item, str):
                out.append(item)
        return "\n".join(part for part in out if part)
    return ""


def normalize_messages(messages: Any) -> List[Dict[str, str]]:
    if not isinstance(messages, list) or not messages:
        raise HTTPException(status_code=400, detail="messages is required")
    normalized: List[Dict[str, str]] = []
    for item in messages:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "user").strip().lower()
        if role not in {"system", "user", "assistant"}:
            role = "user"
        text = extract_text(item.get("content"))
        if not text:
            continue
        normalized.append({"role": role, "content": text})
    if not normalized:
        raise HTTPException(status_code=400, detail="messages must contain text content")
    return normalized


def approx_token_count(text: str) -> int:
    return len(TOKEN_RE.findall(text))


def truncate_to_token_limit(text: str, max_tokens: Optional[int]) -> Tuple[str, bool]:
    if not max_tokens or max_tokens <= 0:
        return text, False
    count = 0
    end_idx = 0
    for match in TOKEN_RE.finditer(text):
        count += 1
        if count > max_tokens:
            return text[:end_idx].rstrip(), True
        end_idx = match.end()
    return text, False


def temperature_instruction(value: Optional[float]) -> Optional[str]:
    if value is None:
        return None
    if value <= 0.2:
        return "Style: be highly deterministic, direct, and conservative."
    if value <= 0.5:
        return "Style: be focused, stable, and concise."
    if value <= 0.8:
        return "Style: be balanced and natural."
    return "Style: use more varied and creative phrasing while staying accurate and relevant."


def build_prompt(messages: List[Dict[str, str]], temperature: Optional[float], max_output_tokens: Optional[int]) -> str:
    system_parts = [m["content"] for m in messages if m["role"] == "system"]
    convo_parts = [m for m in messages if m["role"] != "system"]

    control_lines = [
        "You are continuing the conversation below.",
        "Reply only as the assistant.",
        "Respect the role labels in the transcript.",
    ]
    if max_output_tokens and max_output_tokens > 0:
        control_lines.append(
            f"Keep the final answer within about {max_output_tokens} tokens. If needed, shorten aggressively."
        )
    temp_line = temperature_instruction(temperature)
    if temp_line:
        control_lines.append(temp_line)

    parts: List[str] = ["[Relay Instructions]\n- " + "\n- ".join(control_lines)]
    if system_parts:
        parts.append("[System Instructions]\n" + "\n\n".join(system_parts))

    transcript: List[str] = ["[Conversation Transcript]"]
    for msg in convo_parts:
        transcript.append(f"<{msg['role']}>\n{msg['content']}\n</{msg['role']}>")
    transcript.append("[Assistant Task]\nWrite the next assistant reply only.")
    parts.append("\n\n".join(transcript))
    return "\n\n".join(parts)


def now_ts() -> int:
    return int(time.time())


def make_completion_id() -> str:
    return f"chatcmpl-{uuid.uuid4().hex}"


def usage_obj(prompt: str, completion: str) -> Dict[str, int]:
    prompt_tokens = approx_token_count(prompt)
    completion_tokens = approx_token_count(completion)
    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
    }


@APP.get("/healthz")
def healthz() -> Dict[str, Any]:
    return {"ok": True, "model": FIXED_OPENAI_MODEL}


@APP.get("/v1/models")
def list_models() -> Dict[str, Any]:
    return {
        "object": "list",
        "data": [
            {
                "id": FIXED_OPENAI_MODEL,
                "object": "model",
                "owned_by": "simplai",
            }
        ],
    }


@APP.post("/v1/chat/completions", response_model=None)
async def chat_completions(request: Request):
    body = await request.json()
    messages = normalize_messages(body.get("messages"))
    max_output_tokens = body.get("max_completion_tokens")
    if max_output_tokens is None:
        max_output_tokens = body.get("max_tokens")
    if max_output_tokens is not None:
        try:
            max_output_tokens = int(max_output_tokens)
        except Exception:
            raise HTTPException(status_code=400, detail="max_tokens/max_completion_tokens must be an integer")
        if max_output_tokens <= 0:
            max_output_tokens = None
    temperature = body.get("temperature")
    if temperature is not None:
        try:
            temperature = float(temperature)
        except Exception:
            raise HTTPException(status_code=400, detail="temperature must be numeric")
    stream = bool(body.get("stream", False))

    prompt = build_prompt(messages, temperature, max_output_tokens)
    conversation_id, message_id = CLIENT.start_conversation(prompt)

    completion_id = make_completion_id()
    created = now_ts()

    if stream:
        def event_stream() -> Iterator[bytes]:
            role_chunk = {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": FIXED_OPENAI_MODEL,
                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
            }
            yield f"data: {json.dumps(role_chunk, ensure_ascii=False)}\n\n".encode("utf-8")

            emitted = ""
            hit_limit = False
            for event in CLIENT.iter_stream_events(message_id):
                role = str(event.get("role") or "").lower()
                if role != "assistant":
                    continue
                delta = event.get("content")
                if not isinstance(delta, str) or not delta:
                    continue
                limited_total, truncated = truncate_to_token_limit(emitted + delta, max_output_tokens)
                new_piece = limited_total[len(emitted):]
                if new_piece:
                    chunk = {
                        "id": completion_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": FIXED_OPENAI_MODEL,
                        "choices": [{"index": 0, "delta": {"content": new_piece}, "finish_reason": None}],
                    }
                    yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode("utf-8")
                emitted = limited_total
                if truncated:
                    hit_limit = True
                    break

            final_chunk = {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": FIXED_OPENAI_MODEL,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "length" if hit_limit else "stop"}],
            }
            yield f"data: {json.dumps(final_chunk, ensure_ascii=False)}\n\n".encode("utf-8")
            yield b"data: [DONE]\n\n"

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    completion_text = CLIENT.poll_response(conversation_id)
    completion_text, truncated = truncate_to_token_limit(completion_text, max_output_tokens)

    response = {
        "id": completion_id,
        "object": "chat.completion",
        "created": created,
        "model": FIXED_OPENAI_MODEL,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": completion_text},
                "finish_reason": "length" if truncated else "stop",
            }
        ],
        "usage": usage_obj(prompt, completion_text),
    }
    return JSONResponse(response)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(APP, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
