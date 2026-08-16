import json

from app.providers.base import BaseProvider, ChatResponse, ProviderSettings, ToolCall, VERDICT_TOOL_NAME


class ListRecorder:
    def __init__(self):
        self.events = []

    def event(self, kind, **fields):
        self.events.append({"kind": kind, **fields})


class FakeProvider(BaseProvider):
    """Returns a scripted sequence of ChatResponses, one per _request() call."""

    def __init__(self, responses):
        super().__init__(ProviderSettings(type="custom", model="fake"))
        self._responses = list(responses)
        self.requests = []  # [(messages_snapshot, tools), ...]

    def _initial_messages(self, system, user):
        return [{"role": "system", "content": system}, {"role": "user", "content": user}]

    async def _request(self, messages, tools, system):
        self.requests.append((list(messages), tools))
        return self._responses.pop(0)

    def _append_assistant(self, messages, resp):
        messages.append({"role": "assistant", "tool_calls": resp.tool_calls})

    def _append_tool_results(self, messages, resp, results):
        messages.append({"role": "tool_results", "results": results})

    async def ping(self):
        return {}


def _call(name, args, id_="c1"):
    return ToolCall(id=id_, name=name, arguments=args)


async def test_run_returns_verdict_when_called_alone():
    verdict_args = {"verdict": "HAM", "confidence": 0.8, "category": "newsletter", "reason": "matches expectations"}
    provider = FakeProvider([ChatResponse(tool_calls=[_call(VERDICT_TOOL_NAME, verdict_args)])])
    calls = []

    async def execute_tool(name, args):
        calls.append(name)
        return {}

    result = await provider.run("sys", "user", [], execute_tool, ListRecorder())

    assert json.loads(result) == verdict_args
    assert calls == []  # never routed through the real tool executor
    # verdict tool is always offered, even though the caller passed an empty list
    assert VERDICT_TOOL_NAME in [t["name"] for t in provider.requests[0][1]]


async def test_run_nudges_and_retries_when_verdict_bundled_with_other_tools():
    premature = {"verdict": "SPAM", "confidence": 0.5, "category": "guess", "reason": "too early"}
    final = {"verdict": "SPAM", "confidence": 0.9, "category": "cold B2B", "reason": "confirmed after lookup"}
    provider = FakeProvider([
        ChatResponse(tool_calls=[_call("domain_age", {"domain": "x.example"}, "c1"),
                                 _call(VERDICT_TOOL_NAME, premature, "c2")]),
        ChatResponse(tool_calls=[_call(VERDICT_TOOL_NAME, final, "c3")]),
    ])
    calls = []

    async def execute_tool(name, args):
        calls.append(name)
        return {"registered": True}

    result = await provider.run("sys", "user", [], execute_tool, ListRecorder())

    assert json.loads(result) == final
    assert calls == ["domain_age"]  # the real tool ran exactly once; submit_verdict never did
    assert len(provider.requests) == 2  # first turn was rejected, model got a second chance


async def test_run_falls_back_to_plain_text_when_model_never_calls_a_tool():
    provider = FakeProvider([ChatResponse(text='{"verdict": "HAM", "confidence": 0.6}', tool_calls=[])])

    async def execute_tool(name, args):
        raise AssertionError("should not be called")

    result = await provider.run("sys", "user", [], execute_tool, ListRecorder())

    assert result == '{"verdict": "HAM", "confidence": 0.6}'
