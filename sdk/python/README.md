# Mizan Python SDK

The client an agent holds. Three calls carry the whole loop, and none of them decide anything —
every allow, wait and refusal comes from the control plane.

```python
from mizan import MizanClient, Principal, Resource, Denied

with MizanClient() as mizan:                     # MIZAN_API_URL, MIZAN_AGENT_TOKEN, MIZAN_AGENT_ID
    try:
        decision = mizan.decide(
            tool_id="tool_portfolio-rebalance",
            arguments={"customer_id": "cus_42", "amount": 250_000},
            action_type="financial_write",
            intent="rebalance to the target allocation",
            principal=Principal(id="prn_alice-01", role="advisor"),
            resource=Resource("portfolio/42", "portfolio", "core-banking", "financial"),
            proof_token=memtara_token,
            memtara_chain_head=memtara_chain_head,
        )
    except Denied as refused:
        print(refused.reasons)                   # the recorded reasons, not a guess at them
```

`decide` blocks while humans decide when policy requires an approval, raises `Denied` when policy
refuses, and returns the decision when it does not. Giving up on an approval (`ApprovalTimeout`)
does not cancel it: the work stays paused and the approval stays open.

For Memtara-governed calls, `proof_token` and `memtara_chain_head` are sent only as
`x-memtara-proof` and `x-memtara-chain-head` on `/v1/authorize`. The SDK treats both values as
opaque: verification and validation happen in the control plane.

## Wrapping an existing tool

```python
from mizan import govern, Resource

@govern(
    tool_id="tool_portfolio-read",
    action_type="financial_read",
    resource=Resource("portfolio/42", "portfolio", "core-banking", "financial"),
    client_factory=MizanClient,
    proof_token_factory=lambda **arguments: proof_for(arguments["customer_id"]),
    memtara_chain_head_factory=lambda **arguments: chain_head_for(arguments["customer_id"]),
)
def read_portfolio(customer_id: str) -> dict: ...
```

The decorator authorizes before the call and records the outcome after it. It does not take an
execution lease by default: a lease binds to a workload identity Mizan verified over mTLS, which
an in-process decorator does not have. Set `redeem=True` only where the calling workload is itself
the registered executor.

## Model tool calls

`GovernedToolRouter` takes the tool-call payload the Anthropic and OpenAI APIs already hand you and
runs it through Mizan first. A refusal comes back as a tool result the model can read and explain,
not as an exception that crashes the loop.

```python
router = GovernedToolRouter(mizan, {"rebalance": GovernedTool(...)}, principal=advisor)
results = router.anthropic_tool_results(message.content)      # Anthropic
messages = router.openai_tool_messages(choice.message.tool_calls)  # OpenAI
tools = router.langchain_tools()                              # LangChain (needs langchain-core)
```

## Why the binding hash is computed twice

`parameters_hash` is an independent implementation of the hash the control plane computes. The
server recomputes it from the pointers *its own registry* declares and answers 400
`parameters_hash_mismatch` on disagreement — so the two computations check each other. A client
that imported the server's function would prove nothing. The bound pointers themselves always come
from `GET /v1/tools/{id}`; the SDK never guesses which arguments are policy-relevant.

## Install

```
pip install ./sdk/python            # plus [langchain] for the LangChain adapter
```
