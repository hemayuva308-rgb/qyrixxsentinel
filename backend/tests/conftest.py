import os, tempfile
_tmp = tempfile.mkdtemp(prefix="qyrix-test-")
os.environ.update({
    "QYRIX_ADMIN_TOKEN": "admin-token-for-tests-0123456789",
    "QYRIX_AGENT_TOKEN": "agent-token-for-tests-0123456789",
    "QYRIX_ENABLE_DEMO_RESET": "1",
    "QYRIX_CHAIN_FILE": os.path.join(_tmp, "chain.jsonl"),
    "QYRIX_WORKSPACE": os.path.join(_tmp, "ws"),
    # the suite sends thousands of requests with one credential; limits are tested explicitly in test_identity.py
    # durable-mode tests that are not about data-loss detection run with the witness explicitly disabled (UNSAFE in
    # production; test_integrity.py enables it)
    "QYRIX_STATE_WITNESS": "disabled",
    "QYRIX_RATE_LIMIT_PER_MIN": "1000000", "QYRIX_AUTH_FAIL_PER_MIN": "1000000", "QYRIX_AUTH_FAIL_GLOBAL_PER_MIN": "1000000",
})
os.makedirs(os.environ["QYRIX_WORKSPACE"], exist_ok=True)
ADMIN = {"Authorization": "Bearer " + os.environ["QYRIX_ADMIN_TOKEN"]}
AGENT = {"Authorization": "Bearer " + os.environ["QYRIX_AGENT_TOKEN"]}
