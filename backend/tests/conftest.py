import os, tempfile
_tmp = tempfile.mkdtemp(prefix="qyrix-test-")
os.environ.update({
    "QYRIX_ADMIN_TOKEN": "admin-token-for-tests-0123456789",
    "QYRIX_AGENT_TOKEN": "agent-token-for-tests-0123456789",
    "QYRIX_ENABLE_DEMO_RESET": "1",
    "QYRIX_CHAIN_FILE": os.path.join(_tmp, "chain.jsonl"),
    "QYRIX_WORKSPACE": os.path.join(_tmp, "ws"),
})
os.makedirs(os.environ["QYRIX_WORKSPACE"], exist_ok=True)
ADMIN = {"Authorization": "Bearer " + os.environ["QYRIX_ADMIN_TOKEN"]}
AGENT = {"Authorization": "Bearer " + os.environ["QYRIX_AGENT_TOKEN"]}
