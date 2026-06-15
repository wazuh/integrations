# test_flow.py
from use_cases.dashboard_error import dashboard_error_flow

# Step 1 — START
r = dashboard_error_flow()
print("STEP 1:", r["display"])
print("ASK:", r["ask"])
print("STAGE:", r["context"]["stage"])
print("---")

# Step 2 — User says yes to continue
r = dashboard_error_flow(user_choice="yes", context=r["context"])
print("STEP 2:", r["display"])
print("ASK:", r["ask"])
print("STAGE:", r["context"]["stage"])
print("---")
