import re
from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from tools.ip_checker import check_ip_reputation
from tools.code_analyzer import analyze_code
code_tool = FunctionTool(analyze_code)
from guardrail import check_guardrail

# ─── Sub-Agent A: IP Reputation Checker ───────────────────────────────────────
ip_agent = Agent(
    name="ip_reputation_agent",
    model="gemini-2.0-flash",
    description="Handles IP address reputation checks using VirusTotal.",
    instruction=(
        "You are an IP reputation specialist. "
        "When given an IP address, use the check_ip_reputation tool to look it up "
        "and summarize the threat level, owner, and any malicious flags."
    ),
    # tools will be added in Task 2
    tools=[check_ip_reputation],
    tools=[ip_tool],
)

# ─── Sub-Agent B: Static Code Analyzer ────────────────────────────────────────
code_agent = Agent(
    name="code_analysis_agent",
    model="gemini-2.0-flash",
    description="Handles static code analysis for security vulnerabilities.",
    instruction=(
        "You are a secure code review specialist. "
        "When given a code block, use the analyze_code tool to scan it "
        "and explain each vulnerability found (SQL injection, XSS, hardcoded secrets, etc.)."
    ),
    # tools will be added in Task 3
    tools=[code_tool],
)

# ─── Root Agent (Orchestrator / Router) ───────────────────────────────────────
root_agent = Agent(
    name="security_triage_agent",
    model="gemini-2.0-flash",
    description="Routes security queries to the correct specialist sub-agent.",
    instruction=(
        "You are a security triage router. Analyze the user's input and decide:\n"
        "- If the input contains an IP address (e.g., 192.168.1.1 or any x.x.x.x pattern), "
        "  delegate to 'ip_reputation_agent'.\n"
        "- If the input contains a code block (wrapped in triple backticks ``` or "
        "  starts with keywords like def, import, SELECT, <script), "
        "  delegate to 'code_analysis_agent'.\n"
        "- If neither, ask the user to clarify whether they want an IP check or code review."
    ),
    sub_agents=[ip_agent, code_agent],
)

def run(user_input: str):
    guard = check_guardrail(user_input)
    if not guard["safe"]:
        print(f"\n[GUARDRAIL] {guard['reason']}\n")
        return
    print(f"\n[GUARDRAIL] Input is safe. Routing to agent...\n")
    # root_agent.run(user_input)  ← uncomment when running full ADK pipeline

if __name__ == "__main__":
    user_input = input("Enter security query: ")
    run(user_input)
