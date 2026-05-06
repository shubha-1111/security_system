import subprocess
import tempfile
import os

def analyze_code(code: str) -> dict:
    """
    Analyzes a code snippet for security vulnerabilities using Bandit.
    Returns a list of issues found including severity and line numbers.

    Args:
        code: A string containing the Python code to analyze.
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["bandit", "-r", tmp_path, "-f", "txt"],
            capture_output=True,
            text=True
        )

        output = result.stdout.strip()

        # returncode 1 = issues found, 0 = clean, anything else = error
        if result.returncode == 0:
            return {
                "status": "CLEAN",
                "issues_found": 0,
                "details": "No security vulnerabilities detected."
            }
        elif result.returncode == 1:
            issue_count = output.count(">> Issue:")
            return {
                "status": "VULNERABLE",
                "issues_found": issue_count,
                "details": output
            }
        else:
            return {"error": f"Bandit error: {result.stderr}"}

    except FileNotFoundError:
        return {"error": "Bandit is not installed. Run: pip install bandit"}
    except Exception as e:
        return {"error": f"Analysis failed: {str(e)}"}
    finally:
        os.unlink(tmp_path)
