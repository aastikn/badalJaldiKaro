import requests
import json
import os
from dotenv import load_dotenv

def analyze_vulnerabilities_with_gemini(report_json: dict, gemini_api_key: str) -> dict:
    """
    Calls the Gemini API to analyze a cloud security report and returns a structured vulnerability analysis.
    
    The output JSON will contain an array "vulnerabilities", where each vulnerability is a JSON object with:
      - priority: "critical" or "non critical"
      - problem: one line description of vulnerability
      - solution: one line description of solution
      - cli_command: the CLI command to fix the problem
      - file: (if applicable) a JSON object representing the file changes needed
    
    It also includes a summary indicating if there are any critical vulnerabilities.
    """
    # Build the prompt by embedding the input JSON as a string.
    prompt = (
        "Analyze the following cloud security report JSON and generate a structured vulnerability analysis. "
        "Your output must be valid JSON with an array named 'vulnerabilities'. Each vulnerability object must contain the following keys: "
        "'priority' (either 'critical' or 'non critical'), 'problem' (one line description of the vulnerability), "
        "'solution' (one line description of the solution), 'cli_command' (the AWS CLI command to fix the vulnerability), and "
        "'file' (if any file needs to be changed or created, include a JSON object with the file details). "
        "Also include a summary key indicating whether critical vulnerabilities exist. "
        "Input: " + json.dumps(report_json) + " Output:"
    )
    
    # Build the Gemini API endpoint URL with the provided API key.
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_api_key}"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ]
    }
    
    # Call the Gemini API via a POST request.
    response = requests.post(url, headers=headers, json=data)

    if response.status_code != 200:
        raise Exception(f"Gemini API request failed with status code {response.status_code}: {response.text}")
    else:
        print("Request successful to Gemini")
        print(f"Response: {response.json()}")
    
    # Parse the API response.
    result_json = response.json()
    try:
        output_text = result_json["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        raise Exception("Failed to extract generated output from Gemini API response: " + str(e))
    
    # Remove markdown code block markers if present.
    if output_text.startswith("```json"):
        # Remove the first line ("```json")
        output_text = output_text.split("\n", 1)[1]
        # Remove the last line if it is "```"
        if output_text.rstrip().endswith("```"):
            output_text = output_text.rsplit("\n", 1)[0]
            # Remove any trailing backticks
            output_text = output_text.rstrip("`")
    
    # Now parse the output text into JSON.
    try:
        print(f"output_text stripped : {output_text}")
        structured_output = json.loads(output_text)
        print(f"structured_outpu : {structured_output}")
    except Exception as e:
        raise Exception("Failed to parse Gemini API output as JSON: " + str(e))
    
    return structured_output

# Example usage:
def get_solution():
    # Dummy report_json example (replace with your actual report JSON)
    example_report = {
        "report_time": "2025-02-09T08:43:06.018176",
        "graph_info": "Dependency graph has been saved as 'dependency_graph.png'",
        "aws_resources": [
            {
                "name": "AddNumbers",
                "id": "arn:aws:lambda:ap-south-1:954976300781:function:AddNumbers",
                "type": "serverless",
                "region": "ap-south-1",
                "risk_score": 0.125,
                "vulnerabilities": []
            }
        ],
        "bottlenecks": [
            {
                "type": "AWS Service Role",
                "severity": "Medium",
                "resource": "AWSServiceRoleForAPIGateway"
            },
            {
                "type": "Circular Dependency",
                "severity": "Critical",
                "chain": ["AddNumbers", "lambda-role"]
            }
        ],
        "actionable_recommendations": [
            {
                "bottleneck_type": "AWS Service Role",
                "recommendations": [
                    "Review AWS service role: AWSServiceRoleForAPIGateway • Check cross-account access • Audit permissions scope • Review attached policies • Implement role session duration limits"
                ]
            }
        ],
        "dependency_map": [
            {
                "resource_name": "AddNumbers",
                "provider": "aws",
                "dependencies": [
                    {
                        "dependency_id": "arn:aws:iam::954976300781:role/lambda-role",
                        "dependency_name": "lambda-role",
                        "dependency_type": "identity"
                    }
                ]
            }
        ]
    }
    
    # Load environment variables if needed.
    from dotenv import load_dotenv
    load_dotenv()
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    if not GEMINI_API_KEY:
        raise Exception("GEMINI_API_KEY environment variable not set")
    
    try:
        analysis = analyze_vulnerabilities_with_gemini(example_report, GEMINI_API_KEY)
        print(json.dumps(analysis, indent=2))
        return analysis
    except Exception as err:
        print("Error:", err)

if __name__ == "__main__":
    get_solution()
