import requests
import json
import os
from dotenv import load_dotenv

def analyze_vulnerabilities_with_mistral(report_json: dict, mistral_api_key: str) -> dict:
    """
    Calls the Mistral API to analyze a cloud security report and returns a structured vulnerability analysis.
    
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
        "Input: " + json.dumps(report_json)
    )
    
    # Build the Mistral API endpoint URL.
    url = "https://api.mistral.ai/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {mistral_api_key}",
        "Accept": "application/json"
    }
    data = {
        "model": "mistral-small-latest",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cloud security expert. Analyze the provided cloud security report "
                    "and return a structured JSON vulnerability analysis. Always respond with valid JSON only."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.3,
        "response_format": {"type": "json_object"}
    }
    
    # Call the Mistral API via a POST request.
    response = requests.post(url, headers=headers, json=data)

    if response.status_code != 200:
        raise Exception(f"Mistral API request failed with status code {response.status_code}: {response.text}")
    else:
        print("Request successful to Mistral")
        print(f"Response: {response.json()}")
    
    # Parse the API response.
    result_json = response.json()
    try:
        output_text = result_json["choices"][0]["message"]["content"]
    except Exception as e:
        raise Exception("Failed to extract generated output from Mistral API response: " + str(e))
    
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
        print(f"structured_output : {structured_output}")
    except Exception as e:
        raise Exception("Failed to parse Mistral API output as JSON: " + str(e))
    
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
    MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY")
    if not MISTRAL_API_KEY:
        raise Exception("MISTRAL_API_KEY environment variable not set")
    
    try:
        analysis = analyze_vulnerabilities_with_mistral(example_report, MISTRAL_API_KEY)
        print(json.dumps(analysis, indent=2))
        return analysis
    except Exception as err:
        print("Error:", err)

if __name__ == "__main__":
    get_solution()
