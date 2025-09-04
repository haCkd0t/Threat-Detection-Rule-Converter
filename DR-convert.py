import google.generativeai as genai


genai.configure(api_key="Your API Key")
model = genai.GenerativeModel("gemini-1.5-flash")

def convert_rule(source_platform,rule,target_platform):
    prompt = f"""
You are a SOC Analyst specializing in SIEM and detection rule conversions.
Your task is to convert the following rule from {source_platform} to {target_platform}.

1. Conversion Rules

Output Format:
- Return only the converted rule in {target_platform} syntax.
- Do not add explanations, notes, or markdown formatting.
- If conversion is not possible, return exactly:
  ERROR: Cannot convert

Preserve Logic:
- Always preserve ALL event filters, fields, aggregations, thresholds, and time windows.
- Do not drop conditions (e.g., failed, success, privileged).
- Do not add extra fields unless they exist in the source.

2. Syntax Rules Per Platform

Sentinel KQL:
- Use SecurityEvent (or SigninLogs for Azure AD).
- Use summarize with named columns via count(), countif().
- Use bin(TimeGenerated, X) for time windows.
- Filtering must happen after summarization using named columns.
- Always filter first with where EventID == ...
- For time buckets, use bin(TimeGenerated, X) inside summarize.
- Apply thresholds after summarization with | where.

Splunk SPL:
- Must start with index=* unless another index is given.
- Use stats for aggregation, where for thresholds.
- Use bin(_time, X) for time buckets.

QRadar AQL:
- Must use SELECT ... FROM events ... GROUP BY ... HAVING.
- Use COUNT(CASE WHEN EventID=... THEN 1 END) for conditional counts.
- Do NOT use Splunk-style functions (no eval, no bin()).
- For time windows, only use GROUP BY STARTTIME or rely on correlation window.

Elastic KQL:
- Must use logs-* as dataset.
- Use stats with countif(), not eval or case().
- For time windows use date_histogram(@timestamp, '5m').
- No markdown blocks, no ```kql.
- Always start with logs-*.
- Always filter first with | where event.code == ...
- Use stats count() for totals, and count(if(condition, 1, null)) for conditional counts.
- For time windows, use date_histogram(@timestamp, '5m') as bucket.
- No markdown blocks, no kql.

Sigma:
- Must be valid YAML.
- Must include title, logsource, detection, condition.
- Detection must use selections (selection_fail, selection_success, etc.).
- Condition must only combine selections with AND/OR/NOT.
- Do NOT use count() or thresholds in Sigma (thresholds are handled by backends).

YARA-L:
- Must use rule {{}} syntax.
- Condition may use count(field == value) >= N.
- Include meta: description.

YARA:
- Always return ERROR: Cannot convert.

3. Field Mappings
- Splunk Account_Name → Sentinel Account → QRadar username → Elastic user.name
- Splunk IpAddress → Sentinel IpAddress → QRadar sourceip → Elastic source.ip
- Splunk EventCode → Sentinel EventID → QRadar EventID → Elastic event.code
- Splunk CommandLine → Sentinel CommandLine → QRadar UTF8(payload) → Elastic process.command_line

4. Error Handling
- If exact syntax is unsupported in {target_platform}, return:
  ERROR: Cannot convert

Input Rule:
{rule}
"""


    response = model.generate_content(prompt)
    return response.text


while True:
    c = int(input("Press 1 to convert rule or 0 to exit: "))
    if c == 0:  
        print("Exiting the program.....")
        break
    else:
        source_platform = input("Enter the source platform:- ")
        print("Paste the rule (press Enter twice to finish):")
        lines = []
        while True:
            line = input()
            if line.strip() == "":
                break
            lines.append(line)
            rule = " ".join(lines)
        target_platform = input("Enter the target platform:- ")
        res = convert_rule(source_platform,rule,target_platform)
        print("Converted Rule:",res)
