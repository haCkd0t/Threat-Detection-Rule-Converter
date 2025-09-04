import google.generativeai as genai


genai.configure(api_key="Your API Key")
model = genai.GenerativeModel("gemini-1.5-flash")

def convert_rule(source_platform,rule,target_platform):
    prompt = f"""
You are a SOC Analyst specializing in detection rules across multiple SIEM platforms.
Your task is to convert the following rule from {source_platform} to {target_platform}.
Rules for conversion:
- Only return the converted rule in {target_platform} syntax.
- Do not add explanations, notes, or markdown formatting (no ``` blocks).
- If the conversion is not possible, return exactly: ERROR: Cannot convert
- Always apply correct field name mappings:
  - Elastic KQL `event.code` → QRadar AQL `EventID`
  - Elastic KQL `process.command_line` → QRadar AQL `UTF8(payload)`
  - Splunk `EventCode` → QRadar AQL `EventID`
  - Splunk `CommandLine` → QRadar AQL `UTF8(payload)`
  - Sentinel KQL `EventID` → QRadar AQL `EventID`
- Follow syntax rules of the target platform:
  - Use `=` in AQL
  - Use `:` in KQL
  - Use `stats` in Splunk
  - Always use `index=*` unless the index name is explicitly given in the source rule.
Rule: {rule}
"""
    response = model.generate_content(prompt)
    return response.text


while True:
    c = int(input("Press 1 to convert rule or 0 to exit: "))
    if c == 0:  
        print("Exiting the program.....")
        break
    else:
        source_platform = input("Enter the source platform: ")
        print("Paste the rule (press Enter twice to finish):")
        lines = []
        while True:
            line = input()
            if line.strip() == "":
                break
            lines.append(line)
            rule = " ".join(lines)
        target_platform = input("Enter the target platform: ")
        res = convert_rule(source_platform,rule,target_platform)
        print("Converted Rule:",res)
