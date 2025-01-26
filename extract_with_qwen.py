import re
import ollama
import json
from typing import Dict, List

def extract_entities_with_ollama(choice:str, text: str, model_name='qwen2.5') -> Dict[str, List[str]]:
    """
    Use Ollama Qwen to extract structured threat intelligence data
    """
    prompts = {
        "threat_actors": f"""
            Extract the following threat intelligence entities from the text:

            1. Threat Actors (only name of threat)

            Only extract the asked details, Don't extract any other details 
            dont include any other json keys on your own 

            Text: {text}

            Provide response in strict JSON format with these keys:
            - threat_actors

            important : dont use markdown and only give response in the json format
            remember: you have to give only the name of the threat actor
        """,
        "ttps": f"""
            Extract the following threat intelligence entities from the text:

            1. TTPs (Tactics, Techniques, and Procedures)

            Only extract the asked details, Don't extract any other details 
            dont include any other json keys on your own 

            Text: {text}

            Provide response in strict JSON format with these keys:
            - ttps

            important : dont use markdown and only give response in the json format
            give only name and id of the TTPs dont give any other
        """,
        "malware": f"""
             Extract the following threat intelligence entities from the text:

            1. All Malware Names (only name of the malwares in the text)

            Only extract the asked details, Don't extract any other details 
            dont include any other json keys on your own 

            Text: {text}

            Provide response in strict JSON format with these keys:
            - malware


            important : dont use markdown and only give response in the json format
            remember: you have to give only the name of the malware
        """,
        "targeted_entities": f"""
            Extract the following threat intelligence entities from the text:

            1. victims (only name of the targeted entities)

            Only extract the asked details, Don't extract any other details 
            dont include any other json keys on your own 

            Text: {text}

            Provide response in strict JSON format with these keys:
            - targeted_entities

            important : dont use markdown and only give response in the json format
            remember: you have to give only the name of the targeted entities
        """,
        "all": f"""
            Extract the following threat intelligence entities from the text:

            1. Threat Actors (only name of threat)
            2. TTPs
            3. Malware Names (only name of the malware in the text)
            4. victims (only name of the targeted entities)

            Only extract the asked details, Don't extract any other details 
            dont include any other json keys on your own 

            Text: {text}

            Provide response in strict JSON format with these keys:
            - threat_actors
            - ttps { "Tactics", "Techniques"}
            - malware
            - targeted_entities

            important : dont use markdown and only give response in the json format
            remember: you have to give only the name of the threat actor, malware, targeted entities
        """,
    }
    prompt = prompts.get(choice, prompts["all"])
    try:
        # Attempt to get response
        response = ollama.chat(
            model=model_name,
            messages=[{'role': 'user', 'content': prompt}]
        )
        # Extract content and clean potential markdown
        content = response['message']['content']
        
        # Remove markdown code block markers if present
        content = content.strip('`\n')
        json_match = re.search(r'{.*}', content, re.DOTALL)

        # Parse the JSON response
        if json_match:
            entities = json.loads(json_match.group())
            return entities
        else:
            raise ValueError("No JSON response found")
    
    except Exception as e:
        print(f"Error extracting entities: {e}")
        return {}

def main():
    
    text = """The APT33 group, suspected to be from Iran, has launched a new campaign targeting 
the energy sector organizations. 
 The attack utilizes Shamoon malware, known for its destructive capabilities. The threat 
actor exploited a vulnerability in the network perimeter to gain initial access. 
 The malware was delivered via spear-phishing emails containing a malicious 
attachment. The malware's behavior was observed communicating with IP address 
192.168.1.1 and domain example.com. The attack also involved lateral movement using 
PowerShell scripts."""

    print(extract_entities_with_ollama(choice="all",text= text))

if __name__ == "__main__":
    main()
