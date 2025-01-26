# Threat Intelligence Extraction and Analysis Web Application

## Problem Statement

Cybersecurity teams often face difficulties in quickly extracting critical information from threat reports, such as Indicators of Compromise (IoCs), Threat Actors, Malware, and attack methods (TTPs). This process is usually manual, time-consuming, and prone to errors, slowing down the response to emerging threats.

## Proposed Solution

We propose a Flask-based web application that automates the extraction of key cybersecurity data from PDF threat reports. The application will use Natural Language Processing (NLP) to identify and extract IoCs, Threat Actors, Malware, TTPs, and Targeted Entities. Additionally, it will analyze extracted IoCs with VirusTotal for malicious activity.

## Key Features

- **PDF Upload**: Users can upload PDF reports, and the system will extract the text.
- **Automated Extraction**: The app will automatically extract threat intelligence such as IoCs, Malware, and TTPs.
- **IoC Analysis**: Extracted IoCs (hashes) will be checked against VirusTotal for potential threats.

## Uniqueness

- **Faster Threat Detection**: Automates manual analysis, reducing the time needed to identify threats.
- **Comprehensive Analysis**: Extracts, analyzes, and enriches threat data automatically.

## How IoCs are Extracted and Enriched

1. **Text Extraction**: The text from the PDF is extracted using `pdfminer`.
2. **Pattern Matching**: Regular expressions are used to identify common IoC patterns like IP addresses, URLs, emails, and file hashes, utilizing the `iocextract` library.
3. **Enrichment and Analysis**: VirusTotal is used to analyze file hashes for malicious activity, and if found, the metadata is attached to the corresponding hash.

> *Note*: IoCs are not extracted using Named Entity Recognition (NER) because it requires more time to analyze and extract the text. Regular expressions allow for more efficient extraction.

## How Other Threat Entities are Extracted

1. **Input Text**: The text containing threat intelligence data is extracted from the PDF.
2. **Prompt Creation**: Specific prompts are generated for each entity type (TTPs, Malware, Targeted Entities). If all entities are selected, a combined prompt is used.
3. **API Request**: The text, along with the generated prompt, is sent to the LLM `qwen2.5` for contextual analysis.
4. **Model Processing**: The model identifies entities (TTPs, Malware, and Targeted Entities) and returns results in structured JSON format.
5. **Return Results**: Parse the JSON response and return the extracted entities to the user.

## Overall Flow of the Process

1. **User Uploads PDF**: The user uploads a PDF file for analysis through the web interface.
2. **Text Extraction**: The text is extracted from the PDF using the `pdfminer` library.
3. **Field Selection**: The user selects the fields (IoCs, TTPs, Threat Actors, Malware, and Targeted Entities) they want to extract from the text.
4. **Entity Extraction**: For each selected field, a respective query is sent to Ollama (`qwen2.5`) to extract the relevant entities.
5. **Metadata for IoCs**: If IoCs (hashes) are extracted, they are analyzed using the VirusTotal API to gather metadata.
6. **Result Compilation**: The extracted entities and metadata are compiled into a structured response.
7. **Display Results**: The extracted data is displayed to the user in a readable format.

## Requirements

- `pdfminer.six`
- `iocextract`
- `requests`
- `ollama`
- `python-dotenv`
- `flask`

Install the packages from the `requirements.txt` file in the project folder.  
Apart from those requirements, install Ollama on the machine and download the `qwen2.5` model.

- Link for downloading Ollama: [https://ollama.com/download](https://ollama.com/download)
- Command to install `qwen2.5`:  
  ```bash
  ollama run qwen2.5
  ```

Set up an account in VirusTotal and enter the API key in the `.env` file present in the project folder for entity enrichment.

## How to Run

1. Ensure all dependencies are installed.
2. Inside the project folder, run the following command:
   ```bash
   python main.py
   ```
3. Open the link in your browser: [http://127.0.0.1:5000](http://127.0.0.1:5000)
