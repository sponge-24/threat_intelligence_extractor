import os
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import logging
from dotenv import load_dotenv
load_dotenv()

# Import your custom modules
from pdf_to_text import extract_text_from_pdf
from extract_with_qwen import extract_entities_with_ollama
from ioc_extract import extract_and_analyze_iocs

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Supported extraction fields
SUPPORTED_FIELDS = {
    'iocs': 'Extract Indicators of Compromise (IoCs)',
    'ttps': 'Extract Tactics, Techniques, and Procedures (TTPs)',
    'threat_actors': 'Extract Threat Actors',
    'malware': 'Extract Malware Information',
    'targeted_entities': 'Extract Targeted Entities'
}

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
        
        # Get selected extraction fields from request
        selected_fields = request.form.getlist('extraction_fields')
        
        # Validate selected fields
        if not selected_fields:
            return jsonify({"error": "Please select at least one extraction field"}), 400
        
        invalid_fields = set(selected_fields) - set(SUPPORTED_FIELDS.keys())
        if invalid_fields:
            return jsonify({"error": f"Invalid fields: {', '.join(invalid_fields)}"}), 400
        
        if file and file.filename.lower().endswith('.pdf'):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                # Extract text from PDF
                text = extract_text_from_pdf(filepath)
                
                # Initialize results dictionary
                results = {}
                if all(field in selected_fields for field in ['iocs', 'threat_actors', 'ttps', 'malware', 'targeted_entities']):
                        entities = extract_entities_with_ollama(choice="all", text=text)
                        results['IoCs'] = extract_and_analyze_iocs(text, api_key=os.getenv("api_key"))
                        results['TTPs'] = entities['ttps']
                        results['Threat Actor(s)'] = entities['threat_actors']
                        results['Malware'] = entities['malware']
                        results['Targeted Entities'] = entities['targeted_entities']
                
                else:
                    # Extract selected fields
                    for field in selected_fields:
                        if field == 'iocs':
                            results['IoCs'] = extract_and_analyze_iocs(text,  api_key=os.getenv("api_key"))
                        else:
                            # Use the new extract_entities_with_ollama function with specific field
                            field_results = extract_entities_with_ollama(choice=field, text=text)
                            
                            # Map field names to result keys
                            result_key_map = {
                                'threat_actors': 'Threat Actor(s)',
                                'ttps': 'TTPs',
                                'malware': 'Malware',
                                'targeted_entities': 'Targeted Entities'
                            }
                            
                            # Add the results with the mapped key
                            if field in result_key_map:
                                results[result_key_map[field]] = field_results.get(field, [])
                
                # Remove uploaded file
                os.remove(filepath)
                
                return jsonify(results)

            except Exception as e:
                logging.error(f"Error processing PDF: {e}")
                return jsonify({"error": str(e)}), 500
        
        return jsonify({"error": "Invalid file type. Please upload a PDF."}), 400
    
    return render_template('index.html', supported_fields=SUPPORTED_FIELDS)

if __name__ == '__main__':
    app.run(debug=True)