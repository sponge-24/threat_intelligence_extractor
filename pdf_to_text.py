from pdfminer.high_level import extract_text

def extract_text_from_pdf(file_path):
    """
    Extracts text from a given PDF file and returns it as a string.

    :param file_path: Path to the PDF file.
    :return: Extracted text as a string, or None if an error occurs.
    """
    if not file_path.endswith(".pdf"):
        print(f"The file '{file_path}' is not a PDF.")
        return None

    try:
        # Extract text from the PDF
        text = extract_text(file_path)
        
        # Remove form feed characters and adjust spacing
        text = text.replace("\f", "").replace("\n", "     ")
        
        print(f"Successfully extracted text from '{file_path}'.")
        return text
    except Exception as e:
        print(f"Failed to process '{file_path}': {e}")
        return None


if __name__ == "__main__":
    # Example usage
    file_path = "./file.pdf" # Ask the user for a file path
    text = extract_text_from_pdf(file_path)

    if text:
        print(text)
    else:
        print("No text could be extracted.")
