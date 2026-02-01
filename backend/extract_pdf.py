import pypdf
import os
import traceback

pdf_path = "../../Session 2 - Modern LLM Internals & SFT_ Foundation II_ [#] EAG V2.pdf"
output_path = "session_2_content.txt"

print(f"Extracting from: {os.path.abspath(pdf_path)}")

try:
    reader = pypdf.PdfReader(pdf_path)
    print(f"Number of pages: {len(reader.pages)}")
    
    with open(output_path, "w", encoding="utf-8") as f:
        for i, page in enumerate(reader.pages):
            f.write(f"--- Page {i+1} ---\n")
            try:
                # Try layout mode first, then plain
                text = page.extract_text()
            except Exception as e:
                print(f"Page {i+1} standard extraction failed: {e}. Trying plain mode.")
                try:
                    text = page.extract_text(extraction_mode="plain")
                except Exception as e2:
                    print(f"Page {i+1} plain extraction failed: {e2}")
                    text = "[Extraction Failed]"
            
            f.write(text)
            f.write("\n\n")
    print(f"Extraction complete. Saved to {output_path}")
except Exception as e:
    print(f"Global Error: {e}")
    traceback.print_exc()
