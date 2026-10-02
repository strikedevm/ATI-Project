import os
from fpdf import FPDF

# --- DIRECTORY TREE GENERATOR ---
def generate_ascii_tree(source_folder, ignored_dirs):
    """Generates a text-based representation of the directory structure."""
    tree_lines = [f"{os.path.basename(os.path.abspath(source_folder))}/"]
    for root, dirs, files in os.walk(source_folder):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        level = root.replace(source_folder, '').count(os.sep)
        indent = ' ' * 4 * level
        
        if level > 0:
            tree_lines.append(f"{indent}{os.path.basename(root)}/")
            
        subindent = ' ' * 4 * (level + 1)
        for f in sorted(files):
            # Exclude .env and .html from the visual tree
            if f != '.env' and not f.endswith('.html'):  
                tree_lines.append(f"{subindent}{f}")
                
    return "\n".join(tree_lines)


def merge_project_files_to_pdf(source_folder, output_filename):
    # Initialize the PDF object
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Removed 'data' from ignored_dirs so it shows up in the directory tree
    ignored_dirs = {'.git', '__pycache__', '.vscode', '.idea', 'venv'}
    print(f"Scanning: {source_folder}")

    # 1. Bucket lists to control the specific order
    docs_and_images = []
    env_copy_files = []
    py_files = []
    other_files = []
    log_files = []
    
    total_py_loc = 0

    # 2. Collect and categorize all files
    for root, dirs, files in os.walk(source_folder):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]

        for filename in files:
            rel_path = os.path.relpath(os.path.join(root, filename), source_folder)

            # Strictly ignore the real .env file and all .html files entirely
            if filename == '.env' or filename.endswith('.html'):
                continue 
            
            # Skip documenting files inside the 'data' folder (even though it shows in the tree)
            if 'data' in rel_path.split(os.sep):
                continue

            # Route files into their respective buckets
            if filename.endswith(('.md', '.png', '.jpg', '.jpeg')):
                docs_and_images.append(rel_path)
            elif filename == '.env copy':
                env_copy_files.append(rel_path)
            elif filename.endswith('.py'):
                py_files.append(rel_path)
                
                # Calculate total lines of code for the header (excluding x.py)
                if filename != 'x.py':
                    try:
                        with open(os.path.join(root, filename), 'r', encoding='utf-8', errors='ignore') as f:
                            total_py_loc += len(f.readlines())
                    except Exception:
                        pass
                        
            elif filename.endswith('.log'):
                log_files.append(rel_path)
            else:
                other_files.append(rel_path) # Catches requirements.txt, etc.

    # Sort each bucket alphabetically
    docs_and_images.sort()
    env_copy_files.sort()
    py_files.sort()
    other_files.sort()
    log_files.sort()
    
    # Combine in the specific requested order
    ordered_files = docs_and_images + env_copy_files + py_files + other_files + log_files

    # Dictionary to hold the clickable link targets
    links = {}

    # --- A. Custom Header & Directory Tree ---
    pdf.add_page()
    
    # Custom Header Block
    pdf.set_font("Courier", "B", 9)
    header_text = (
        "# ==============================================================================\n"
        "# Author: Yuga \n"
        "# Description: Build an AI-based Intelligent Lab Builder\n"
        f"# Size= {total_py_loc} (Total lines of Python code, excluding x.py)\n"
        "# ==============================================================================\n"
    )
    pdf.multi_cell(0, 4, header_text)
    pdf.ln(5)
    
    # Title
    pdf.set_font("Courier", "B", 14)
    pdf.cell(0, 10, "Project Codebase Documentation", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(5)
    
    # Tree
    pdf.set_font("Courier", "", 9)
    raw_tree = generate_ascii_tree(source_folder, ignored_dirs)
    safe_tree = raw_tree.encode('latin-1', 'replace').decode('latin-1') 
    pdf.multi_cell(0, 4, safe_tree)
    
    # --- B. Clickable Index Page ---
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Index", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    pdf.set_font("Helvetica", "U", 10)
    pdf.set_text_color(0, 0, 255) # Blue links
    
    for rel_path in ordered_files:
        link_id = pdf.add_link()
        links[rel_path] = link_id
        
        safe_path = rel_path.encode('latin-1', 'replace').decode('latin-1')
        pdf.cell(0, 8, safe_path, link=link_id, new_x="LMARGIN", new_y="NEXT")
        
    pdf.set_text_color(0, 0, 0) # Reset to black text

    # --- C. Process Files ---
    for rel_path in ordered_files:
        file_path = os.path.join(source_folder, rel_path)
        
        pdf.add_page()
        
        if rel_path in links:
            pdf.set_link(links[rel_path])

        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, f"FILE: {rel_path}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

        try:
            # Handle Image Files
            if file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
                pdf.image(file_path, w=pdf.epw)
                print(f"Added Image: {rel_path}")
                continue

            # Handle Text-based Files
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.read().splitlines()

            pdf.set_font("Helvetica", "I", 9)
            if not lines:
                pdf.cell(0, 5, "*[File is empty]*", new_x="LMARGIN", new_y="NEXT")
                continue

            # Special Log Handling
            if file_path.endswith('.log'):
                content = "===TRUNCATED------\n" + "\n".join(lines[-5:])
                pdf.cell(0, 5, "Line Count: (Showing last 5 lines)", new_x="LMARGIN", new_y="NEXT")
            else:
                content = "\n".join(lines)
                pdf.cell(0, 5, f"Line Count: {len(lines)}", new_x="LMARGIN", new_y="NEXT")

            pdf.ln(4)

            # Write text content
            pdf.set_font("Courier", "", 8)
            safe_content = content.encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 4, safe_content)
            print(f"Processed: {rel_path}")

        except Exception as e:
            pdf.set_text_color(255, 0, 0)
            pdf.cell(0, 5, f"[Error loading file: {e}]", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            print(f"Skipped {rel_path} due to error: {e}")

    # Save Document
    pdf.output(output_filename)
    print(f"\nDone! Saved to: {output_filename}")


# --- CONFIGURATION ---
path = r'.'
output = 'test.pdf'

merge_project_files_to_pdf(path, output)
