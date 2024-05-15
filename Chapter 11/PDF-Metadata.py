#!/usr/bin/env python3
# PDF Metadata Extract
# Author Yehia Elghaly

import os
import time
import hashlib
import magic
import argparse
import PyPDF2

def extract_pdf_metadata(file_path):
    with open(file_path, 'rb') as f:
        pdf_reader = PyPDF2.PdfFileReader(f)
        metadata = pdf_reader.getDocumentInfo()
        num_pages = pdf_reader.getNumPages()
        text = ""
        links = []
        javascript_objects = []
        flash_objects = []

        for i in range(num_pages):
            page = pdf_reader.getPage(i)
            text += page.extractText()
            annotations = page.get('/Annots', [])
            if isinstance(annotations, PyPDF2.generic.IndirectObject):
                annotations = annotations.getObject()

            if isinstance(annotations, list):
                for annot in annotations:
                    action = annot.getObject().get('/A')
                    if action:
                        action_resolved = pdf_reader.getObject(action)
                        if action_resolved.get('/URI'):
                            uri = action_resolved.get('/URI')
                            links.append(uri)

            # Check for JavaScript objects
            if page.get('/AA'):
                for key, value in page.get('/AA').items():
                    if key == '/JS' or key == '/JavaScript':
                        javascript_objects.append(value)

            # Check for Flash objects
            if page.get('/RichMedia'):
                for rich_media in page.get('/RichMedia'):
                    if rich_media.get('/RichMediaSettings'):
                        if rich_media.get('/RichMediaSettings').get('/FlashVars'):
                            flash_objects.append(rich_media)

        try:
            outlines = pdf_reader.getOutlines()
        except:
            outlines = "No outlines found"

    return metadata, num_pages, text, outlines, links, javascript_objects, flash_objects

# Argument parsing
parser = argparse.ArgumentParser(description="Analyze file metadata and generate hashes.")
parser.add_argument('-f', '--file', type=str, required=True, help="Path to the file to be analyzed.")
args = parser.parse_args()

file_path = args.file

# File type identification
magic_obj = magic.Magic()
file_type = magic_obj.from_file(file_path)

if 'PDF' in file_type:
    metadata, num_pages, text, outlines, links, javascript_objects, flash_objects = extract_pdf_metadata(file_path)
    
    if metadata is not None:
        print("PDF Metadata:")
        for key, value in metadata.items():
            print(f"{key}: {value}")
    else:
        print("No metadata found.")

    print("\nNumber of pages:", num_pages)

    print("\nText content:")
    print(text)

    print("\nOutlines:")
    print(outlines)

    print("\nLinks:")
    for link in links:
        print(link)
    
    print("\nJavaScript objects:")
    for js_object in javascript_objects:
        print(js_object)
    
    print("\nFlash objects:")
    for flash_object in flash_objects:
        print(flash_object)

else:
    print("This script currently only supports PDF file metadata extraction.")
