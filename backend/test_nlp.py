from transformers import pipeline

summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
text = """
Scan detected 3 SQL injection vulnerabilities and 2 XSS vulnerabilities.
The SQLi issues are in the login form, search page, and user profile.
XSS was found in the comment section and URL parameters.
"""
summary = summarizer(text, max_length=50, min_length=25, do_sample=False)
print(summary[0]["summary_text"]) 