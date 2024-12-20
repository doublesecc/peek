import argparse
import hashlib
import base64
import urllib.parse
from termcolor import colored
import re
import os
from tqdm import tqdm  # For the loading bar

def load_wordlist(wordlist_file=None, word_string=None):
    """Load words from a wordlist file into a set, or use a direct string."""
    if word_string:
        return {word_string}  # Treat the string as a single word
    elif wordlist_file:
        with open(wordlist_file, 'r') as f:
            return {line.strip() for line in f if line.strip()}
    return set()  # Return empty set if neither is provided

def md5_hash(word):
    """Return the MD5 hash of the word."""
    return hashlib.md5(word.encode('utf-8')).hexdigest()

def sha1_hash(word):
    """Return the SHA1 hash of the word."""
    return hashlib.sha1(word.encode('utf-8')).hexdigest()

def sha256_hash(word):
    """Return the SHA256 hash of the word."""
    return hashlib.sha256(word.encode('utf-8')).hexdigest()

def base64_encode(word):
    """Return the Base64 encoded version of the word."""
    return base64.b64encode(word.encode('utf-8')).decode('utf-8')

def url_encode(word):
    """Return the URL encoded version of the word."""
    return urllib.parse.quote(word)

def process_encoded_data(encoded_data, encoding_type):
    """Decode or hash the data based on the encoding type."""
    if encoding_type == 'md5':
        return md5_hash(encoded_data)
    elif encoding_type == 'sha1':
        return sha1_hash(encoded_data)
    elif encoding_type == 'sha256':
        return sha256_hash(encoded_data)
    elif encoding_type == 'b64':
        return base64_encode(encoded_data)
    elif encoding_type == 'url':
        return url_encode(encoded_data)
    else:
        print(f"Unsupported encoding type: {encoding_type}")
        return None

def similarity_ratio(str1, str2):
    """Calculate similarity between two strings based on the ratio of matching characters."""
    matches = sum(1 for a, b in zip(str1, str2) if a == b)
    return matches / max(len(str1), len(str2))

def search_file(file_path, wordlist, encoding_type=None, verbose=0, partial=False, min_similarity=0.60, case_sensitive=False):
    """Search a file for words or encoded words from the wordlist."""
    word_counts = {}
    word_files = {}  # To track which files have matched words and their occurrences
    partial_matches = {}  # Store partial matches and their context
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
    except UnicodeDecodeError:
        try:
            with open(file_path, 'r', encoding='ISO-8859-1') as f:
                file_content = f.read()
        except UnicodeDecodeError:
            print(f"Skipping file due to encoding error: {file_path}")
            return word_counts, word_files, partial_matches

    if not case_sensitive:
        file_content = file_content.lower()

    if verbose > 0:
        print(f"Searching in: {file_path}")

    for word in wordlist:
        if len(word) < 2:
            continue

        # If encoding type is specified, process the word accordingly
        if encoding_type:
            encoded_word = process_encoded_data(word, encoding_type)
            if verbose > 0:
                print(colored(f"Encoded word for '{word}' using {encoding_type}: {encoded_word}", 'yellow'))
            count = len(re.findall(re.escape(encoded_word), file_content))
        else:
            search_word = word if case_sensitive else word.lower()
            count = len(re.findall(r'\b' + re.escape(search_word) + r'(?!\w)', file_content))

        partial_match_found = False
        partial_match_context = ""
        if partial and count == 0:
            for i in range(len(file_content) - len(word) + 1):
                substring = file_content[i:i + len(word)]
                if similarity_ratio(word, substring) >= min_similarity:
                    partial_match_found = True
                    count = 1
                    # Capture the surrounding context of the match (before and after the match)
                    context_start = max(0, i - 30)  # 30 characters before
                    context_end = min(len(file_content), i + len(word) + 30)  # 30 characters after
                    partial_match_context = file_content[context_start:context_end]
                    break

        if count > 0:
            word_counts[word] = word_counts.get(word, 0) + count
            if word not in word_files:
                word_files[word] = []
            word_files[word].append((file_path, count))

        if partial_match_found:
            if word not in partial_matches:
                partial_matches[word] = []
            partial_matches[word].append((file_path, partial_match_context))

        if verbose == 1:
            if count > 0:
                print(colored(f"[ + ] {word} (found {count} times)", 'green'))
            elif partial_match_found:
                print(colored(f"[ ~ ] {word} (partial match found, {count} times)", 'cyan'))

        if verbose == 2:
            if count > 0:
                print(colored(f"[ + ] {word} (found {count} times)", 'green'))
            elif partial_match_found:
                print(colored(f"[ ~ ] {word} (partial match found, {count} times)", 'cyan'))
            else:
                print(colored(f"[ - ] {word} (not found)", 'red'))

    return word_counts, word_files, partial_matches

def search_directory(dir_path, wordlist, encoding_type=None, verbose=0, partial=False, min_similarity=0.80, case_sensitive=False, quiet=False):
    """Search all files in a directory and its subdirectories."""
    word_counts = {}
    word_files = {}
    partial_matches = {}
    files = []
    for root, dirs, files_in_dir in os.walk(dir_path):
        for file in files_in_dir:
            files.append(os.path.join(root, file))
    
    with tqdm(total=len(files), desc="Searching files", unit="file", disable=quiet) as pbar:
        for file_path in files:
            file_word_counts, file_word_files, file_partial_matches = search_file(file_path, wordlist, encoding_type, verbose, partial, min_similarity, case_sensitive)
            word_counts.update(file_word_counts)
            for word, occurrences in file_word_files.items():
                if word not in word_files:
                    word_files[word] = []
                word_files[word].extend(occurrences)
            for word, partial_occurrences in file_partial_matches.items():
                if word not in partial_matches:
                    partial_matches[word] = []
                partial_matches[word].extend(partial_occurrences)
            pbar.update(1)
    
    return word_counts, word_files, partial_matches


def save_results(word_counts, output_file):
    """Save the matched results to a file."""
    with open(output_file, 'w') as f:
        for word, count in word_counts.items():
            f.write(f"Original Word: {word}, Occurrences: {count}\n")

def print_banner():
    """Print the banner when the script runs."""
    banner = """
   _ (`-.    ('-.     ('-.  .-. .-')   
  ( (OO  ) _(  OO)  _(  OO) \  ( OO )  
 _.`     \(,------.(,------.,--. ,--.  
(__...--'' |  .---' |  .---'|  .'   /  
 |  /  | | |  |     |  |    |      /,  
 |  |_.' |(|  '--. (|  '--. |     ' _) 
 |  .___.' |  .--'  |  .--' |  .   \   
 |  |      |  `---. |  `---.|  |\   \  
 `--'      `------' `------'`--' '--'  
"""
    print(colored(banner, 'magenta'))

from termcolor import colored

from termcolor import colored

def print_results_table(word_files, partial_matches):
    """Print the results table after search completion with colorized lines and column delimiters, including top border."""
    if word_files:
        # Print the top border
        print("-" * 120)
        
        # Print the header with a separator line
        print(f"| {'Searched Word':<20} | {'File Path':<50} | {'Occurrences':<10} | {'Partial Match Context'} |")
        
        # Print the separator line under the header
        print("-" * 120)
        
        for word, files in word_files.items():
            total_occurrences = 0
            # First print full matches in green
            for file, count in files:
                total_occurrences += count
                print(colored(f"| {word:<20} | {file:<50} | {count:<10} |", 'green'), end="")
                print(colored(f" Full match |", 'green'))
            
            # Then print partial matches in cyan and magenta for the matched part
            if word in partial_matches:
                for partial_file, partial_context in partial_matches[word]:
                    total_occurrences += 1  # For each partial match

                    # Find the position of the matched part (case-insensitive)
                    match_start = partial_context.lower().find(word.lower())
                    
                    # Only process the match if the word is found in the context
                    if match_start != -1:
                        match_end = match_start + len(word)

                        # Divide the context into three parts: before, matched, and after
                        before_match = partial_context[:match_start]
                        match = partial_context[match_start:match_end]
                        after_match = partial_context[match_end:]

                        # Print the context with the matched part in magenta and the rest in cyan
                        print(colored(f"| {word:<20} | {partial_file:<50} | {'1':<10} |", 'cyan'), end="")
                        print(f" Partial Match: {colored(before_match, 'cyan')}{colored(match, 'magenta')}{colored(after_match, 'cyan')} |")
            
            # After printing all instances of the word, print the total occurrences in magenta
            print(colored(f"| {'':<20} | {'':<50} | {total_occurrences:<10} | Total Occurrences |", 'magenta'))

        # Print bottom border
        print("-" * 120)
    else:
        print("Search completed with no matches.")


def main():
    parser = argparse.ArgumentParser(description="Search a file or directory for words from a wordlist or a string.")
    
    # Argument group for file or directory
    group_input = parser.add_mutually_exclusive_group(required=True)
    group_input.add_argument('-f', '--file', help="Path to the file to search in")
    group_input.add_argument('-d', '--dir', help="Path to the directory to search in recursively")
    
    # Argument group for wordlist or string
    group_word_or_string = parser.add_mutually_exclusive_group(required=True)
    group_word_or_string.add_argument('-w', '--wordlist', help="Path to the wordlist file")
    group_word_or_string.add_argument('-s', '--string', help="String to search for")
    
    # Other optional arguments
    parser.add_argument('-e', '--encode', choices=['md5', 'sha1', 'sha256', 'b64', 'url'],
                        help="Specify encoding type (md5, sha1, sha256, b64, url)")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose mode, print each check result")
    parser.add_argument('-vv', '--very-verbose', action='store_true', help="Very verbose mode, print all details")
    parser.add_argument('-o', '--output', help="Save matched results to the specified output file")
    parser.add_argument('-p', '--partial', action='store_true', help="Enable partial word matching")
    parser.add_argument('--case-sensitive', action='store_true', help="Enable case-sensitive search (default is case-insensitive)")
    parser.add_argument('-t', '--threshold', type=float, default=0.75, help="Partial match threshold 0.0-1 (default is 0.75)")
    parser.add_argument('--no-banner', action='store_true', help="Disable banner print")

    args = parser.parse_args()

    # Print banner if not disabled
    if not args.no_banner:
        print_banner()

    # Load wordlist or string
    if args.string:
        wordlist = load_wordlist(word_string=args.string)
    elif args.wordlist:
        wordlist = load_wordlist(wordlist_file=args.wordlist)
    else:
        print("Error: You must specify either a wordlist file or a string to search.")
        return

    word_counts = {}
    word_files = {}
    partial_matches = {}

    # Perform the search, depending on file or directory argument
    if args.file:
        word_counts, word_files, partial_matches = search_file(
            args.file,
            wordlist,
            encoding_type=args.encode,
            verbose=2 if args.very_verbose else (1 if args.verbose else 0),
            partial=args.partial,
            min_similarity=args.threshold,
            case_sensitive=args.case_sensitive
        )
    elif args.dir:
        word_counts, word_files, partial_matches = search_directory(
            args.dir,
            wordlist,
            encoding_type=args.encode,
            verbose=2 if args.very_verbose else (1 if args.verbose else 0),
            partial=args.partial,
            min_similarity=args.threshold,
            case_sensitive=args.case_sensitive
        )
    else:
        print("Error: You must specify either a file or a directory to search.")
        return

    # Save to output file if specified
    if args.output:
        save_results(word_counts, args.output)
        print(f"Results saved to {args.output}")

    # Print the results table after search completion
    print_results_table(word_files, partial_matches)

if __name__ == "__main__":
    main()