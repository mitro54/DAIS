# ==================================================================================
# DAIS CONFIGURATION
# ==================================================================================

# Toggle the "[-]" logo injection at the start of every line
SHOW_LOGO = True

# SHELL PROMPT DETECTION
# DAIS needs to know what your shell prompt looks like to know when 'ls' has finished.
# Common defaults are added below. If DAIS hangs on 'ls', add your prompt here.
# NOTE: It is safer to include the trailing space if your prompt has one.
SHELL_PROMPTS = [
    "$ ",  # Bash / Zsh default (user)
    "% ",  # Zsh default
    "> ",  # Python / Windows default
    "# ",  # Root default
    "➜ "   # Starship / Oh-My-Zsh common arrow
]

# Centralized Color Palette (ANSI Escape Codes)
# These values are read by the C++ engine at startup.
THEME = {
    "RESET":     "\x1b[0m",
    "STRUCTURE": "\x1b[38;5;240m", # Dark Gray (Borders, Parentheses)
    "UNIT":      "\x1b[38;5;109m", # Sage Blue (KB, MB, DIR label)
    "VALUE":     "\x1b[0m",        # Default White (Numbers, Filenames)
    "ESTIMATE":  "\x1b[38;5;139m", # Muted Purple (~)
    "TEXT":      "\x1b[0m",        # Default White (Directories)
    "SYMLINK":   "\x1b[38;5;36m",  # Cyan (Symlinks)
    
    # Engine Colors
    "LOGO":      "\x1b[95m",       # Pink/Magenta (The [-] Logo)
    "SUCCESS":   "\x1b[92m",       # Green (Success logs)
    "WARNING":   "\x1b[93m",       # Yellow (Warnings)
    "ERROR":     "\x1b[91m",       # Red (Errors)
    "NOTICE":    "\x1b[94m"        # Blue (Notifications)
}

# ==================================================================================
# LS OUTPUT FORMATTING
# ==================================================================================
# Customize how 'ls' output is displayed using format templates.
#
# Data placeholders:
#   {name}  - filename or directory name
#   {size}  - formatted size (e.g., "10KB", "1.5MB")
#   {rows}  - row count for text files (e.g., "50", "~1.2k")
#   {cols}  - max column width for text files
#   {count} - item count (directories only)
#
# Color placeholders (use THEME colors):
#   {RESET}     - reset to default
#   {STRUCTURE} - borders, parentheses, punctuation
#   {VALUE}     - numbers and values
#   {UNIT}      - units like KB, R, C, items
#   {ESTIMATE}  - for estimated values (~)
#   {TEXT}      - text/filename color
#   {SYMLINK}   - symlink names

LS_FORMATS = {
    "directory":   "{TEXT}{name}{STRUCTURE}/ ({VALUE}{count} {UNIT}items{STRUCTURE})",
    "text_file":   "{TEXT}{name} {STRUCTURE}({VALUE}{size}{STRUCTURE}, {VALUE}{rows} {UNIT}R{STRUCTURE}, {VALUE}{cols} {UNIT}C{STRUCTURE})",
    "data_file":   "{TEXT}{name} {STRUCTURE}({VALUE}{size}{STRUCTURE}, {VALUE}{rows} {UNIT}R{STRUCTURE}, {VALUE}{cols} {UNIT}C{STRUCTURE})",
    "binary_file": "{TEXT}{name} {STRUCTURE}({VALUE}{size}{STRUCTURE})",
    "error":       "{TEXT}{name}",  # Shown when file analysis fails
}


# ==========================================
# Icons Style for example
# ==========================================
# LS_FORMATS = {
#     "directory":   "📁 {TEXT}{name}{STRUCTURE}/ ({VALUE}{count} {UNIT}items{STRUCTURE})",
#     "text_file":   "📄 {TEXT}{name} {STRUCTURE}({VALUE}{size}{STRUCTURE}, {VALUE}{rows}{UNIT}R{STRUCTURE}, {VALUE}{cols}{UNIT}C{STRUCTURE})",
#     "data_file":   "📊 {TEXT}{name} {STRUCTURE}({VALUE}{size}{STRUCTURE}, {VALUE}{rows}{UNIT}R{STRUCTURE}, {VALUE}{cols}{UNIT}cols{STRUCTURE})",
#     "binary_file": "📦 {TEXT}{name} {STRUCTURE}({VALUE}{size}{STRUCTURE})",
#     "error":       "❓ {TEXT}{name}",
# }