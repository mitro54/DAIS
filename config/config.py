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
    "➜ ",  # Starship / Oh-My-Zsh common arrow
    "❯ ",  # Starship / Oh-My-Zsh common arrow
    ")> ", # Fish common (e.g. git branch)
    ")>",  # Fish common no-space
    "~> ", # Fish default
    "~>"   # Fish default no-space
]

# ==================================================================================
# FILE EXTENSION DETECTION
# ==================================================================================
# Customize which file extensions are recognized as text files or data files.
# Text files show: size, row count, max column width
# Data files show: size, row count, column count (uses data_file template)

TEXT_EXTENSIONS = [
    ".txt", ".cpp", ".hpp", ".c", ".h", ".py", ".md", ".cmake",
    ".log", ".sh", ".ini", ".js", ".ts", ".html", ".css", ".xml",
    ".yml", ".yaml", ".conf", ".toml", ".rs", ".go", ".java", ".rb"
]

DATA_EXTENSIONS = [
    ".csv", ".tsv", ".json"
]

# ==================================================================================
# LS SORTING
# ==================================================================================
# Configure how 'ls' output is sorted.
# Runtime commands:
#   :ls                     - Show current settings
#   :ls [by] [order] [dirs] - Change settings (e.g., :ls rows desc false)
#   :ls d                   - Reset to defaults

LS_SORT = {
    "by": "type",        # "name", "size", "type", "rows", "none"
    "order": "asc",      # "asc" or "desc"
    "dirs_first": True,  # Group directories before files
    "flow": "h"          # "h" (horizontal) or "v" (vertical)
}

# ==================================================================================
# LS OUTPUT FORMATTING
# ==================================================================================
# Configure the visual spacing of the 'ls' grid.
# Increase this value for more breathing room, decrease for a tighter grid.
LS_PADDING = 2  # default: 2 spaces (min: 1) (max: depends on terminal width)


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


# # ==========================================
# DEFAULT THEME
# # ==========================================
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


# # ==========================================
# CUSTOM SHOWCASE STYLE (Neon Nights)
# # ==========================================
# Comment out the default theme and uncomment this to use the custom theme 
# THEME = {
#     "RESET":     "\x1b[0m",
#     "STRUCTURE": "\x1b[38;5;213m", # Pink (Separators, Borders)
#     "UNIT":      "\x1b[38;5;123m", # Cyan (Labels like KB, items)
#     "VALUE":     "\x1b[38;5;226m", # Bright Yellow (Numbers)
#     "ESTIMATE":  "\x1b[38;5;208m", # Orange (Tilde ~)
#     "TEXT":      "\x1b[38;5;255m", # White (Filenames)
#     "SYMLINK":   "\x1b[38;5;51m",  # Cyan (Symlinks)
    
#     # Engine Colors
#     "LOGO":      "\x1b[38;5;196m", # Red
#     "SUCCESS":   "\x1b[38;5;46m",  # Green
#     "WARNING":   "\x1b[38;5;226m", # Yellow
#     "ERROR":     "\x1b[38;5;196m", # Red
#     "NOTICE":    "\x1b[38;5;21m"   # Blue
# }

# LS_FORMATS = {
#     "directory":   "{STRUCTURE}[ {UNIT}DIR {STRUCTURE}] {TEXT}{name} {STRUCTURE}--- {VALUE}{count} {UNIT}items",
#     "text_file":   "{STRUCTURE}[ {UNIT}TXT {STRUCTURE}] {TEXT}{name} {STRUCTURE}--- {VALUE}{size} {STRUCTURE}| {VALUE}{rows} {UNIT}lines {STRUCTURE}| {VALUE}{cols} {UNIT}wide",
#     "data_file":   "{STRUCTURE}[ {UNIT}DAT {STRUCTURE}] {TEXT}{name} {STRUCTURE}--- {VALUE}{size} {STRUCTURE}| {VALUE}{rows} {UNIT}rows {STRUCTURE}| {VALUE}{cols} {UNIT}cols",
#     "binary_file": "{STRUCTURE}[ {UNIT}BIN {STRUCTURE}] {TEXT}{name} {STRUCTURE}--- {VALUE}{size}",
#     "error":       "{STRUCTURE}[ {ERROR}ERR {STRUCTURE}] {TEXT}{name}",
# }


# ==========================================
# CUSTOM SHOWCASE STYLE (Deep Sea Diver)
# ==========================================
# THEME = {
#     "RESET":     "\x1b[0m",
#     "STRUCTURE": "\x1b[38;5;24m",  # Deep Blue (Borders)
#     "UNIT":      "\x1b[38;5;37m",  # Teal (Labels)
#     "VALUE":     "\x1b[38;5;255m", # White (Numbers)
#     "ESTIMATE":  "\x1b[38;5;30m",  # Aqua (~)
#     "TEXT":      "\x1b[38;5;195m", # Light Cyan (Filenames)
#     "SYMLINK":   "\x1b[38;5;87m",  # Cyan (Symlinks)
    
#     # Engine Colors
#     "LOGO":      "\x1b[38;5;39m",  # Bright Blue
#     "SUCCESS":   "\x1b[38;5;48m",  # Spring Green
#     "WARNING":   "\x1b[38;5;220m", # Gold
#     "ERROR":     "\x1b[38;5;196m", # Red
#     "NOTICE":    "\x1b[38;5;33m"   # Dodger Blue
# }

# LS_FORMATS = {
#     "directory":   "{STRUCTURE}>> {TEXT}{name} {STRUCTURE}:: {VALUE}{count} {UNIT}objects",
#     "text_file":   "{STRUCTURE}   {TEXT}{name} {STRUCTURE}:: {VALUE}{size} {STRUCTURE}[{VALUE}{rows} {UNIT}L{STRUCTURE}]",
#     "data_file":   "{STRUCTURE}   {TEXT}{name} {STRUCTURE}:: {VALUE}{size} {STRUCTURE}[{VALUE}{rows} {UNIT}R {STRUCTURE}x {VALUE}{cols} {UNIT}C{STRUCTURE}]",
#     "binary_file": "{STRUCTURE}   {TEXT}{name} {STRUCTURE}:: {VALUE}{size}",
#     "error":       "{STRUCTURE}!! {TEXT}{name}",
# }


# ==========================================
# CUSTOM SHOWCASE STYLE (Amber Retro)
# ==========================================
# THEME = {
#     "RESET":     "\x1b[0m",
#     "STRUCTURE": "\x1b[38;5;136m", # Dark Amber (Borders)
#     "UNIT":      "\x1b[38;5;136m", # Dark Amber (Labels)
#     "VALUE":     "\x1b[38;5;214m", # Bright Orange (Numbers)
#     "ESTIMATE":  "\x1b[38;5;214m", # Bright Orange (~)
#     "TEXT":      "\x1b[38;5;220m", # Gold (Filenames)
#     "SYMLINK":   "\x1b[38;5;208m", # Orange (Symlinks)
    
#     # Engine Colors
#     "LOGO":      "\x1b[38;5;214m", # Bright Orange
#     "SUCCESS":   "\x1b[38;5;214m", # Bright Orange
#     "WARNING":   "\x1b[38;5;208m", # Orange
#     "ERROR":     "\x1b[38;5;160m", # Deep Red
#     "NOTICE":    "\x1b[38;5;136m"  # Dark Amber
# }

# LS_FORMATS = {
#     "directory":   "{STRUCTURE}<{UNIT}DIR{STRUCTURE}>  {TEXT}{name} {STRUCTURE}.. {VALUE}{count} {UNIT}items",
#     "text_file":   "{STRUCTURE}<{UNIT}TXT{STRUCTURE}>  {TEXT}{name} {STRUCTURE}.. {VALUE}{size} {STRUCTURE}[{VALUE}{rows} {UNIT}L{STRUCTURE}]",
#     "data_file":   "{STRUCTURE}<{UNIT}DAT{STRUCTURE}>  {TEXT}{name} {STRUCTURE}.. {VALUE}{size} {STRUCTURE}[{VALUE}{rows} {UNIT}R {STRUCTURE}x {VALUE}{cols} {UNIT}C{STRUCTURE}]",
#     "binary_file": "{STRUCTURE}<{UNIT}BIN{STRUCTURE}>  {TEXT}{name} {STRUCTURE}.. {VALUE}{size}",
#     "error":       "{STRUCTURE}<{ERROR}ERR{STRUCTURE}>  {TEXT}{name}",
# }