# ==================================================================================
# DAIS CONFIGURATION
# ==================================================================================

# Toggle the "[-]" logo injection at the start of every line
SHOW_LOGO = True

# Centralized Color Palette (ANSI Escape Codes)
# These values are read by the C++ engine at startup.
THEME = {
    "RESET":     "\x1b[0m",
    "STRUCTURE": "\x1b[38;5;240m", # Dark Gray (Borders, Parentheses)
    "UNIT":      "\x1b[38;5;109m", # Sage Blue (KB, MB, DIR label)
    "VALUE":     "\x1b[0m",        # Default White (Numbers, Filenames)
    "ESTIMATE":  "\x1b[38;5;139m", # Muted Purple (~)
    "DIR_NAME":  "\x1b[1m\x1b[38;5;39m", # Bold Blue (Directories)
    "SYMLINK":   "\x1b[38;5;36m",  # Cyan (Symlinks)
    
    # Engine Colors
    "LOGO":      "\x1b[95m",       # Pink/Magenta (The [-] Logo)
    "SUCCESS":   "\x1b[92m",       # Green (Success logs)
    "WARNING":   "\x1b[93m",       # Yellow (Warnings)
    "ERROR":     "\x1b[91m",       # Red (Errors)
    "NOTICE":    "\x1b[94m"        # Blue (Notifications)
}