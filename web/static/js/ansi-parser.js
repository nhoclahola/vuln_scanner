/**
 * ANSI Escape Sequence Parser
 * A utility for converting ANSI escape sequences to HTML with CSS classes
 */

class AnsiParser {
    constructor() {
        // Regular expressions for ANSI sequences
        this.ansiRegex = /\x1b\[([0-9;]*)m/g;
        this.emojiRegex = /🤖|🧠/g;
        
        // Special patterns
        this.patterns = [
            { regex: /\[1;32m🤖 Agent: \[0m\[32m([^[]+)\[0m/, replace: '<span class="ansi-bold ansi-green">🤖 Agent: $1</span>' },
            { regex: /\[37m Status: \[0m\[1;32m([^[]+)\[0m/, replace: '<span class="ansi-white">Status: </span><span class="ansi-bold ansi-green">$1</span>' },
            { regex: /\[1;34m🧠 \[0m\[34m([^[]+)\[0m/, replace: '<span class="ansi-bold ansi-blue">🧠 $1</span>' },
            { regex: /\[1m\[95m# Agent:\[00m \[1m\[92m([^[]+)\[00m/, replace: '<span class="ansi-bold ansi-bright-magenta"># Agent:</span> <span class="ansi-bold ansi-bright-green">$1</span>' },
            { regex: /\[95m## ([^:]+):\[00m \[92m(.+?)\[00m/, replace: '<span class="ansi-magenta">## $1:</span> <span class="ansi-green">$2</span>' },
            { regex: /└──/, replace: '└── ' }
        ];
        
        // ANSI color codes mapping
        this.colorCodes = {
            0: 'reset',
            1: 'bold',
            2: 'faint',
            3: 'italic',
            4: 'underline',
            5: 'blink',
            30: 'black',
            31: 'red',
            32: 'green',
            33: 'yellow',
            34: 'blue',
            35: 'magenta',
            36: 'cyan',
            37: 'white',
            90: 'bright-black',
            91: 'bright-red',
            92: 'bright-green',
            93: 'bright-yellow',
            94: 'bright-blue',
            95: 'bright-magenta',
            96: 'bright-cyan',
            97: 'bright-white',
            40: 'bg-black',
            41: 'bg-red',
            42: 'bg-green',
            43: 'bg-yellow',
            44: 'bg-blue',
            45: 'bg-magenta',
            46: 'bg-cyan',
            47: 'bg-white'
        };
    }

    /**
     * Parse text containing ANSI escape sequences into HTML
     * @param {string} text - The raw text with ANSI sequences
     * @returns {string} HTML formatted text
     */
    parse(text) {
        if (!text) return '';
        
        // Escape HTML special characters
        text = this._escapeHtml(text);
        
        // First try to match the common patterns
        for (const pattern of this.patterns) {
            text = text.replace(pattern.regex, pattern.replace);
        }
        
        // Process remaining ANSI sequences
        let result = '';
        let lastIndex = 0;
        let activeClasses = [];
        
        // Iterate through all matches
        text.replace(this.ansiRegex, (match, codes, index) => {
            // Add the text between the last match and this one
            result += text.substring(lastIndex, index);
            lastIndex = index + match.length;
            
            if (codes === '' || codes === '0') {
                // Reset all formatting
                if (activeClasses.length > 0) {
                    result += '</span>'.repeat(activeClasses.length);
                    activeClasses = [];
                }
                return '';
            }
            
            // Process the ANSI codes
            const codeArray = codes.split(';');
            const classes = [];
            
            for (const code of codeArray) {
                const num = parseInt(code, 10);
                if (this.colorCodes[num]) {
                    classes.push(`ansi-${this.colorCodes[num]}`);
                }
            }
            
            if (classes.length > 0) {
                activeClasses.push(classes);
                result += `<span class="${classes.join(' ')}">`;
            }
            
            return '';
        });
        
        // Add any remaining text
        result += text.substring(lastIndex);
        
        // Close any open spans
        if (activeClasses.length > 0) {
            result += '</span>'.repeat(activeClasses.length);
        }
        
        return result;
    }
    
    /**
     * Escape HTML special characters
     * @private
     * @param {string} text - Raw text to escape
     * @returns {string} Escaped text
     */
    _escapeHtml(text) {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
}

// Create a global instance for use in the application
window.ansiParser = new AnsiParser(); 