package completion

import (
	"fmt"
	"io"
	"strings"
)

// Shell represents a supported Unix shell for autocompletion generation.
type Shell string

const (
	ShellBash Shell = "bash"
	ShellZsh  Shell = "zsh"
	ShellFish Shell = "fish"
)

// SupportedShellList lists all shells supported by the completion generator.
var SupportedShellList = []Shell{
	ShellBash,
	ShellZsh,
	ShellFish,
}

// SupportedShells returns a slice of string names for all supported shells.
func SupportedShells() []string {
	res := make([]string, len(SupportedShellList))
	for i, s := range SupportedShellList {
		res[i] = string(s)
	}
	return res
}

// IsSupportedShell checks if a shell name is supported.
func IsSupportedShell(shell string) bool {
	norm := strings.ToLower(strings.TrimSpace(shell))
	for _, s := range SupportedShellList {
		if string(s) == norm {
			return true
		}
	}
	return false
}

// Generate returns the autocompletion script for the specified shell name.
func Generate(shell string) (string, error) {
	norm := strings.ToLower(strings.TrimSpace(shell))
	switch Shell(norm) {
	case ShellBash:
		return GenerateBash(), nil
	case ShellZsh:
		return GenerateZsh(), nil
	case ShellFish:
		return GenerateFish(), nil
	default:
		return "", fmt.Errorf("unsupported shell %q (supported: bash, zsh, fish)", shell)
	}
}

// WriteCompletion generates and writes the completion script to an io.Writer.
func WriteCompletion(w io.Writer, shell string) error {
	script, err := Generate(shell)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, script)
	return err
}

// GenerateBash generates a Bash completion script for dorkforge.
func GenerateBash() string {
	return `#!/usr/bin/env bash
# Bash completion script for dorkforge

_dorkforge() {
    local cur prev words cword
    if type _init_completion >/dev/null 2>&1; then
        _init_completion || return
    else
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    fi

    local commands="scan subdomains list categories completion version help"
    local categories="configs secrets admin backups cloud source-code errors docs api-endpoints subdomains network-iot employees-osint all"
    local severities="low medium high critical"
    local engines="google github duckduckgo bing shodan all"
    local formats="markdown json html urls"
    local shells="bash zsh fish"

    # Identify primary command
    local cmd=""
    local i
    for ((i = 1; i < cword; i++)); do
        case "${words[i]}" in
            scan|subdomains|list|categories|completion|version|help)
                cmd="${words[i]}"
                break
                ;;
        esac
    done

    # Autocomplete root commands and top-level flags
    if [[ -z "$cmd" ]]; then
        if [[ "$cur" == -* ]]; then
            COMPREPLY=( $(compgen -W "-h --help -v --version" -- "$cur") )
        else
            COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        fi
        return 0
    fi

    # Value completion for preceding flags
    case "$prev" in
        -c|--category)
            COMPREPLY=( $(compgen -W "$categories" -- "$cur") )
            return 0
            ;;
        -s|--min-severity)
            COMPREPLY=( $(compgen -W "$severities" -- "$cur") )
            return 0
            ;;
        -e|--engine)
            COMPREPLY=( $(compgen -W "$engines" -- "$cur") )
            return 0
            ;;
        -f|--format)
            COMPREPLY=( $(compgen -W "$formats" -- "$cur") )
            return 0
            ;;
        -l|--list|-o|--output|--custom)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
    esac

    # Command-specific flag and argument completion
    case "$cmd" in
        scan)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-d --domain -l --list -c --category -s --min-severity -e --engine -q --search -o --output -f --format --custom --open --batch-size --delay --no-color -h --help" -- "$cur") )
            fi
            ;;
        subdomains)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-d --domain --exclude -o -f --open --no-color -h --help" -- "$cur") )
            fi
            ;;
        list)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-c --custom --no-color -h --help" -- "$cur") )
            fi
            ;;
        categories)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-h --help" -- "$cur") )
            fi
            ;;
        completion)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-h --help" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$shells" -- "$cur") )
            fi
            ;;
        help)
            COMPREPLY=( $(compgen -W "scan subdomains list categories completion version" -- "$cur") )
            ;;
    esac
}

complete -F _dorkforge dorkforge
`
}

// GenerateZsh generates a Zsh completion script for dorkforge.
func GenerateZsh() string {
	return `#compdef dorkforge
# Zsh completion script for dorkforge

_dorkforge() {
    local context state state_policy line
    typeset -A opt_args

    local -a categories=(
        'configs:Exposed .env, server configs, docker-compose'
        'secrets:AWS keys, SSH keys, GitHub tokens, database passwords'
        'admin:Administrative login portals and management panels'
        'backups:Database dumps and compressed source archives'
        'cloud:Public S3 buckets, Azure Blobs, Google Cloud Storage'
        'source-code:Exposed .git folders, code leaks'
        'errors:PHP info, framework stack traces, error logs'
        'docs:Confidential documents, spreadsheets, payrolls'
        'api-endpoints:Swagger/OpenAPI specs, GraphQL consoles'
        'subdomains:Search engine exclusion and SSL recon'
        'network-iot:Router/firewall interfaces, web terminals'
        'employees-osint:LinkedIn profiles, employee directories'
        'all:All available categories'
    )

    local -a severities=(
        'critical:Critical severity risks'
        'high:High severity risks'
        'medium:Medium severity risks'
        'low:Low severity risks'
    )

    local -a engines=(
        'google:Google Search engine'
        'github:GitHub Code Search'
        'duckduckgo:DuckDuckGo Search'
        'bing:Microsoft Bing Search'
        'shodan:Shodan Computer Search Engine'
        'all:All supported search engines'
    )

    local -a formats=(
        'markdown:Formatted Markdown audit report'
        'json:Raw JSON data structure'
        'html:Interactive HTML report dashboard'
        'urls:Plain list of search URLs'
    )

    local -a shells=(
        'bash:Generate Bash autocompletion script'
        'zsh:Generate Zsh autocompletion script'
        'fish:Generate Fish autocompletion script'
    )

    _arguments -C \
        '(-v --version)'{-v,--version}'[Show version and build information]' \
        '(-h --help)'{-h,--help}'[Show help information]' \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            local -a commands=(
                'scan:Execute a dorking reconnaissance audit against a target'
                'subdomains:Generate negative exclusion dorks for subdomain discovery'
                'list:Display the complete catalog of built-in search signatures'
                'categories:List all 12 supported dorking categories and descriptions'
                'completion:Generate shell autocompletion script (bash, zsh, fish)'
                'version:Show version and build information'
                'help:Display help information'
            )
            _describe -t commands 'dorkforge command' commands
            ;;
        args)
            case $words[1] in
                scan)
                    _arguments \
                        '(-d --domain)'{-d,--domain}'[Target domain (e.g. example.com)]:domain:' \
                        '(-l --list)'{-l,--list}'[Path to file containing domain targets]:target file:_files' \
                        '(-c --category)'{-c,--category}'[Comma-separated categories or all]:category:_values -s , "category" $categories' \
                        '(-s --min-severity)'{-s,--min-severity}'[Minimum severity filter]:severity:(critical high medium low)' \
                        '(-e --engine)'{-e,--engine}'[Engines to use]:engine:_values -s , "engine" $engines' \
                        '(-q --search)'{-q,--search}'[Keyword search within dork descriptions]:query:' \
                        '(-o --output)'{-o,--output}'[Output file path]:output file:_files' \
                        '(-f --format)'{-f,--format}'[Export format]:format:(markdown json html urls)' \
                        '--custom[Path to custom JSON dorks file]:custom dorks:_files' \
                        '--open[Open generated queries in default web browser]' \
                        '--batch-size[Number of search tabs to open per batch]:batch size:' \
                        '--delay[Delay in milliseconds between browser batches]:delay ms:' \
                        '--no-color[Disable colorized terminal output]' \
                        '(-h --help)'{-h,--help}'[Show help for scan]'
                    ;;
                subdomains)
                    _arguments \
                        '(-d --domain)'{-d,--domain}'[Target domain (e.g. example.com)]:domain:' \
                        '--exclude[Comma-separated subdomains to exclude]:subdomains:' \
                        '-o[Output file path]:output file:_files' \
                        '-f[Export format]:format:(markdown json html urls)' \
                        '--open[Open subdomain dorks in default browser]' \
                        '--no-color[Disable color output]' \
                        '(-h --help)'{-h,--help}'[Show help for subdomains]'
                    ;;
                list)
                    _arguments \
                        '-c[Filter list by category]:category:_values "category" $categories' \
                        '--custom[Include custom dorks JSON file]:custom dorks:_files' \
                        '--no-color[Disable color output]' \
                        '(-h --help)'{-h,--help}'[Show help for list]'
                    ;;
                categories)
                    _arguments \
                        '(-h --help)'{-h,--help}'[Show help for categories]'
                    ;;
                completion)
                    _arguments \
                        '1:shell:(bash zsh fish)' \
                        '(-h --help)'{-h,--help}'[Show help for completion]'
                    ;;
                help)
                    _values 'commands' scan subdomains list categories completion version
                    ;;
            esac
            ;;
    esac
}

_dorkforge "$@"
`
}

// GenerateFish generates a Fish completion script for dorkforge.
func GenerateFish() string {
	return `# Fish completion script for dorkforge

# Disable file completion by default unless explicitly enabled
complete -c dorkforge -f

# Main commands
set -l commands scan subdomains list categories completion version help
complete -c dorkforge -n "not __fish_seen_subcommand_from $commands" -a scan -d "Execute a dorking reconnaissance audit"
complete -c dorkforge -n "not __fish_seen_subcommand_from $commands" -a subdomains -d "Generate negative exclusion dorks for subdomain discovery"
complete -c dorkforge -n "not __fish_seen_subcommand_from $commands" -a list -d "Display the complete catalog of search signatures"
complete -c dorkforge -n "not __fish_seen_subcommand_from $commands" -a categories -d "List all 12 supported dorking categories"
complete -c dorkforge -n "not __fish_seen_subcommand_from $commands" -a completion -d "Generate shell autocompletion script"
complete -c dorkforge -n "not __fish_seen_subcommand_from $commands" -a version -d "Show version and build information"
complete -c dorkforge -n "not __fish_seen_subcommand_from $commands" -a help -d "Show help information"

# Global options
complete -c dorkforge -s h -l help -d "Show help information"
complete -c dorkforge -s v -l version -d "Show version"

# Value helpers
set -l categories configs secrets admin backups cloud source-code errors docs api-endpoints subdomains network-iot employees-osint all
set -l severities low medium high critical
set -l engines google github duckduckgo bing shodan all
set -l formats markdown json html urls
set -l shells bash zsh fish

# Scan command options
complete -c dorkforge -n "__fish_seen_subcommand_from scan" -s d -l domain -d "Target domain (e.g. example.com)" -r
complete -c dorkforge -n "__fish_seen_subcommand_from scan" -s l -l list -d "Path to target domains file" -r -F
complete -c dorkforge -n "__fish_seen_subcommand_from scan" -s c -l category -d "Categories filter" -r -a "$categories"
complete -c dorkforge -n "__fish_seen_subcommand_from scan" -s s -l min-severity -d "Minimum severity filter" -r -a "$severities"
complete -c dorkforge -n "__fish_seen_subcommand_from scan" -s e -l engine -d "Engines to use" -r -a "$engines"
complete -c dorkforge -n "__fish_seen_subcommand_from scan" -s q -l search -d "Keyword search in dorks" -r
complete -c dorkforge -n "__fish_seen_subcommand_from scan" -s o -l output -d "Output file path" -r -F
complete -c dorkforge -n "__fish_seen_subcommand_from scan" -s f -l format -d "Export format" -r -a "$formats"
complete -c dorkforge -n "__fish_seen_subcommand_from scan" -l custom -d "Path to custom JSON dorks file" -r -F
complete -c dorkforge -n "__fish_seen_subcommand_from scan" -l open -d "Open generated queries in default web browser"
complete -c dorkforge -n "__fish_seen_subcommand_from scan" -l batch-size -d "Number of search tabs per batch" -r
complete -c dorkforge -n "__fish_seen_subcommand_from scan" -l delay -d "Delay in ms between browser batches" -r
complete -c dorkforge -n "__fish_seen_subcommand_from scan" -l no-color -d "Disable colorized terminal output"

# Subdomains command options
complete -c dorkforge -n "__fish_seen_subcommand_from subdomains" -s d -l domain -d "Target domain (e.g. example.com)" -r
complete -c dorkforge -n "__fish_seen_subcommand_from subdomains" -l exclude -d "Comma-separated subdomains to exclude" -r
complete -c dorkforge -n "__fish_seen_subcommand_from subdomains" -s o -d "Output file path" -r -F
complete -c dorkforge -n "__fish_seen_subcommand_from subdomains" -s f -d "Export format" -r -a "$formats"
complete -c dorkforge -n "__fish_seen_subcommand_from subdomains" -l open -d "Open subdomain dorks in default browser"
complete -c dorkforge -n "__fish_seen_subcommand_from subdomains" -l no-color -d "Disable color output"

# List command options
complete -c dorkforge -n "__fish_seen_subcommand_from list" -s c -d "Filter list by category" -r -a "$categories"
complete -c dorkforge -n "__fish_seen_subcommand_from list" -l custom -d "Include custom dorks JSON file" -r -F
complete -c dorkforge -n "__fish_seen_subcommand_from list" -l no-color -d "Disable color output"

# Completion command options
complete -c dorkforge -n "__fish_seen_subcommand_from completion" -a "$shells" -d "Target shell"

# Help command options
complete -c dorkforge -n "__fish_seen_subcommand_from help" -a "scan subdomains list categories completion version"
`
}
