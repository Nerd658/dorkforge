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

// GenerateBash generates a Bash completion script for dorkforge and dfg.
func GenerateBash() string {
	return `#!/usr/bin/env bash
# Bash completion script for dorkforge and dfg

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

    local commands="scan fetch probe subdomains list categories completion version help"
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
            scan|fetch|probe|subdomains|list|categories|completion|version|help)
                cmd="${words[i]}"
                break
                ;;
        esac
    done

    # If no subcommand given yet, complete commands or global flags
    if [[ -z "$cmd" ]]; then
        if [[ "$cur" == -* ]]; then
            COMPREPLY=( $(compgen -W "-h --help -v --version" -- "$cur") )
        else
            COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        fi
        return 0
    fi

    # Subcommand specific completion
    case "$cmd" in
        scan)
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
                    _filedir 2>/dev/null || true
                    return 0
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-d --domain -l --list -c --category -s --min-severity -e --engine -q --search -o --output -f --format --custom --live --probe --open --batch-size --delay --no-color -h --help" -- "$cur") )
            fi
            ;;
        fetch)
            case "$prev" in
                -f|--format)
                    COMPREPLY=( $(compgen -W "$formats" -- "$cur") )
                    return 0
                    ;;
                -o|--output)
                    _filedir 2>/dev/null || true
                    return 0
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-d --domain --subs --sensitive-only -o --output -f --format --limit --timeout --no-color -h --help" -- "$cur") )
            fi
            ;;
        probe)
            case "$prev" in
                -f|--format)
                    COMPREPLY=( $(compgen -W "$formats" -- "$cur") )
                    return 0
                    ;;
                -l|--list|-o|--output)
                    _filedir 2>/dev/null || true
                    return 0
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-d --domain -l --list -t --concurrency --timeout -o --output -f --format --no-color -h --help" -- "$cur") )
            fi
            ;;
        subdomains)
            case "$prev" in
                -f|--format)
                    COMPREPLY=( $(compgen -W "$formats" -- "$cur") )
                    return 0
                    ;;
                -o|--output)
                    _filedir 2>/dev/null || true
                    return 0
                    ;;
            esac
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
            COMPREPLY=( $(compgen -W "scan fetch probe subdomains list categories completion version" -- "$cur") )
            ;;
    esac
}

complete -F _dorkforge dorkforge dfg
`
}

// GenerateZsh generates a Zsh completion script for dorkforge and dfg.
func GenerateZsh() string {
	return `#compdef dorkforge dfg
# Zsh completion script for dorkforge and dfg

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
        'markdown:Deliverable Markdown report with remediation'
        'json:Machine-readable structured JSON report'
        'html:Interactive standalone HTML web dashboard'
        'urls:Newline-delimited raw search URLs'
    )

    local -a shells=(
        'bash:GNU Bourne-Again Shell'
        'zsh:Z Shell'
        'fish:Friendly Interactive Shell'
    )

    _arguments -C \
        '(-h --help)'{-h,--help}'[Show help information]' \
        '(-v --version)'{-v,--version}'[Show version and build info]' \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            local -a subcommands=(
                'scan:Execute a passive dorking reconnaissance audit'
                'fetch:Extract historical URLs from Wayback Machine and AlienVault OTX'
                'probe:Actively probe HTTP status codes on sensitive endpoints'
                'subdomains:Generate negative exclusion dorks for subdomain discovery'
                'list:Display the complete catalog of search signatures'
                'categories:List all 12 supported dorking categories'
                'completion:Generate shell autocompletion script'
                'version:Show version and build information'
                'help:Show help information'
            )
            _describe -t subcommands 'dorkforge command' subcommands
            ;;
        args)
            case $line[1] in
                scan)
                    _arguments \
                        '(-d --domain)'{-d,--domain}'[Target domain]:domain: ' \
                        '(-l --list)'{-l,--list}'[Path to target domains file]:file:_files' \
                        '(-c --category)'{-c,--category}'[Category filter]:category:_values -s , "categories" $categories' \
                        '(-s --min-severity)'{-s,--min-severity}'[Minimum severity filter]:severity:_values "severities" $severities' \
                        '(-e --engine)'{-e,--engine}'[Search engine filter]:engine:_values -s , "engines" $engines' \
                        '(-q --search)'{-q,--search}'[Search dorks by keyword]:keyword: ' \
                        '(-o --output)'{-o,--output}'[Output file destination]:file:_files' \
                        '(-f --format)'{-f,--format}'[Export format]:format:_values "formats" $formats' \
                        '--custom[Custom dorks JSON file]:file:_files' \
                        '--live[Scrape live DuckDuckGo results]' \
                        '--probe[Actively probe target endpoints]' \
                        '--open[Open queries in default web browser]' \
                        '--batch-size[Number of tabs per browser batch]:count: ' \
                        '--delay[Delay in ms between browser batches]:ms: ' \
                        '--no-color[Disable colorized terminal output]' \
                        '(-h --help)'{-h,--help}'[Show help]'
                    ;;
                fetch)
                    _arguments \
                        '(-d --domain)'{-d,--domain}'[Target domain]:domain: ' \
                        '--subs[Include subdomains in lookup]' \
                        '--sensitive-only[Filter to sensitive endpoints]' \
                        '(-o --output)'{-o,--output}'[Output file destination]:file:_files' \
                        '(-f --format)'{-f,--format}'[Export format]:format:_values "formats" $formats' \
                        '--limit[Maximum URLs to extract]:int: ' \
                        '--timeout[Network timeout in seconds]:int: ' \
                        '--no-color[Disable color output]' \
                        '(-h --help)'{-h,--help}'[Show help]'
                    ;;
                probe)
                    _arguments \
                        '(-d --domain)'{-d,--domain}'[Target domain]:domain: ' \
                        '(-l --list)'{-l,--list}'[Path to target domains file]:file:_files' \
                        '(-t --concurrency)'{-t,--concurrency}'[Worker pool count]:int: ' \
                        '--timeout[HTTP timeout in seconds]:int: ' \
                        '(-o --output)'{-o,--output}'[Output file destination]:file:_files' \
                        '(-f --format)'{-f,--format}'[Export format]:format:_values "formats" $formats' \
                        '--no-color[Disable color output]' \
                        '(-h --help)'{-h,--help}'[Show help]'
                    ;;
                subdomains)
                    _arguments \
                        '(-d --domain)'{-d,--domain}'[Target domain]:domain: ' \
                        '--exclude[Comma-separated subdomains to exclude]:subdomains: ' \
                        '-o[Output file destination]:file:_files' \
                        '-f[Export format]:format:_values "formats" $formats' \
                        '--open[Open subdomain dorks in default browser]' \
                        '--no-color[Disable color output]' \
                        '(-h --help)'{-h,--help}'[Show help]'
                    ;;
                list)
                    _arguments \
                        '-c[Filter list by category]:category:_values -s , "categories" $categories' \
                        '--custom[Custom dorks JSON file]:file:_files' \
                        '--no-color[Disable color output]' \
                        '(-h --help)'{-h,--help}'[Show help]'
                    ;;
                completion)
                    _arguments \
                        '1:shell:_values "shells" $shells' \
                        '(-h --help)'{-h,--help}'[Show help]'
                    ;;
            esac
            ;;
    esac
}

_dorkforge "$@"
`
}

// GenerateFish generates a Fish completion script for dorkforge and dfg.
func GenerateFish() string {
	return `# Fish completion script for dorkforge and dfg

complete -c dorkforge -f
complete -c dfg -f

set -l commands scan fetch probe subdomains list categories completion version help
for cmd_name in dorkforge dfg
    complete -c $cmd_name -n "not __fish_seen_subcommand_from $commands" -a scan -d "Execute a dorking reconnaissance audit"
    complete -c $cmd_name -n "not __fish_seen_subcommand_from $commands" -a fetch -d "Extract historical URLs from archive indices"
    complete -c $cmd_name -n "not __fish_seen_subcommand_from $commands" -a probe -d "Actively probe HTTP status codes"
    complete -c $cmd_name -n "not __fish_seen_subcommand_from $commands" -a subdomains -d "Generate negative exclusion dorks for subdomain discovery"
    complete -c $cmd_name -n "not __fish_seen_subcommand_from $commands" -a list -d "Display the complete catalog of search signatures"
    complete -c $cmd_name -n "not __fish_seen_subcommand_from $commands" -a categories -d "List all 12 supported dorking categories"
    complete -c $cmd_name -n "not __fish_seen_subcommand_from $commands" -a completion -d "Generate shell autocompletion script"
    complete -c $cmd_name -n "not __fish_seen_subcommand_from $commands" -a version -d "Show version and build information"
    complete -c $cmd_name -n "not __fish_seen_subcommand_from $commands" -a help -d "Show help information"

    complete -c $cmd_name -s h -l help -d "Show help information"
    complete -c $cmd_name -s v -l version -d "Show version"

    set -l categories configs secrets admin backups cloud source-code errors docs api-endpoints subdomains network-iot employees-osint all
    set -l severities low medium high critical
    set -l engines google github duckduckgo bing shodan all
    set -l formats markdown json html urls
    set -l shells bash zsh fish

    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -s d -l domain -d "Target domain (e.g. example.com)" -r
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -s l -l list -d "Path to target domains file" -r -F
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -s c -l category -d "Categories filter" -r -a "$categories"
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -s s -l min-severity -d "Minimum severity filter" -r -a "$severities"
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -s e -l engine -d "Engines to use" -r -a "$engines"
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -s q -l search -d "Keyword search in dorks" -r
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -s o -l output -d "Output file path" -r -F
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -s f -l format -d "Export format" -r -a "$formats"
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -l custom -d "Path to custom JSON dorks file" -r -F
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -l live -d "Scrape live DuckDuckGo results"
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -l probe -d "Actively probe target endpoints"
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -l open -d "Open generated queries in default web browser"
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -l batch-size -d "Number of search tabs per batch" -r
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -l delay -d "Delay in ms between browser batches" -r
    complete -c $cmd_name -n "__fish_seen_subcommand_from scan" -l no-color -d "Disable colorized terminal output"

    complete -c $cmd_name -n "__fish_seen_subcommand_from fetch" -s d -l domain -d "Target domain" -r
    complete -c $cmd_name -n "__fish_seen_subcommand_from fetch" -l subs -d "Include subdomains"
    complete -c $cmd_name -n "__fish_seen_subcommand_from fetch" -l sensitive-only -d "Filter sensitive endpoints"
    complete -c $cmd_name -n "__fish_seen_subcommand_from fetch" -s o -l output -d "Output file path" -r -F
    complete -c $cmd_name -n "__fish_seen_subcommand_from fetch" -s f -l format -d "Export format" -r -a "$formats"
    complete -c $cmd_name -n "__fish_seen_subcommand_from fetch" -l limit -d "Maximum URLs" -r
    complete -c $cmd_name -n "__fish_seen_subcommand_from fetch" -l timeout -d "Timeout in seconds" -r
    complete -c $cmd_name -n "__fish_seen_subcommand_from fetch" -l no-color -d "Disable color output"

    complete -c $cmd_name -n "__fish_seen_subcommand_from probe" -s d -l domain -d "Target domain" -r
    complete -c $cmd_name -n "__fish_seen_subcommand_from probe" -s l -l list -d "Target list file" -r -F
    complete -c $cmd_name -n "__fish_seen_subcommand_from probe" -s t -l concurrency -d "Concurrency count" -r
    complete -c $cmd_name -n "__fish_seen_subcommand_from probe" -l timeout -d "Timeout in seconds" -r
    complete -c $cmd_name -n "__fish_seen_subcommand_from probe" -s o -l output -d "Output file path" -r -F
    complete -c $cmd_name -n "__fish_seen_subcommand_from probe" -s f -l format -d "Export format" -r -a "$formats"
    complete -c $cmd_name -n "__fish_seen_subcommand_from probe" -l no-color -d "Disable color output"

    complete -c $cmd_name -n "__fish_seen_subcommand_from subdomains" -s d -l domain -d "Target domain (e.g. example.com)" -r
    complete -c $cmd_name -n "__fish_seen_subcommand_from subdomains" -l exclude -d "Comma-separated subdomains to exclude" -r
    complete -c $cmd_name -n "__fish_seen_subcommand_from subdomains" -s o -d "Output file path" -r -F
    complete -c $cmd_name -n "__fish_seen_subcommand_from subdomains" -s f -d "Export format" -r -a "$formats"
    complete -c $cmd_name -n "__fish_seen_subcommand_from subdomains" -l open -d "Open subdomain dorks in default browser"
    complete -c $cmd_name -n "__fish_seen_subcommand_from subdomains" -l no-color -d "Disable color output"

    complete -c $cmd_name -n "__fish_seen_subcommand_from list" -s c -d "Filter list by category" -r -a "$categories"
    complete -c $cmd_name -n "__fish_seen_subcommand_from list" -l custom -d "Include custom dorks JSON file" -r -F
    complete -c $cmd_name -n "__fish_seen_subcommand_from list" -l no-color -d "Disable color output"

    complete -c $cmd_name -n "__fish_seen_subcommand_from completion" -a "$shells" -d "Target shell"
    complete -c $cmd_name -n "__fish_seen_subcommand_from help" -a "scan fetch probe subdomains list categories completion version"
end
`
}
