# Bash completions for pwr
# Source this file to enable tab completion:
#   source <(pwr completions bash)

_pwr_completions() {
    local cur prev words cword
    _init_completion || return

    case $prev in
        pwr)
            COMPREPLY=($(compgen -W "init archive restore ensure status list log shell tui" -- "$cur"))
            return
            ;;
        archive|restore|ensure)
            # Complete with directories
            COMPREPLY=($(compgen -d -- "$cur"))
            return
            ;;
        status|list)
            COMPREPLY=($(compgen -W "--recursive -r" -- "$cur"))
            return
            ;;
        log)
            COMPREPLY=($(compgen -W "--errors -e --project" -- "$cur"))
            return
            ;;
        shell)
            COMPREPLY=($(compgen -W "bash zsh fish --init" -- "$cur"))
            return
            ;;
        init)
            COMPREPLY=($(compgen -W "--server-host --server-port --psk --local-root" -- "$cur"))
            return
            ;;
        *)
            ;;
    esac
}

complete -F _pwr_completions pwr
