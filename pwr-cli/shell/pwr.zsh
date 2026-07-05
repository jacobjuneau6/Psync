# pwr shell integration for Zsh
# Add to ~/.zshrc: eval "$(pwr shell zsh)"

__pwr_original_cd() {
    builtin cd "$@"
}

cd() {
    local target="${1:-$HOME}"
    if [ -d "$target" ]; then
        if [ -f "$target/.project.toml" ]; then
            if grep -q 'state = "archived"' "$target/.project.toml" 2>/dev/null; then
                echo "Project archived on server. Restoring..."
                pwr ensure "$target" && __pwr_original_cd "$target" || return 1
            else
                __pwr_original_cd "$target"
            fi
        else
            __pwr_original_cd "$target"
        fi
    else
        __pwr_original_cd "$target"
    fi
}
