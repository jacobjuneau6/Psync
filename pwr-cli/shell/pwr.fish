# pwr shell integration for Fish
# Add to ~/.config/fish/config.fish: pwr shell fish | source

function __pwr_original_cd
    builtin cd $argv
end

function cd --wraps=__pwr_original_cd
    set target $argv[1]
    test -z "$target"; and set target $HOME

    if test -d "$target"
        if test -f "$target/.project.toml"
            if grep -q 'state = "archived"' "$target/.project.toml" 2>/dev/null
                echo "Project archived on server. Restoring..."
                pwr ensure "$target"; and __pwr_original_cd "$target"; or return 1
            else
                __pwr_original_cd $argv
            end
        else
            __pwr_original_cd $argv
        end
    else
        __pwr_original_cd $argv
    end
end
